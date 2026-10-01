package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

const (
	maxAnswer  = 16 << 10
	retryPause = 200 * time.Millisecond
)

type rosterEntry struct {
	name     string
	addr     string
	admin    string
	info     string
	identity string
}

var errIdentityPin = errors.New("request signed by another key than the one the relay logged at start")

// replaced in tests to see that no refusal ever gets as far as a CA key
var newCA = pki.NewCA

// an answer the relay gave, as opposed to a request that may or may not have
// reached it
type statusError struct {
	code int
	text string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.code, http.StatusText(e.code), e.text)
}

// the relay's answer to a request or certificate once it has taken one; only a
// restart, with its fresh identity, makes it enrollable again
func alreadyInstalled(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == http.StatusConflict && strings.Contains(se.text, "already installed")
}

// a transport error or a 5xx after the certificate went out leaves open
// whether the relay installed it
func ambiguous(err error) bool {
	var se *statusError
	return !errors.As(err, &se) || se.code >= http.StatusInternalServerError
}

type roster []rosterEntry

func (r *roster) String() string { return "" }

func (r *roster) Set(s string) error {
	e, err := parseNode(s)
	if err != nil {
		return err
	}
	*r = append(*r, e)
	return nil
}

func parseNode(s string) (rosterEntry, error) {
	parts := strings.Split(s, ",")
	name, addr, ok := strings.Cut(parts[0], "=")
	if !ok {
		return rosterEntry{}, fmt.Errorf("%q: want name=host:port,admin=host:port,info=host:port,identity=hash", s)
	}
	e := rosterEntry{name: name, addr: addr}
	for _, kv := range parts[1:] {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case ok && k == "admin" && e.admin == "":
			e.admin = v
		case ok && k == "info" && e.info == "":
			e.info = v
		case ok && k == "identity" && e.identity == "":
			e.identity = v
		default:
			return rosterEntry{}, fmt.Errorf("%q: unknown or repeated part %q", s, kv)
		}
	}
	if !pki.ValidName(e.name) {
		return rosterEntry{}, fmt.Errorf("%q: name %q is not 1 to 32 characters of a-z, 0-9 and -", s, e.name)
	}
	if !pki.ValidAddr(e.addr) {
		return rosterEntry{}, fmt.Errorf("%q: address %q is not a host:port a certificate can carry", s, e.addr)
	}
	for _, ep := range []struct{ key, v string }{{"admin", e.admin}, {"info", e.info}} {
		if _, _, err := net.SplitHostPort(ep.v); err != nil || ep.v == "" {
			return rosterEntry{}, fmt.Errorf("%q: %s wants host:port", s, ep.key)
		}
	}
	if !validKeyHash(e.identity) {
		return rosterEntry{}, fmt.Errorf("%q: identity wants the %d hex digits of identity_hash from the relay log", s, 2*pki.HashSize)
	}
	return e, nil
}

func validKeyHash(s string) bool {
	if len(s) != 2*pki.HashSize {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// two entries for one relay would get it two certificates, and two relays
// behind one endpoint would get one relay's certificate installed twice
func checkRoster(nodes roster) error {
	if len(nodes) == 0 {
		return errors.New("no -node given")
	}
	seen := make(map[string]bool)
	for _, n := range nodes {
		for _, v := range []string{"name " + n.name, "address " + n.addr, "endpoint " + n.admin, "endpoint " + n.info, "identity " + n.identity} {
			if seen[v] {
				return fmt.Errorf("%s repeated in the roster", v)
			}
			seen[v] = true
		}
	}
	return nil
}

func runEnroll(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite of the relays: gost or c25519")
	certTTL := fs.Duration("cert-ttl", 72*time.Hour, "lifetime of the certificates")
	var nodes roster
	fs.Var(&nodes, "node", "one relay as name=host:port,admin=host:port,info=host:port,identity=hash: name and address go into its certificate, admin reaches its loopback listener, info its descriptor, identity is the identity_hash it logged at start; repeat per relay")
	timeout := fs.Duration("timeout", 30*time.Second, fmt.Sprintf("deadline for the whole enrollment, at most %v: a relay accepts its certificate only that long after its request", pki.InstallWindow))
	namespace := fs.String("namespace", "jimichi", "namespace named in restart hints; deployments are taken to be named after the relays")
	keymem := fs.String("keymem", "all", "key memory measures for the CA key: all, none, or a list of offheap, lock, dontdump, zero")
	harden := fs.Bool("harden", true, "disable core dumps and ptrace access for the process")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := checkRoster(nodes); err != nil {
		return err
	}
	if *certTTL < time.Minute {
		return fmt.Errorf("-cert-ttl %v: want at least 1m", *certTTL)
	}
	if *timeout <= 0 || *timeout > pki.InstallWindow {
		return fmt.Errorf("-timeout %v: want more than 0 and at most %v, the time a relay waits for its certificate", *timeout, pki.InstallWindow)
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	p, err := suite.New(chosen)
	if err != nil {
		return err
	}
	if err := protectKeyMemory(*keymem, *harden, stderr); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	e := &enrollment{p: p, nodes: nodes, certTTL: *certTTL, web: newWebClient(), now: time.Now, log: stderr, namespace: *namespace}
	anchor, err := e.run(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, anchor.String())
	return nil
}

// the CA key is the one secret of this process; asking for locked memory and
// not getting it stops the run before the key exists
func protectKeyMemory(keymem string, harden bool, stderr io.Writer) error {
	policy, err := secmem.ParsePolicy(keymem)
	if err != nil {
		return err
	}
	if err := secmem.SetPolicy(policy); err != nil {
		return err
	}
	const fallback = "; where the host has no such measure pass -keymem zero -harden=false"
	if harden {
		if err := secmem.HardenProcess(); err != nil {
			return fmt.Errorf("harden: %v%s", err, fallback)
		}
	}
	if policy.Lock {
		probe, err := secmem.New(32)
		if err != nil {
			return fmt.Errorf("key memory: %v%s", err, fallback)
		}
		locked := probe.Locked()
		probe.Release()
		if !locked {
			return errors.New("key memory is not locked, refusing to create the CA key" + fallback)
		}
	}
	var missing []string
	if !policy.Lock {
		missing = append(missing, "locked memory")
	}
	if !harden {
		missing = append(missing, "process hardening")
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "WARNING: the CA key is held without %s while it issues the certificates\n", strings.Join(missing, " and "))
	}
	return nil
}

// a relay answers on loopback through a port-forward; a proxy from the
// environment or a redirect would send the request somewhere else
func newWebClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type enrollment struct {
	p         jcrypto.CryptoProvider
	nodes     roster
	certTTL   time.Duration
	web       *http.Client
	now       func() time.Time
	log       io.Writer
	namespace string
}

func (e *enrollment) restartHint(names []string) string {
	deployments := make([]string, len(names))
	for i, n := range names {
		deployments[i] = "deployment/" + n
	}
	return fmt.Sprintf("kubectl -n %s rollout restart %s", e.namespace, strings.Join(deployments, " "))
}

// nothing is issued until every request has passed, and the anchor is returned
// only once every relay serves a descriptor that verifies against it the way
// a client checks it
func (e *enrollment) run(ctx context.Context) (anchor pki.Anchor, err error) {
	reqs := make([]*pki.Request, len(e.nodes))
	for i, n := range e.nodes {
		var nonce [pki.NonceSize]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return pki.Anchor{}, err
		}
		raw, err := e.call(ctx, http.MethodPost, "http://"+n.admin+"/csr", nonce[:], http.StatusOK)
		if alreadyInstalled(err) {
			fmt.Fprintf(e.log, "relay %s already holds a certificate; re-enrollment needs a fresh identity: %s, then run enroll again\n",
				n.name, e.restartHint([]string{n.name}))
		}
		if err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: certificate request: %w", n.name, err)
		}
		r, err := pki.ParseRequest(raw)
		if err == nil {
			err = r.Check(e.p, nonce, n.name, n.addr)
		}
		if err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: %w", n.name, err)
		}
		// the port-forward reaches whatever answers on the pod's loopback; the
		// hash read from the relay's own log ties the request to its key
		if got := pki.KeyHash(e.p, r.Identity); got != n.identity {
			return pki.Anchor{}, fmt.Errorf("node %s: %w (logged %s, request %s)", n.name, errIdentityPin, n.identity, got)
		}
		reqs[i] = r
	}
	for i := range reqs {
		for j := range i {
			if bytes.Equal(reqs[i].Identity, reqs[j].Identity) {
				return pki.Anchor{}, fmt.Errorf("nodes %s and %s: %w", e.nodes[j].name, e.nodes[i].name, pki.ErrDuplicate)
			}
		}
	}

	ca, err := newCA(e.p)
	if err != nil {
		return pki.Anchor{}, err
	}
	defer ca.Close()
	now := e.now()
	certs := make([]*pki.Cert, len(reqs))
	for i, r := range reqs {
		if certs[i], err = ca.Issue(r, now, now.Add(e.certTTL)); err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: issuing: %w", e.nodes[i].name, err)
		}
	}
	anchor = ca.Anchor()
	ca.Close()

	// installing is not atomic across relays: once one has taken a certificate
	// of this CA, a failure leaves it serving under an anchor nobody will get,
	// and it keeps that certificate until it restarts
	var installed, mayHold []string
	defer func() {
		if err == nil || len(installed)+len(mayHold) == 0 {
			return
		}
		held := "relays " + strings.Join(installed, ", ") + " now hold"
		switch {
		case len(installed) == 0:
			held = "relays " + strings.Join(mayHold, ", ") + " may hold"
		case len(mayHold) > 0:
			held += " and " + strings.Join(mayHold, ", ") + " may hold"
		}
		fmt.Fprintf(e.log, "%s certificates of a discarded CA; clients refuse them, restart them with %s, then run enroll again\n",
			held, e.restartHint(append(installed, mayHold...)))
	}()
	for i, n := range e.nodes {
		_, err := e.call(ctx, http.MethodPut, "http://"+n.admin+"/cert", certs[i].Marshal(), http.StatusNoContent)
		switch {
		case err == nil:
			installed = append(installed, n.name)
			continue
		case alreadyInstalled(err):
			fmt.Fprintf(e.log, "relay %s already holds a certificate; re-enrollment needs a fresh identity: %s\n",
				n.name, e.restartHint([]string{n.name}))
		case ambiguous(err):
			mayHold = append(mayHold, n.name)
		}
		return pki.Anchor{}, fmt.Errorf("node %s: installing the certificate: %w", n.name, err)
	}

	addrs := make([]string, len(e.nodes))
	bundles := make([][]byte, len(e.nodes))
	for i, n := range e.nodes {
		addrs[i] = n.addr
		if bundles[i], err = e.call(ctx, http.MethodGet, "http://"+n.info+"/descriptor", nil, http.StatusOK); err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: descriptor: %w", n.name, err)
		}
	}
	verified, err := pki.VerifyChain(e.p, pki.Policy{Anchor: anchor, Skew: pki.Skew}, addrs, bundles, e.now())
	if err != nil {
		return pki.Anchor{}, err
	}
	for i, v := range verified {
		fmt.Fprintf(e.log, "enrolled %s identity=%s serial=%x certificate until %s\n",
			v.Name, pki.Fingerprint(e.p, v.Identity), certs[i].Serial, v.CertUntil.UTC().Format(time.RFC3339))
	}
	return anchor, nil
}

// kubectl port-forward refuses connections until it is up, so a failed
// connection is retried until the deadline; an answer is never retried
func (e *enrollment) call(ctx context.Context, method, url string, body []byte, want int) ([]byte, error) {
	for {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		resp, err := e.web.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, err
			case <-time.After(retryPause):
				continue
			}
		}
		out, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
		resp.Body.Close()
		switch {
		case err != nil:
			return nil, err
		case len(out) > maxAnswer:
			return nil, fmt.Errorf("answer over %d bytes", maxAnswer)
		case resp.StatusCode != want:
			return nil, &statusError{code: resp.StatusCode, text: strings.TrimSpace(string(out))}
		}
		return out, nil
	}
}
