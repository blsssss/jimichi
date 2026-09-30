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
	name  string
	addr  string
	admin string
	info  string
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
		return rosterEntry{}, fmt.Errorf("%q: want name=host:port,admin=host:port,info=host:port", s)
	}
	e := rosterEntry{name: name, addr: addr}
	for _, kv := range parts[1:] {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case ok && k == "admin" && e.admin == "":
			e.admin = v
		case ok && k == "info" && e.info == "":
			e.info = v
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
	return e, nil
}

// two entries for one relay would get it two certificates, and two relays
// behind one endpoint would get one relay's certificate installed twice
func checkRoster(nodes roster) error {
	if len(nodes) == 0 {
		return errors.New("no -node given")
	}
	seen := make(map[string]bool)
	for _, n := range nodes {
		for _, v := range []string{"name " + n.name, "address " + n.addr, "endpoint " + n.admin, "endpoint " + n.info} {
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
	fs.Var(&nodes, "node", "one relay as name=host:port,admin=host:port,info=host:port: name and address go into its certificate, admin reaches its loopback listener, info its descriptor; repeat per relay")
	timeout := fs.Duration("timeout", 30*time.Second, "deadline for the whole enrollment")
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
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %v: must be positive", *timeout)
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
	e := &enrollment{p: p, nodes: nodes, certTTL: *certTTL, web: newWebClient(), now: time.Now, log: stderr}
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
		fmt.Fprintf(stderr, "WARNING: the CA key is held without %s for the seconds of this run\n", strings.Join(missing, " and "))
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
	p       jcrypto.CryptoProvider
	nodes   roster
	certTTL time.Duration
	web     *http.Client
	now     func() time.Time
	log     io.Writer
}

// nothing is issued until every request has passed, and the anchor is returned
// only once every relay serves a descriptor that verifies against it the way
// a client checks it
func (e *enrollment) run(ctx context.Context) (pki.Anchor, error) {
	ca, err := pki.NewCA(e.p)
	if err != nil {
		return pki.Anchor{}, err
	}
	defer ca.Close()

	reqs := make([]*pki.Request, len(e.nodes))
	for i, n := range e.nodes {
		var nonce [pki.NonceSize]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return pki.Anchor{}, err
		}
		raw, err := e.call(ctx, http.MethodPost, "http://"+n.admin+"/csr", nonce[:], http.StatusOK)
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
		reqs[i] = r
	}
	for i := range reqs {
		for j := range i {
			if bytes.Equal(reqs[i].Identity, reqs[j].Identity) {
				return pki.Anchor{}, fmt.Errorf("nodes %s and %s: %w", e.nodes[j].name, e.nodes[i].name, pki.ErrDuplicate)
			}
		}
	}

	now := e.now()
	certs := make([]*pki.Cert, len(reqs))
	for i, r := range reqs {
		if certs[i], err = ca.Issue(r, now, now.Add(e.certTTL)); err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: issuing: %w", e.nodes[i].name, err)
		}
	}
	anchor := ca.Anchor()
	ca.Close()

	for i, n := range e.nodes {
		if _, err := e.call(ctx, http.MethodPut, "http://"+n.admin+"/cert", certs[i].Marshal(), http.StatusNoContent); err != nil {
			return pki.Anchor{}, fmt.Errorf("node %s: installing the certificate: %w", n.name, err)
		}
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
			return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out)))
		}
		return out, nil
	}
}
