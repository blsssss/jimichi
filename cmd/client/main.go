package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	fetchAttempts = 30
	fetchPause    = time.Second
)

var (
	errNoBundle = errors.New("the entry holds no bundle for it")
	errTooFew   = errors.New("the entry leaves out too many nodes")
)

func main() {
	nodes := flag.String("nodes", "", "comma separated host:port of the nodes the chain is drawn from, at least -hops of them")
	hops := flag.Int("hops", 3, "nodes in the chain; one setup cell carries at most 4 on c25519 and 3 on gost")
	fixed := flag.Bool("fixed-chain", false, "take the first -hops nodes of -nodes in the listed order instead of drawing the chain at random, for measurements that need a known path")
	infoPort := flag.String("info-port", "9100", "port where the entry publishes the descriptors of every listed node")
	message := flag.String("message", "hello from the chain", "payload to send")
	count := flag.Int("count", 1, "how many messages to send, 0 for endless")
	interval := flag.Duration("interval", time.Second, "pause between messages")
	cover := flag.Duration("cover", 0, "cover traffic added on top of payload, 0 disables it")
	mode := flag.String("mode", "immediate", "immediate or fixed: fixed sends one cell per tick and a payload takes a cover slot")
	rate := flag.Duration("rate", 200*time.Millisecond, "cell period in fixed mode")
	jitter := flag.Duration("jitter", 0, "random delay added before each cell")
	suiteName := flag.String("suite", suite.Default.String(), "primitive suite: gost or c25519, must match the nodes")
	harden := flag.Bool("harden", true, "disable core dumps and ptrace access for the process")
	keymem := flag.String("keymem", "all", "key memory measures: all, none, or a list of offheap, lock, dontdump, zero")
	auth := flag.Bool("auth", true, "verify the descriptor of every listed node against -ca before building the circuit; false takes the keys unverified")
	ca := flag.String("ca", "", "trust anchor <suite>:<base64>, the CA public key printed by jimichi enroll")
	skew := flag.Duration("skew", pki.Skew, "tolerated lag of this clock behind the nodes' clocks")
	missing := flag.Int("missing", 1, "listed nodes the entry may leave out of its descriptors, at most the nodes beyond -hops; the chain is drawn among the rest")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	policy, err := secmem.ParsePolicy(*keymem)
	if err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if err := secmem.SetPolicy(policy); err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if *harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Fatalf("harden: %v", err)
		}
	}
	// the circuit keys come later, so a probe buffer tells now whether locking
	// works at all; a client that asked for it must not run without it
	if policy.Lock {
		probe, err := secmem.New(32)
		if err != nil {
			logger.Fatalf("key memory: %v", err)
		}
		locked := probe.Locked()
		probe.Release()
		if !locked {
			logger.Fatal("key memory is not locked, refusing to start")
		}
	}

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		logger.Fatal(err)
	}
	provider, err := suite.New(chosen)
	if err != nil {
		logger.Fatal(err)
	}
	addrs := splitList(*nodes)
	if err := checkNodes(provider, addrs, *hops, *infoPort); err != nil {
		logger.Fatal(err)
	}
	trust, err := trustPolicy(*auth, *ca, chosen, *skew)
	if err != nil {
		logger.Fatal(err)
	}
	if !*auth {
		logger.Print("WARNING: -auth=false, node keys are taken unverified from whoever answers the descriptor request")
	}
	if *missing < 0 {
		logger.Fatalf("-missing %d: must not be negative", *missing)
	}
	if *hops == 1 {
		logger.Print("WARNING: -hops 1, a single node sees both the sender and what it sends on")
	}

	sel := selection{
		addrs: addrs, hops: *hops, fixed: *fixed, missing: *missing, infoPort: *infoPort,
		auth: *auth, trust: trust,
		web: fetch.NewClient(), attempts: fetchAttempts, pause: fetchPause,
		rnd: rand.Reader,
	}
	chain, err := sel.chain(provider, logger, time.Now())
	if err != nil {
		logger.Fatalf("refusing to build the circuit: %v", err)
	}

	cfg := client.Config{
		Provider:  provider,
		Chain:     chain,
		CoverRate: *cover,
		Jitter:    *jitter,
	}
	if *mode == "fixed" {
		cfg.Mode = client.ConstantRate
		cfg.Rate = *rate
	}

	c, err := client.Dial(cfg)
	if err != nil {
		logger.Fatalf("dial: %s", sel.cause(err))
	}
	// Fatal would skip a deferred Close and leave the circuit keys unzeroed
	fail := func(format string, args ...any) {
		_ = c.Close()
		logger.Printf(format, args...)
		os.Exit(1)
	}
	defer c.Close()

	logger.Printf("circuit of %d hops among %d listed nodes, payload limit %d bytes, mode %s", len(chain), len(addrs), c.MaxPayload(), *mode)

	for i := 0; *count == 0 || i < *count; i++ {
		start := time.Now()
		if err := c.Send([]byte(*message)); err != nil {
			fail("send: %s", sel.cause(err))
		}
		select {
		case reply, open := <-c.Replies():
			if !open {
				// a dead circuit would otherwise swallow every message silently;
				// exiting lets the orchestrator restart the client on a fresh one
				fail("circuit closed")
			}
			logger.Printf("round trip %d bytes in %s", len(reply), time.Since(start).Round(time.Microsecond))
		case <-time.After(5 * time.Second):
			logger.Print("no reply within 5s")
		}
		if *count == 0 || i+1 < *count {
			time.Sleep(*interval)
		}
	}
}

func splitList(s string) []string {
	out := make([]string, 0, 3)
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// settled before any network request and before anything is drawn: a list the
// client cannot build a chain from must fail the same way at every start, not
// only when the draw reaches the bad entry
func checkNodes(p jcrypto.CryptoProvider, addrs []string, hops int, infoPort string) error {
	if len(addrs) == 0 {
		return errors.New("no nodes given")
	}
	limit, err := wire.MaxLayers(p)
	if err != nil {
		return err
	}
	switch {
	case hops < 1:
		return fmt.Errorf("-hops %d: want at least 1", hops)
	case hops > limit:
		return fmt.Errorf("-hops %d: a setup cell of suite %s carries at most %d hops", hops, p.Suite(), limit)
	case len(addrs) < hops:
		return fmt.Errorf("-nodes lists %d nodes, -hops %d needs at least as many", len(addrs), hops)
	case !pki.ValidPort(infoPort):
		return fmt.Errorf("-info-port %q: want a port number", infoPort)
	}
	seen := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		if !pki.ValidAddr(addr) {
			return fmt.Errorf("-nodes: %q: want host:port in printable ASCII, lower case, at most %d bytes", addr, wire.AddrSize)
		}
		if seen[addr] {
			return fmt.Errorf("-nodes: %s listed twice", addr)
		}
		seen[addr] = true
	}
	return nil
}

// settled before any network request, so a client that cannot check what it
// fetches never asks for it
func trustPolicy(auth bool, ca string, s jcrypto.Suite, skew time.Duration) (pki.Policy, error) {
	if !auth {
		return pki.Policy{}, nil
	}
	if ca == "" {
		return pki.Policy{}, errors.New("-auth needs -ca, the anchor printed by jimichi enroll")
	}
	anchor, err := pki.ParseAnchor(ca)
	if err != nil {
		return pki.Policy{}, fmt.Errorf("-ca: %w", err)
	}
	if anchor.Suite != s {
		return pki.Policy{}, fmt.Errorf("-ca is an anchor for suite %s, the client runs %s: %w", anchor.Suite, s, pki.ErrSuite)
	}
	if skew < 0 {
		return pki.Policy{}, fmt.Errorf("-skew %v: must not be negative", skew)
	}
	return pki.Policy{Anchor: anchor, Skew: skew}, nil
}

// how the chain is taken from the listed nodes
type selection struct {
	addrs []string
	hops  int
	fixed bool
	// listed nodes the entry may leave out of its descriptors
	missing  int
	infoPort string
	auth     bool
	trust    pki.Policy
	web      *http.Client
	attempts int
	pause    time.Duration
	rnd      io.Reader
}

// the entry is drawn first and asked for the bundles of every listed node, so
// the request is the same whatever path follows; the other hops are drawn only
// once all of them have passed the check. Nothing here logs the entry or any
// other node of the path: the lines are the same for every draw
func (s selection) chain(p jcrypto.CryptoProvider, logger *log.Logger, now time.Time) ([]client.Node, error) {
	entry := 0
	if !s.fixed {
		var err error
		if entry, err = client.ChooseEntry(len(s.addrs), s.rnd); err != nil {
			return nil, err
		}
	}
	bundles, err := nodeBundles(s.web, s.addrs, entry, s.infoPort, s.attempts, s.pause)
	if err != nil {
		return nil, s.named(err)
	}
	// position in the list of present nodes for every listed node, or -1
	at := make([]int, len(s.addrs))
	var addrs []string
	var held [][]byte
	for i, b := range bundles {
		at[i] = -1
		if b != nil {
			at[i] = len(addrs)
			addrs = append(addrs, s.addrs[i])
			held = append(held, b)
		}
	}
	if err := s.enough(at, entry); err != nil {
		return nil, err
	}
	// every bundle the entry does serve has to pass: one that fails is a refusal,
	// never a node left out
	nodes, err := resolve(p, s.auth, s.trust, addrs, held, now)
	if err != nil {
		return nil, err
	}
	if s.auth {
		for _, v := range nodes {
			// the entry's own descriptor is the freshest in its mirror, so its time
			// stays out of the log unless the chain is fixed anyway
			if s.fixed {
				logger.Printf("node %s identity=%s certificate until %s, descriptor until %s",
					v.Name, pki.Fingerprint(p, v.Identity),
					v.CertUntil.UTC().Format(time.RFC3339), v.DescUntil.UTC().Format(time.RFC3339))
				continue
			}
			logger.Printf("node %s identity=%s certificate until %s",
				v.Name, pki.Fingerprint(p, v.Identity), v.CertUntil.UTC().Format(time.RFC3339))
		}
	}
	if s.auth {
		logger.Printf("%d of %d listed nodes verified", len(nodes), len(s.addrs))
	}
	path := make([]int, s.hops)
	for i := range path {
		path[i] = at[i]
	}
	if !s.fixed {
		if path, err = client.ChooseRest(at[entry], len(nodes), s.hops, s.rnd); err != nil {
			return nil, err
		}
	}
	return chainOf(nodes, path), nil
}

// a mirror that waits for every node would let one node that withholds its
// descriptor empty the mirrors of all the others, so the entry may leave out a
// bounded number of nodes; a fixed chain needs exactly its own
func (s selection) enough(at []int, entry int) error {
	if s.fixed {
		for i := 0; i < s.hops; i++ {
			if at[i] < 0 {
				return fmt.Errorf("node %s: %w", s.addrs[i], errNoBundle)
			}
		}
		return nil
	}
	if at[entry] < 0 {
		return &entryError{errNoBundle}
	}
	absent := 0
	for _, i := range at {
		if i < 0 {
			absent++
		}
	}
	allowed := client.MaxAbsent(len(s.addrs), s.hops, s.missing)
	if absent > allowed {
		return fmt.Errorf("%w: %d of %d listed nodes, at most %d may be left out", errTooFew, absent, len(s.addrs), allowed)
	}
	return nil
}

// with a fixed chain the entry is the first listed node, which the
// configuration already says, so its failure is reported in full
func (s selection) named(err error) error {
	var failed *entryError
	if s.fixed && errors.As(err, &failed) {
		return fmt.Errorf("node %s: %w", s.addrs[0], failed.err)
	}
	return err
}

// what a failure on the circuit is reported as: with a drawn chain only its
// class, since the error of a connection names the entry it was made to
func (s selection) cause(err error) string {
	if s.fixed {
		return err.Error()
	}
	return failureClass(err)
}

// a request to the entry that failed. The entry is the first node of the
// path, so the text carries neither its address nor the error itself, which
// names the address dialled
type entryError struct{ err error }

func (e *entryError) Error() string { return "the entry: " + failureClass(e.err) }

func (e *entryError) Unwrap() error { return e.err }

var knownFailures = []error{
	errNoBundle, fetch.ErrTooLarge, pki.ErrFormat, pki.ErrVersion, pki.ErrDuplicate,
	link.ErrHandshake, client.ErrNodeKey, wire.ErrPayloadSize,
}

// one of a fixed set of texts, none of which names a node
func failureClass(err error) string {
	var status *fetch.StatusError
	if errors.As(err, &status) {
		return status.Error()
	}
	for _, known := range knownFailures {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "timed out"
	}
	return "connection failed"
}

// every bundle comes from the entry, the one node the client connects to
// anyway; each is verified afterwards, so the entry can withhold a bundle but
// not alter one
func nodeBundles(web *http.Client, addrs []string, entry int, infoPort string, attempts int, pause time.Duration) ([][]byte, error) {
	url, err := fetch.URL(addrs[entry], infoPort, "/descriptors")
	if err != nil {
		return nil, &entryError{err}
	}
	entries, err := fetch.Mirror(web, url, attempts, pause)
	if err != nil {
		return nil, &entryError{err}
	}
	held := make(map[string][]byte, len(entries))
	for _, e := range entries {
		held[e.Addr] = e.Bundle
	}
	// a listed node the entry does not serve stays nil
	bundles := make([][]byte, len(addrs))
	for i, addr := range addrs {
		bundles[i] = held[addr]
	}
	return bundles, nil
}

func resolve(p jcrypto.CryptoProvider, auth bool, trust pki.Policy, addrs []string, bundles [][]byte, now time.Time) ([]pki.Verified, error) {
	if auth {
		return pki.VerifyChain(p, trust, addrs, bundles, now)
	}
	return pki.Unverified(p, addrs, bundles)
}

func chainOf(nodes []pki.Verified, path []int) []client.Node {
	chain := make([]client.Node, len(path))
	for i, node := range path {
		v := nodes[node]
		chain[i] = client.Node{Addr: v.Addr, StaticPub: v.OnionPub, LinkPub: v.LinkPub}
	}
	return chain
}
