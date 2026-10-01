package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/pki"
)

const (
	fetchAttempts = 30
	fetchPause    = time.Second
)

var errNoBundle = errors.New("the entry holds no bundle for it")

func main() {
	nodes := flag.String("nodes", "", "comma separated host:port of the chain, in order")
	infoPort := flag.String("info-port", "9100", "port where the entry, the first of -nodes, publishes the descriptors of the chain")
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
	auth := flag.Bool("auth", true, "verify every node descriptor against -ca before building the circuit; false takes the keys unverified")
	ca := flag.String("ca", "", "trust anchor <suite>:<base64>, the CA public key printed by jimichi enroll")
	skew := flag.Duration("skew", pki.Skew, "tolerated lag of this clock behind the nodes' clocks")
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

	addrs := splitList(*nodes)
	if len(addrs) == 0 {
		logger.Fatal("no nodes given")
	}

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		logger.Fatal(err)
	}
	provider, err := suite.New(chosen)
	if err != nil {
		logger.Fatal(err)
	}
	trust, err := trustPolicy(*auth, *ca, chosen, *skew)
	if err != nil {
		logger.Fatal(err)
	}
	if !*auth {
		logger.Print("WARNING: -auth=false, node keys are taken unverified from whoever answers the descriptor request")
	}

	bundles, err := chainBundles(fetch.NewClient(), addrs, *infoPort, fetchAttempts, fetchPause)
	if err != nil {
		logger.Fatalf("refusing to build the circuit: %v", err)
	}
	verified, err := resolve(provider, *auth, trust, addrs, bundles, time.Now())
	if err != nil {
		logger.Fatalf("refusing to build the circuit: %v", err)
	}
	if *auth {
		for _, v := range verified {
			logger.Printf("node %s identity=%s certificate until %s, descriptor until %s",
				v.Name, pki.Fingerprint(provider, v.Identity),
				v.CertUntil.UTC().Format(time.RFC3339), v.DescUntil.UTC().Format(time.RFC3339))
		}
	}
	chain := chainOf(verified)

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
		logger.Fatalf("dial: %v", err)
	}
	// Fatal would skip a deferred Close and leave the circuit keys unzeroed
	fail := func(format string, args ...any) {
		_ = c.Close()
		logger.Printf(format, args...)
		os.Exit(1)
	}
	defer c.Close()

	logger.Printf("circuit of %d hops, payload limit %d bytes, mode %s", len(chain), c.MaxPayload(), *mode)

	for i := 0; *count == 0 || i < *count; i++ {
		start := time.Now()
		if err := c.Send([]byte(*message)); err != nil {
			fail("send: %v", err)
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

// every bundle comes from the entry, the one node the client connects to
// anyway; each is verified afterwards, so the entry can withhold a bundle but
// not alter one
func chainBundles(web *http.Client, addrs []string, infoPort string, attempts int, pause time.Duration) ([][]byte, error) {
	url, err := fetch.URL(addrs[0], infoPort, "/descriptors")
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", addrs[0], err)
	}
	entries, err := fetch.Mirror(web, url, attempts, pause)
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", addrs[0], err)
	}
	held := make(map[string][]byte, len(entries))
	for _, e := range entries {
		held[e.Addr] = e.Bundle
	}
	bundles := make([][]byte, len(addrs))
	for i, addr := range addrs {
		b, ok := held[addr]
		if !ok {
			return nil, fmt.Errorf("node %s: %w", addr, errNoBundle)
		}
		bundles[i] = b
	}
	return bundles, nil
}

func resolve(p jcrypto.CryptoProvider, auth bool, trust pki.Policy, addrs []string, bundles [][]byte, now time.Time) ([]pki.Verified, error) {
	if auth {
		return pki.VerifyChain(p, trust, addrs, bundles, now)
	}
	return pki.Unverified(p, addrs, bundles)
}

func chainOf(nodes []pki.Verified) []client.Node {
	chain := make([]client.Node, len(nodes))
	for i, v := range nodes {
		chain[i] = client.Node{Addr: v.Addr, StaticPub: v.OnionPub, LinkPub: v.LinkPub}
	}
	return chain
}
