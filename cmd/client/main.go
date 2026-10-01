package main

import (
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
	"github.com/jimichi-org/jimichi/pki"
)

const (
	maxBundle     = 16 << 10
	fetchAttempts = 30
	fetchPause    = time.Second
	fetchTimeout  = 5 * time.Second
)

func main() {
	nodes := flag.String("nodes", "", "comma separated host:port of the chain, in order")
	infoPort := flag.String("info-port", "9100", "port where a node publishes its descriptor")
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

	web := &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	bundles := make([][]byte, len(addrs))
	for i, addr := range addrs {
		url, err := descriptorURL(addr, *infoPort)
		if err == nil {
			bundles[i], err = fetchBundle(web, url, fetchAttempts, fetchPause)
		}
		if err != nil {
			logger.Fatalf("refusing to build the circuit: node %s: %v", addr, err)
		}
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

func descriptorURL(addr, infoPort string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return "http://" + net.JoinHostPort(host, infoPort) + "/descriptor", nil
}

// only a failed connection or a node still waiting for its certificate is
// worth another try; anything else it answered stays wrong on the next one
func fetchBundle(web *http.Client, url string, attempts int, pause time.Duration) ([]byte, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(pause)
		}
		body, retry, err := getBundle(web, url)
		if err == nil {
			return body, nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func getBundle(web *http.Client, url string) (body []byte, retry bool, err error) {
	resp, err := web.Get(url)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return nil, true, errors.New("no descriptor published, the node has no valid certificate")
	default:
		return nil, false, fmt.Errorf("descriptor request answered %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBundle+1))
	if err != nil {
		return nil, true, err
	}
	if len(body) > maxBundle {
		return nil, false, fmt.Errorf("descriptor over %d bytes", maxBundle)
	}
	if _, err := pki.ParseBundle(body); err != nil {
		return nil, false, err
	}
	return body, false, nil
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
