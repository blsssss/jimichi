package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blsssss/jimichi/client"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/crypto/suite"
)

func main() {
	nodes := flag.String("nodes", "", "comma separated host:port of the chain, in order")
	infoPort := flag.String("info-port", "9100", "port where a node publishes its key")
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
	chain := make([]client.Node, 0, len(addrs))
	for _, addr := range addrs {
		pub, nodeSuite, err := fetchKey(addr, *infoPort)
		if err != nil {
			logger.Fatalf("key of %s: %v", addr, err)
		}
		if nodeSuite != chosen.String() {
			logger.Fatalf("%s runs suite %q, this client %q", addr, nodeSuite, chosen)
		}
		chain = append(chain, client.Node{Addr: addr, StaticPub: pub})
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

// a node publishes only its public key, so fetching it over plain http leaks
// nothing an observer could not derive from the directory anyway
func fetchKey(addr, infoPort string) (pub []byte, suiteName string, err error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}
	url := fmt.Sprintf("http://%s/key", net.JoinHostPort(host, infoPort))

	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		var body struct {
			Pub   string `json:"pub"`
			Suite string `json:"suite"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return nil, "", err
		}
		pub, err := base64.StdEncoding.DecodeString(body.Pub)
		return pub, body.Suite, err
	}
	return nil, "", lastErr
}
