package lab

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/blsssss/jimichi/client"
	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/relay"
)

type Config struct {
	Hops       int
	Flows      int
	Duration   time.Duration
	SendEvery  time.Duration
	CoverEvery time.Duration
	Mode       client.Mode
	Rate       time.Duration
	Jitter     time.Duration
	// every relay sends on its own clock with this period; zero forwards at once
	RelayPeriod time.Duration
	Payload     int
	Seed        int64
}

func (c Config) withDefaults() Config {
	if c.Hops == 0 {
		c.Hops = 3
	}
	if c.Flows == 0 {
		c.Flows = 5
	}
	if c.Duration == 0 {
		c.Duration = 20 * time.Second
	}
	if c.SendEvery == 0 {
		c.SendEvery = 200 * time.Millisecond
	}
	if c.Payload == 0 {
		c.Payload = 128
	}
	return c
}

// entry and exit traces of the same flow share an index, which is the ground
// truth the attack is scored against and which the attack itself never sees
type Run struct {
	Config  Config
	Entry   []*Trace
	Exit    []*Trace
	Sent    int
	Cells   int
	Dropped uint64
	// delivery latency of every message that came back, in order
	Latency []time.Duration
}

type node struct {
	addr  string
	pub   []byte
	relay *relay.Relay
	ln    net.Listener
	priv  *secmem.Buffer
}

// Execute runs one configuration end to end and returns what the adversary saw
func Execute(cfg Config) (*Run, error) {
	cfg = cfg.withDefaults()
	provider := c25519.New()
	start := time.Now()

	frame, err := link.FrameSize(provider)
	if err != nil {
		return nil, err
	}
	handshake, err := link.InitiatorHandshakeSize(provider)
	if err != nil {
		return nil, err
	}
	tap := func(conn net.Conn, t *Trace) net.Conn {
		return &tappedConn{Conn: conn, trace: t, skip: handshake, frame: frame}
	}

	exitTraces := make([]*Trace, 0, cfg.Flows)
	var exitMu sync.Mutex
	// the last link carries the cells of one circuit only, so a new connection
	// on it marks a new flow for the observer
	lastHopDial := func(network, addr string) (net.Conn, error) {
		conn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		t := NewTrace(start)
		exitMu.Lock()
		exitTraces = append(exitTraces, t)
		exitMu.Unlock()
		return tap(conn, t), nil
	}

	nodes := make([]*node, cfg.Hops)
	for i := cfg.Hops - 1; i >= 0; i-- {
		observed := i == cfg.Hops-2
		n, err := startNode(provider, cfg.RelayPeriod, observed, lastHopDial)
		if err != nil {
			return nil, err
		}
		nodes[i] = n
	}
	defer func() {
		for _, n := range nodes {
			n.relay.Close()
			_ = n.ln.Close()
			n.priv.Release()
		}
	}()

	chain := make([]client.Node, cfg.Hops)
	for i, n := range nodes {
		chain[i] = client.Node{Addr: n.addr, StaticPub: n.pub}
	}

	entry := make([]*Trace, cfg.Flows)
	clients := make([]*client.Client, cfg.Flows)
	defer func() {
		for _, c := range clients {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	exitSeen := func() int {
		exitMu.Lock()
		defer exitMu.Unlock()
		return len(exitTraces)
	}
	for i := 0; i < cfg.Flows; i++ {
		entry[i] = NewTrace(start)
		c, err := client.Dial(client.Config{
			Provider:  provider,
			Chain:     chain,
			Mode:      cfg.Mode,
			Rate:      cfg.Rate,
			CoverRate: cfg.CoverEvery,
			Jitter:    cfg.Jitter,
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return tap(conn, entry[i]), nil
			},
		})
		if err != nil {
			return nil, fmt.Errorf("flow %d: %w", i, err)
		}
		clients[i] = c
		// exit traces are labelled by the order their links open; letting the
		// next flow dial before this one's link exists would let two setups race
		// and score the attack against a wrong pairing
		if cfg.Hops >= 2 {
			if err := waitFor(func() bool { return exitSeen() == i+1 }, 5*time.Second); err != nil {
				return nil, fmt.Errorf("flow %d: exit link: %w", i, err)
			}
		}
	}

	latency := newLatency(clients)
	sent := runFlows(cfg, clients, latency)

	// let the last cells drain before the traces are read
	time.Sleep(300 * time.Millisecond)

	run := &Run{Config: cfg, Entry: entry, Sent: sent, Latency: latency.samples()}
	for _, c := range clients {
		run.Dropped += c.Dropped()
	}
	exitMu.Lock()
	run.Exit = exitTraces
	exitMu.Unlock()
	for _, t := range run.Entry {
		run.Cells += t.Len()
	}
	return run, nil
}

func waitFor(cond func() bool, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %v", limit)
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

// pairs a reply with the message that caused it: one flow per client, and the
// exit answers in order
type latencyCollector struct {
	mu   sync.Mutex
	sent [][]time.Time
	out  []time.Duration
}

func newLatency(clients []*client.Client) *latencyCollector {
	l := &latencyCollector{sent: make([][]time.Time, len(clients))}
	for i, c := range clients {
		go func(flow int, c *client.Client) {
			for range c.Replies() {
				l.mu.Lock()
				if len(l.sent[flow]) > 0 {
					l.out = append(l.out, time.Since(l.sent[flow][0]))
					l.sent[flow] = l.sent[flow][1:]
				}
				l.mu.Unlock()
			}
		}(i, c)
	}
	return l
}

func (l *latencyCollector) mark(flow int) {
	l.mu.Lock()
	l.sent[flow] = append(l.sent[flow], time.Now())
	l.mu.Unlock()
}

func (l *latencyCollector) samples() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]time.Duration, len(l.out))
	copy(out, l.out)
	return out
}

func runFlows(cfg Config, clients []*client.Client, latency *latencyCollector) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sent := 0
	deadline := time.Now().Add(cfg.Duration)

	for i, c := range clients {
		wg.Add(1)
		go func(flow int, c *client.Client) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(cfg.Seed + int64(flow)))
			payload := make([]byte, cfg.Payload)
			binary.BigEndian.PutUint16(payload[:2], uint16(flow))
			local := 0
			for time.Now().Before(deadline) {
				// exponential gaps: a real conversation is bursty, and a
				// regular pattern would make the attack unrealistically easy
				gap := time.Duration(rng.ExpFloat64() * float64(cfg.SendEvery))
				time.Sleep(gap)
				if time.Now().After(deadline) {
					break
				}
				latency.mark(flow)
				if err := c.Send(payload); err != nil {
					return
				}
				local++
			}
			mu.Lock()
			sent += local
			mu.Unlock()
		}(i, c)
	}
	wg.Wait()
	return sent
}

func startNode(provider jcrypto.CryptoProvider, period time.Duration, observed bool, dial func(string, string) (net.Conn, error)) (*node, error) {
	priv, pub, err := provider.GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	cfg := relay.Config{
		Provider:   provider,
		StaticPriv: priv,
		// the exit echoes, which is what lets a run measure delivery latency
		Deliver: func(_ uint64, payload []byte) []byte { return payload },
		Period:  period,
	}
	if observed {
		cfg.Dial = dial
	}
	r, err := relay.New(cfg)
	if err != nil {
		priv.Release()
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		priv.Release()
		return nil, err
	}
	go func() { _ = r.Serve(ln) }()
	return &node{addr: ln.Addr().String(), pub: pub, relay: r, ln: ln, priv: priv}, nil
}
