package lab

import (
	"context"
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
	Config Config
	// Entry and Exit carry the forward direction the attack scores; the Back
	// traces are the same links towards the client, counted for the cost
	Entry     []*Trace
	Exit      []*Trace
	EntryBack []*Trace
	ExitBack  []*Trace
	Sent      int
	Cells     int
	Dropped   uint64
	// cells the relays themselves dropped, from their aggregated counters
	RelayDropped uint64
	// where the observation window starts on the trace clock: flows begin to
	// send only once every circuit is up, so setup falls before it
	Origin time.Duration
	// delivery latency of every message that came back, in order
	Latency []time.Duration
	// messages whose echo had not come back when the run was read
	Unanswered int
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
	answer, err := link.ResponderHandshakeSize(provider)
	if err != nil {
		return nil, err
	}
	tap := func(conn net.Conn, out, in *Trace) net.Conn {
		return &tappedConn{
			Conn: conn,
			out:  &counter{trace: out, skip: handshake, frame: frame},
			in:   &counter{trace: in, skip: answer, frame: frame},
		}
	}

	exitTraces := make([]*Trace, 0, cfg.Flows)
	exitBack := make([]*Trace, 0, cfg.Flows)
	var exitMu sync.Mutex
	// the last link carries the cells of one circuit only, so a new connection
	// on it marks a new flow for the observer
	lastHopDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		t, back := NewTrace(start), NewTrace(start)
		exitMu.Lock()
		exitTraces = append(exitTraces, t)
		exitBack = append(exitBack, back)
		exitMu.Unlock()
		return tap(conn, t, back), nil
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
	entryBack := make([]*Trace, cfg.Flows)
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
	// real clients start at unrelated moments, so each schedule gets a random
	// phase; dialling back to back instead would put every client in phase and
	// hand the attack ties that no real network produces
	phases := rand.New(rand.NewSource(Derive(cfg.Seed, streamPhases)))
	schedule := max(cfg.Rate, cfg.CoverEvery)
	for i := 0; i < cfg.Flows; i++ {
		if schedule > 0 {
			time.Sleep(time.Duration(phases.Int63n(int64(schedule))))
		}
		entry[i], entryBack[i] = NewTrace(start), NewTrace(start)
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
				return tap(conn, entry[i], entryBack[i]), nil
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
	// the last client started its schedule a moment ago, so a window opening
	// now would sit in phase with it and not with the others
	if schedule > 0 {
		time.Sleep(time.Duration(phases.Int63n(int64(schedule))))
	}
	origin := time.Since(start)
	sent := runFlows(cfg, clients, latency)

	// a fixed drain would cut the latency tail of a slow schedule; a message
	// lost on the way never answers, so the wait is bounded by the configuration
	drain := 300*time.Millisecond + time.Duration(4*cfg.Hops)*(cfg.Rate+cfg.RelayPeriod+cfg.Jitter)
	_ = waitFor(func() bool { return latency.pending() == 0 }, drain)

	run := &Run{Config: cfg, Entry: entry, EntryBack: entryBack, Sent: sent, Latency: latency.samples(), Origin: origin, Unanswered: latency.pending()}
	for _, c := range clients {
		run.Dropped += c.Dropped()
	}
	for _, n := range nodes {
		run.RelayDropped += n.relay.Stats().Snapshot().Dropped
	}
	exitMu.Lock()
	run.Exit = exitTraces
	run.ExitBack = exitBack
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

// pairs a reply with the message that caused it by the sequence number the
// exit echoes back, so a lost message cannot shift every later pairing
type latencyCollector struct {
	mu   sync.Mutex
	sent []map[uint64]time.Time
	out  []time.Duration
}

const (
	flowField = 2
	seqField  = 8
)

func newLatency(clients []*client.Client) *latencyCollector {
	l := &latencyCollector{sent: make([]map[uint64]time.Time, len(clients))}
	for i, c := range clients {
		l.sent[i] = make(map[uint64]time.Time)
		go func(flow int, c *client.Client) {
			for reply := range c.Replies() {
				if len(reply) < flowField+seqField {
					continue
				}
				seq := binary.BigEndian.Uint64(reply[flowField : flowField+seqField])
				l.mu.Lock()
				if at, ok := l.sent[flow][seq]; ok {
					l.out = append(l.out, time.Since(at))
					delete(l.sent[flow], seq)
				}
				l.mu.Unlock()
			}
		}(i, c)
	}
	return l
}

func (l *latencyCollector) mark(flow int, seq uint64) {
	l.mu.Lock()
	l.sent[flow][seq] = time.Now()
	l.mu.Unlock()
}

func (l *latencyCollector) pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.sent {
		n += len(m)
	}
	return n
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
			rng := rand.New(rand.NewSource(Derive(cfg.Seed, streamGaps, uint64(flow))))
			payload := make([]byte, max(cfg.Payload, flowField+seqField))
			binary.BigEndian.PutUint16(payload[:flowField], uint16(flow))
			local := 0
			defer func() {
				mu.Lock()
				sent += local
				mu.Unlock()
			}()
			for time.Now().Before(deadline) {
				// exponential gaps: a real conversation is bursty, and a
				// regular pattern would make the attack unrealistically easy
				gap := time.Duration(rng.ExpFloat64() * float64(cfg.SendEvery))
				time.Sleep(gap)
				if time.Now().After(deadline) {
					break
				}
				seq := uint64(local)
				binary.BigEndian.PutUint64(payload[flowField:flowField+seqField], seq)
				latency.mark(flow, seq)
				if err := c.Send(payload); err != nil {
					return
				}
				local++
			}
		}(i, c)
	}
	wg.Wait()
	return sent
}

func startNode(provider jcrypto.CryptoProvider, period time.Duration, observed bool, dial func(context.Context, string, string) (net.Conn, error)) (*node, error) {
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
