package relay

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
)

type served struct {
	r    *Relay
	addr string
	pub  []byte
	done chan error
}

// tune sees the relay before it serves, where no handler reads its fields yet
func serveOn(t *testing.T, p jcrypto.CryptoProvider, cfg Config, ln net.Listener, tune ...func(*Relay)) *served {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	cfg.Provider, cfg.StaticPriv, cfg.StaticPub = p, priv, pub
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, f := range tune {
		f(r)
	}
	s := &served{r: r, addr: ln.Addr().String(), pub: pub, done: make(chan error, 1)}
	go func() { s.done <- r.Serve(ln) }()
	t.Cleanup(func() {
		r.Close()
		_ = ln.Close()
	})
	return s
}

func serveRelay(t *testing.T, cfg Config) *served {
	t.Helper()
	s, _ := serveCounted(t, cfg)
	return s
}

// counts the operations that cost a node CPU before anyone is authenticated
type countingProvider struct {
	jcrypto.CryptoProvider
	keyPairs, agreements atomic.Int64
}

func (c *countingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	c.keyPairs.Add(1)
	return c.CryptoProvider.GenerateEphemeral()
}

func (c *countingProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	c.agreements.Add(1)
	return c.CryptoProvider.Agree(priv, peerPub, ctx)
}

func serveCounted(t *testing.T, cfg Config) (*served, *countingProvider) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &countingProvider{CryptoProvider: c25519.New()}
	// the hello size is learned once per suite; learning it here keeps that key
	// pair out of the counts
	if _, err := link.ResponderHandshakeSize(p); err != nil {
		t.Fatal(err)
	}
	s := serveOn(t, p, cfg, ln)
	p.keyPairs.Store(0)
	p.agreements.Store(0)
	return s, p
}

func dialFrom(t *testing.T, s *served, local string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
	raw, err := d.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial from %s: %v", local, err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func echo(_ uint64, payload []byte) []byte { return payload }

func waitUntil(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, limit)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (r *Relay) inboundLinks() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inbound
}

func roundTrip(t *testing.T, cl *client.Client) {
	t.Helper()
	if err := cl.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case reply, open := <-cl.Replies():
		if !open || string(reply) != "ping" {
			t.Fatalf("reply %q, open %v", reply, open)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply")
	}
}

func dialExit(t *testing.T, s *served, cfg client.Config) *client.Client {
	t.Helper()
	return dialChain(t, []*served{s}, cfg)
}

func dialChain(t *testing.T, nodes []*served, cfg client.Config) *client.Client {
	t.Helper()
	cfg.Provider = c25519.New()
	for _, n := range nodes {
		cfg.Chain = append(cfg.Chain, client.Node{Addr: n.addr, StaticPub: n.pub})
	}
	cl, err := client.Dial(cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func waitClosed(t *testing.T, cl *client.Client, limit time.Duration) {
	t.Helper()
	timeout := time.After(limit)
	for {
		select {
		case _, open := <-cl.Replies():
			if !open {
				return
			}
		case <-timeout:
			t.Fatalf("circuit still open after %v", limit)
		}
	}
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "accept: too many open files" }
func (temporaryError) Temporary() bool { return true }
func (temporaryError) Timeout() bool   { return false }

// a listener that first fails the way a node out of descriptors does, then
// accepts, and fails for good once told to
type flakyListener struct {
	net.Listener
	mu        sync.Mutex
	transient int
	permanent error
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.transient > 0 {
		l.transient--
		l.mu.Unlock()
		return nil, temporaryError{}
	}
	l.mu.Unlock()
	conn, err := l.Listener.Accept()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.permanent != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, l.permanent
	}
	return conn, err
}

func TestServeOutlastsTemporaryAcceptErrors(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: inner, transient: 3}
	s := serveOn(t, c25519.New(), Config{Deliver: echo}, ln)

	cl := dialExit(t, s, client.Config{})
	roundTrip(t, cl)
	select {
	case err := <-s.done:
		t.Fatalf("Serve returned %v after temporary errors", err)
	default:
	}
	if !s.r.Serving() {
		t.Fatal("a serving relay reports that it does not serve")
	}
	if n := s.r.Stats().Snapshot().AcceptRetries; n != 3 {
		t.Fatalf("%d accept retries counted, want 3", n)
	}

	broken := errors.New("listener broken")
	ln.mu.Lock()
	ln.permanent = broken
	ln.mu.Unlock()
	if conn, err := net.Dial("tcp", s.addr); err == nil {
		defer conn.Close()
	}
	select {
	case err := <-s.done:
		if !errors.Is(err, broken) {
			t.Fatalf("Serve returned %v, want %v", err, broken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve kept going after a permanent error")
	}
	if s.r.Serving() {
		t.Fatal("a relay whose Serve returned still reports that it serves")
	}
}

// completes the handshake and then sends nothing, which is all a link costs
// its peer before the setup
func idleLink(t *testing.T, s *served) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := link.Dial(raw, c25519.New(), s.pub); err != nil {
		t.Fatalf("link: %v", err)
	}
	return raw
}

func closedByPeer(t *testing.T, raw net.Conn, limit time.Duration) bool {
	t.Helper()
	_ = raw.SetReadDeadline(time.Now().Add(limit))
	_, err := raw.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestLinksWithoutSetupAreClosed(t *testing.T) {
	const links = 5
	s := serveRelay(t, Config{SetupTimeout: 200 * time.Millisecond})

	raws := make([]net.Conn, links)
	for i := range raws {
		raws[i] = idleLink(t, s)
	}
	for i, raw := range raws {
		if !closedByPeer(t, raw, 3*time.Second) {
			t.Fatalf("link %d without a setup is still open", i)
		}
	}
	waitUntil(t, "links released", 2*time.Second, func() bool { return s.r.inboundLinks() == 0 })
	if st := s.r.Stats().Snapshot(); st.TimedOut != links || st.Broken != 0 {
		t.Fatalf("%d timeouts and %d closed circuits counted, want %d and 0", st.TimedOut, st.Broken, links)
	}
}

func TestSetupDeadlineEndsWithTheSetup(t *testing.T) {
	setup := 150 * time.Millisecond
	s := serveRelay(t, Config{SetupTimeout: setup, Deliver: echo})
	cl := dialExit(t, s, client.Config{})
	roundTrip(t, cl)
	time.Sleep(3 * setup)
	roundTrip(t, cl)
	if n := s.r.Stats().Snapshot().TimedOut; n != 0 {
		t.Fatalf("%d timeouts on a link that carries a circuit", n)
	}
}

// a next hop that finishes its handshake, takes the setup and then never reads
type stalledHop struct {
	addr  string
	pub   []byte
	setup chan struct{}
}

func startStalledHop(t *testing.T) *stalledHop {
	t.Helper()
	p := c25519.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	h := &stalledHop{addr: ln.Addr().String(), pub: pub, setup: make(chan struct{})}
	held := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		held <- raw
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(1)
		}
		lc, err := link.Accept(raw, p, priv, pub)
		if err != nil {
			return
		}
		var cell wire.Cell
		if lc.ReadCell(&cell) == nil {
			close(h.setup)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case raw := <-held:
			_ = raw.Close()
		default:
		}
		priv.Release()
	})
	return h
}

func (r *Relay) onlyCircuit() *circuit {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.circuits {
		return c
	}
	return nil
}

// set once the circuit is complete, after extend has filled in every field
func (c *circuit) watched() bool {
	c.expiryMu.Lock()
	defer c.expiryMu.Unlock()
	return c.expiry != nil
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestStalledNextHopTearsTheCircuitDown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		period time.Duration
	}{{"paced", time.Millisecond}, {"unpaced", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			hop := startStalledHop(t)
			s := serveRelay(t, Config{
				Period:       tc.period,
				WriteTimeout: 100 * time.Millisecond,
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					conn, err := d.DialContext(ctx, network, addr)
					if tcp, ok := conn.(*net.TCPConn); ok {
						_ = tcp.SetWriteBuffer(1)
					}
					return conn, err
				},
			})
			cl, err := client.Dial(client.Config{Provider: c25519.New(), Chain: []client.Node{
				{Addr: s.addr, StaticPub: s.pub},
				{Addr: hop.addr, StaticPub: hop.pub},
			}})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			t.Cleanup(func() { _ = cl.Close() })
			select {
			case <-hop.setup:
			case <-time.After(3 * time.Second):
				t.Fatal("the setup never reached the next hop")
			}
			var c *circuit
			waitUntil(t, "circuit complete", 3*time.Second, func() bool {
				c = s.r.onlyCircuit()
				return c != nil && c.watched()
			})
			if tc.period == 0 {
				// without pacing only forwarded cells fill the stalled link
				go func() {
					for cl.SendCover() == nil {
					}
				}()
			}

			waitClosed(t, cl, 20*time.Second)
			waitUntil(t, "circuit released", 3*time.Second, func() bool { return s.r.inboundLinks() == 0 })
			// one failed write: one deadline that ran out and one circuit closed
			if st := s.r.Stats().Snapshot(); st.TimedOut != 1 || st.Broken != 1 {
				t.Fatalf("the stalled write counted %d timeouts and %d closed circuits, want 1 and 1", st.TimedOut, st.Broken)
			}
			if !isClosed(c.done) {
				t.Fatal("the backward reader is still running")
			}
			if c.fwd != nil && (!isClosed(c.fwd.done) || !isClosed(c.bwd.done)) {
				t.Fatal("a pacer is still running")
			}
			if _, err := c.hop.Peel(&wire.Cell{}); err == nil || err.Error() != "wire: hop closed" {
				t.Fatalf("the hop key is still in use: %v", err)
			}
			closed := make(chan struct{})
			go func() {
				s.r.Close()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("Close is stuck")
			}
		})
	}
}

// a next hop that takes the connection and leaves the link handshake unfinished:
// it says nothing, or answers its key and withholds the frame that confirms it
func startSilentHop(t *testing.T, answersKey bool) (addr string, pub []byte) {
	t.Helper()
	p := c25519.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	hello, err := link.InitiatorHandshakeSize(p)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		held <- raw
		if !answersKey {
			return
		}
		if _, err := io.ReadFull(raw, make([]byte, hello)); err == nil {
			_, _ = raw.Write(pub)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case raw := <-held:
			_ = raw.Close()
		default:
		}
	})
	return ln.Addr().String(), pub
}

// a relay whose bound on the dial and the handshake onwards a test can wait
// out, set before the relay serves
func serveBounded(t *testing.T, cfg Config, onward time.Duration) *served {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveOn(t, c25519.New(), cfg, ln, func(r *Relay) { r.onward = onward })
}

// the handshake onwards ends at its deadline wherever the next hop stopped: one
// failed extend, one deadline that ran out and the setup cell dropped
func TestSilentNextHopFailsTheExtendAtItsDeadline(t *testing.T) {
	for _, tc := range []struct {
		name       string
		answersKey bool
	}{{"no answer", false}, {"no confirmation", true}} {
		t.Run(tc.name, func(t *testing.T) {
			addr, pub := startSilentHop(t, tc.answersKey)
			s := serveBounded(t, Config{Peers: func(next string) ([]byte, bool) { return pub, next == addr }}, 150*time.Millisecond)

			cl, err := client.Dial(client.Config{Provider: c25519.New(), Chain: []client.Node{
				{Addr: s.addr, StaticPub: s.pub},
				{Addr: addr, StaticPub: pub},
			}})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			t.Cleanup(func() { _ = cl.Close() })
			// well inside the 5 s the bound is outside this test
			waitClosed(t, cl, 3*time.Second)

			if st := s.r.Stats().Snapshot(); st.FailedExtend != 1 || st.TimedOut != 1 || st.Dropped != 1 || st.RefusedExtend != 0 || st.Broken != 0 {
				t.Fatalf("failed extends = %d, timed out = %d, dropped = %d, refused extends = %d, closed circuits = %d, want 1, 1, 1, 0, 0",
					st.FailedExtend, st.TimedOut, st.Dropped, st.RefusedExtend, st.Broken)
			}
		})
	}
}

// a dial onwards that never connects ends at the same bound and, unlike a
// handshake, leaves nothing but the dropped setup cell in the counters
func TestUnreachableNextHopDropsTheSetupAtTheDialDeadline(t *testing.T) {
	priv, pub, err := c25519.New().GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	s := serveBounded(t, Config{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}, 150*time.Millisecond)

	cl, err := client.Dial(client.Config{Provider: c25519.New(), Chain: []client.Node{
		{Addr: s.addr, StaticPub: s.pub},
		{Addr: "127.0.0.1:9", StaticPub: pub},
	}})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	waitClosed(t, cl, 3*time.Second)

	if st := s.r.Stats().Snapshot(); st.Dropped != 1 || st.FailedExtend != 0 || st.TimedOut != 0 || st.RefusedExtend != 0 || st.Broken != 0 {
		t.Fatalf("dropped = %d, failed extends = %d, timed out = %d, refused extends = %d, closed circuits = %d, want 1, 0, 0, 0, 0",
			st.Dropped, st.FailedExtend, st.TimedOut, st.RefusedExtend, st.Broken)
	}
}

func TestOnwardBoundIsFiveSecondsUnlessATestSetsIt(t *testing.T) {
	if s := serveRelay(t, Config{}); s.r.onward != 5*time.Second {
		t.Fatalf("a relay bounds the dial and the handshake onwards by %v, want 5s", s.r.onward)
	}
}

// raw connections that never start a handshake: each holds a slot until the
// handshake deadline, which is what the admission limits count
func rawConn(t *testing.T, s *served) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func TestAdmissionLimitsRefuseAndCount(t *testing.T) {
	off := Config{HandshakeTimeout: -1, MaxHandshakes: -1, MaxHandshakesPerSource: -1, MaxLinks: -1, MaxLinksPerSource: -1, SourceLinkRate: -1, SourceSetupRate: -1}
	hello, err := link.InitiatorHandshakeSize(c25519.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		cfg     func(Config) Config
		counter func(Counters) uint64
	}{
		{"handshakes", func(c Config) Config { c.MaxHandshakes = 2; return c }, func(s Counters) uint64 { return s.RefusedBusy }},
		{"handshakes per source", func(c Config) Config { c.MaxHandshakesPerSource = 2; return c }, func(s Counters) uint64 { return s.RefusedSource }},
		{"links", func(c Config) Config { c.MaxLinks = 2; return c }, func(s Counters) uint64 { return s.RefusedLinks }},
		{"per source", func(c Config) Config { c.MaxLinksPerSource = 2; return c }, func(s Counters) uint64 { return s.RefusedSource }},
		{"link rate", func(c Config) Config { c.SourceLinkRate, c.SourceLinkBurst = 1e-6, 2; return c }, func(s Counters) uint64 { return s.RefusedRate }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cost := serveCounted(t, tc.cfg(off))
			first := rawConn(t, s)
			rawConn(t, s)
			waitUntil(t, "two links admitted", 2*time.Second, func() bool { return s.r.inboundLinks() == 2 })
			over := rawConn(t, s)
			// a whole hello, which an admitted connection would answer with a key
			// pair and an agreement
			_, _ = over.Write(make([]byte, hello))
			if !closedByPeer(t, over, 2*time.Second) {
				t.Fatal("a connection over the limit was admitted")
			}
			if n := tc.counter(s.r.Stats().Snapshot()); n != 1 {
				t.Fatalf("%d refusals counted, want 1", n)
			}
			if k, a := cost.keyPairs.Load(), cost.agreements.Load(); k != 0 || a != 0 {
				t.Fatalf("a refused connection cost %d key pairs and %d agreements", k, a)
			}

			_ = first.Close()
			waitUntil(t, "closed link released", 6*time.Second, func() bool { return s.r.inboundLinks() == 1 })
			refilled := !closedByPeer(t, rawConn(t, s), 200*time.Millisecond)
			// a token spent stays spent when the link closes, a slot comes back
			if want := tc.name != "link rate"; refilled != want {
				t.Fatalf("after one link closed a new one was admitted: %v, want %v", refilled, want)
			}
		})
	}
}

func (r *Relay) knownSources() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sources)
}

// the table would otherwise be a record of who connected, readable from memory
func TestSourcesAreForgottenOnceTheirLinksClose(t *testing.T) {
	s := serveRelay(t, Config{Deliver: echo, SourceSetupRate: 10})
	cl := dialExit(t, s, client.Config{})
	roundTrip(t, cl)
	if n := s.r.knownSources(); n != 1 {
		t.Fatalf("%d sources known while one link is open", n)
	}
	_ = cl.Close()
	waitUntil(t, "source forgotten", 3*time.Second, func() bool { return s.r.knownSources() == 0 })

	limited := serveRelay(t, Config{MaxLinksPerSource: -1, SourceLinkRate: 20, SourceLinkBurst: 1})
	admitted := rawConn(t, limited)
	waitUntil(t, "link admitted", 2*time.Second, func() bool { return limited.r.inboundLinks() == 1 })
	if !closedByPeer(t, rawConn(t, limited), 2*time.Second) {
		t.Fatal("a link over the rate was admitted")
	}
	_ = admitted.Close()
	waitUntil(t, "refused source forgotten", 3*time.Second, func() bool { return limited.r.knownSources() == 0 })
}

func TestSetupRateRefusesAndCounts(t *testing.T) {
	s, cost := serveCounted(t, Config{Deliver: echo, SourceSetupRate: 1e-6, SourceSetupBurst: 1})
	roundTrip(t, dialExit(t, s, client.Config{}))
	built := cost.agreements.Swap(0)

	second := dialExit(t, s, client.Config{})
	_ = second.Send([]byte("ping"))
	waitClosed(t, second, 3*time.Second)
	if n := s.r.Stats().Snapshot().RefusedSetups; n != 1 {
		t.Fatalf("%d refused setups counted, want 1", n)
	}
	// the link handshake is paid either way, the agreement with the node key is not
	if refused := cost.agreements.Load(); refused >= built {
		t.Fatalf("a refused setup cost %d agreements, a built circuit %d", refused, built)
	}
}

// a silent connection holds a handshake slot until its deadline; one address
// hammering a node spends its own tokens and leaves the other slots free
func TestOneSourceCannotHoldEveryHandshake(t *testing.T) {
	s := serveRelay(t, Config{
		Deliver:                echo,
		HandshakeTimeout:       -1,
		MaxHandshakes:          4,
		MaxHandshakesPerSource: 2,
		MaxLinksPerSource:      -1,
		SourceLinkRate:         1e-6,
		SourceLinkBurst:        5,
		SourceSetupRate:        -1,
	})
	for i := 0; i < 2; i++ {
		dialFrom(t, s, "127.0.0.2")
	}
	waitUntil(t, "two handshakes held", 2*time.Second, func() bool { return s.r.inboundLinks() == 2 })
	for i := 0; i < 4; i++ {
		if !closedByPeer(t, dialFrom(t, s, "127.0.0.2"), 2*time.Second) {
			t.Fatalf("connection %d of one source was admitted past its share", i+3)
		}
	}
	// three find the source at its share and still pay a token, the fourth finds
	// no token left; none of them reaches the shared cap
	st := s.r.Stats().Snapshot()
	if st.RefusedSource != 3 || st.RefusedRate != 1 || st.RefusedBusy != 0 {
		t.Fatalf("refused %d at the share, %d at the rate, %d at the shared cap; want 3, 1, 0",
			st.RefusedSource, st.RefusedRate, st.RefusedBusy)
	}
	roundTrip(t, dialExit(t, s, client.Config{}))
}

// retrying against a full node spends the retrying source's own tokens, so it
// cannot take a slot the moment one frees up
func TestRefusalAtASharedCapCostsAToken(t *testing.T) {
	s := serveRelay(t, Config{
		HandshakeTimeout:       -1,
		MaxHandshakes:          2,
		MaxHandshakesPerSource: -1,
		MaxLinksPerSource:      -1,
		SourceLinkRate:         1e-6,
		SourceLinkBurst:        2,
		SourceSetupRate:        -1,
	})
	holder := dialFrom(t, s, "127.0.0.2")
	dialFrom(t, s, "127.0.0.2")
	waitUntil(t, "shared cap full", 2*time.Second, func() bool { return s.r.inboundLinks() == 2 })
	for i := 0; i < 2; i++ {
		if !closedByPeer(t, dialFrom(t, s, "127.0.0.3"), 2*time.Second) {
			t.Fatalf("attempt %d was admitted past a full shared cap", i+1)
		}
	}

	_ = holder.Close()
	waitUntil(t, "slot freed", 2*time.Second, func() bool { return s.r.inboundLinks() == 1 })
	if !closedByPeer(t, dialFrom(t, s, "127.0.0.3"), 2*time.Second) {
		t.Fatal("a source that spent its burst against a full node took the freed slot")
	}
	if st := s.r.Stats().Snapshot(); st.RefusedBusy != 2 || st.RefusedRate != 1 {
		t.Fatalf("refused %d at the shared cap and %d at the rate, want 2 and 1", st.RefusedBusy, st.RefusedRate)
	}
}

func TestSilentHandshakeIsCutShort(t *testing.T) {
	s := serveRelay(t, Config{HandshakeTimeout: 200 * time.Millisecond})
	if !closedByPeer(t, rawConn(t, s), 1500*time.Millisecond) {
		t.Fatal("a silent connection kept its handshake slot past the deadline")
	}
	waitUntil(t, "slot released", 2*time.Second, func() bool { return s.r.inboundLinks() == 0 })
	if n := s.r.Stats().Snapshot().TimedOut; n != 1 {
		t.Fatalf("%d timeouts counted, want 1", n)
	}
}

func TestSourceTableIsBounded(t *testing.T) {
	s := serveRelay(t, Config{HandshakeTimeout: -1})
	s.r.mu.Lock()
	s.r.sourceCap = 2
	s.r.mu.Unlock()

	dialFrom(t, s, "127.0.0.2")
	third := dialFrom(t, s, "127.0.0.3")
	waitUntil(t, "two sources admitted", 2*time.Second, func() bool { return s.r.inboundLinks() == 2 })
	if !closedByPeer(t, dialFrom(t, s, "127.0.0.4"), 2*time.Second) {
		t.Fatal("a source past the bound of the table was admitted")
	}
	if n := s.r.knownSources(); n != 2 {
		t.Fatalf("the table holds %d sources, bound 2", n)
	}
	if n := s.r.Stats().Snapshot().RefusedSource; n != 1 {
		t.Fatalf("%d refusals counted, want 1", n)
	}
	if closedByPeer(t, dialFrom(t, s, "127.0.0.2"), 200*time.Millisecond) {
		t.Fatal("a known source was refused while the table was full")
	}

	_ = third.Close()
	waitUntil(t, "closed source forgotten", 3*time.Second, func() bool { return s.r.knownSources() == 1 })
	if closedByPeer(t, dialFrom(t, s, "127.0.0.4"), 200*time.Millisecond) {
		t.Fatal("a new source was refused after the table had room again")
	}
}

// the limited node is either the exit or a node that forwards, the other one
// has no limit of its own
func limitedChain(t *testing.T, where string, limited Config) (*served, []*served) {
	t.Helper()
	unlimited := Config{IdleTimeout: -1, CircuitLifetime: -1}
	if where == "exit" {
		limited.Deliver = echo
		exit := serveRelay(t, limited)
		return exit, []*served{exit}
	}
	unlimited.Deliver = echo
	exit := serveRelay(t, unlimited)
	entry := serveRelay(t, limited)
	return entry, []*served{entry, exit}
}

func TestIdleCircuitExpires(t *testing.T) {
	for _, where := range []string{"exit", "forwarding"} {
		t.Run(where, func(t *testing.T) {
			idle := 200 * time.Millisecond
			node, chain := limitedChain(t, where, Config{IdleTimeout: idle, CircuitLifetime: -1})

			busy := dialChain(t, chain, client.Config{CoverRate: 20 * time.Millisecond})
			quiet := dialChain(t, chain, client.Config{})
			roundTrip(t, quiet)
			time.Sleep(idle / 2)
			roundTrip(t, quiet)
			waitClosed(t, quiet, 3*time.Second)
			roundTrip(t, busy)
			// an expired circuit is not one the node closed over a fault
			if st := node.r.Stats().Snapshot(); st.Expired != 1 || st.Broken != 0 {
				t.Fatalf("%d circuits expired and %d counted as closed, want only the quiet one and 0", st.Expired, st.Broken)
			}
		})
	}
}

func TestOldCircuitExpires(t *testing.T) {
	for _, where := range []string{"exit", "forwarding"} {
		t.Run(where, func(t *testing.T) {
			lifetime := 500 * time.Millisecond
			node, chain := limitedChain(t, where, Config{IdleTimeout: -1, CircuitLifetime: lifetime})

			start := time.Now()
			cl := dialChain(t, chain, client.Config{CoverRate: 20 * time.Millisecond})
			roundTrip(t, cl)
			time.Sleep(lifetime / 4)
			roundTrip(t, cl)
			waitClosed(t, cl, 3*time.Second)
			if age := time.Since(start); age < lifetime {
				t.Fatalf("circuit closed after %v, before its lifetime of %v", age, lifetime)
			}
			if st := node.r.Stats().Snapshot(); st.Expired != 1 || st.Broken != 0 {
				t.Fatalf("%d circuits expired and %d counted as closed, want 1 and 0", st.Expired, st.Broken)
			}
		})
	}
}

func TestSourceLimitsMustBeValid(t *testing.T) {
	p := c25519.New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	for _, rate := range []float64{math.NaN(), math.Inf(1)} {
		if _, err := New(Config{Provider: p, StaticPriv: priv, StaticPub: pub, SourceLinkRate: rate}); err == nil {
			t.Fatalf("New accepted a link rate of %v", rate)
		}
	}
	// a negative rate turns a limit off; a negative burst would silently mean
	// the default instead
	for _, cfg := range []Config{{SourceLinkBurst: -1}, {SourceSetupBurst: -1}} {
		cfg.Provider, cfg.StaticPriv, cfg.StaticPub = p, priv, pub
		if _, err := New(cfg); err == nil {
			t.Fatalf("New accepted a negative burst: %+v", cfg)
		}
	}
}

func TestIPv6SourceIsItsPrefix(t *testing.T) {
	a := sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:aaaa::1"), Port: 1})
	b := sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:bbbb::2"), Port: 2})
	c := sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3})
	v4 := sourceOf(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 4})
	if a != b || a == c {
		t.Fatalf("sources %v, %v, %v: one /64 must be one source", a, b, c)
	}
	if v4.String() != "192.0.2.7" {
		t.Fatalf("mapped address counted as %v", v4)
	}
}
