package relay

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"time"
)

const (
	DefaultHandshakeTimeout  = 2 * time.Second
	DefaultSetupTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 5 * time.Minute
	DefaultCircuitLifetime   = 24 * time.Hour
	DefaultMaxHandshakes     = 32
	DefaultMaxLinks          = 512
	DefaultMaxLinksPerSource = 32
	DefaultSourceLinkRate    = 10.0
	DefaultSourceLinkBurst   = 50
	// one address needs about 91 hours to fill the default setup cache
	DefaultSourceSetupRate  = 0.2
	DefaultSourceSetupBurst = 10

	// the share of the handshake slots one address may hold
	sourceHandshakeShare = 8

	// without pacing a write blocks only while the peer's window is shut
	unpacedWriteTimeout = 5 * time.Second
	// a paced write waits a few periods, never less than a scheduler pause
	pacedWritePeriods  = 4
	minPacedWriteLimit = time.Second

	// keeps many short-lived sources from growing the table without end
	maxSources = 1 << 14
)

// the effective values: zero here means the limit is off
type limits struct {
	handshake, setup, write, idle, lifetime time.Duration
	handshakes, sourceHandshakes            int
	links, perSource                        int
	linkRate, setupRate                     float64
	linkBurst, setupBurst                   float64
}

func pick[T ~int | ~int64 | ~float64](v, def T) T {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

func resolveLimits(cfg Config) (limits, error) {
	for _, rate := range []float64{cfg.SourceLinkRate, cfg.SourceSetupRate} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) {
			return limits{}, fmt.Errorf("relay: source rate %v is not a number of events per second", rate)
		}
	}
	if cfg.SourceLinkBurst < 0 || cfg.SourceSetupBurst < 0 {
		return limits{}, errors.New("relay: negative burst; a negative rate is what turns a source rate off")
	}
	l := limits{
		handshake:  pick(cfg.HandshakeTimeout, DefaultHandshakeTimeout),
		setup:      pick(cfg.SetupTimeout, DefaultSetupTimeout),
		idle:       pick(cfg.IdleTimeout, DefaultIdleTimeout),
		lifetime:   pick(cfg.CircuitLifetime, DefaultCircuitLifetime),
		handshakes: pick(cfg.MaxHandshakes, DefaultMaxHandshakes),
		links:      pick(cfg.MaxLinks, DefaultMaxLinks),
		perSource:  pick(cfg.MaxLinksPerSource, DefaultMaxLinksPerSource),
		linkRate:   pick(cfg.SourceLinkRate, DefaultSourceLinkRate),
		setupRate:  pick(cfg.SourceSetupRate, DefaultSourceSetupRate),
		linkBurst:  float64(pick(cfg.SourceLinkBurst, DefaultSourceLinkBurst)),
		setupBurst: float64(pick(cfg.SourceSetupBurst, DefaultSourceSetupBurst)),
	}
	shared := l.handshakes
	if shared == 0 {
		shared = DefaultMaxHandshakes
	}
	l.sourceHandshakes = pick(cfg.MaxHandshakesPerSource, max(1, shared/sourceHandshakeShare))
	switch {
	case cfg.WriteTimeout != 0:
		l.write = pick(cfg.WriteTimeout, 0)
	case cfg.Period > 0:
		l.write = max(pacedWritePeriods*cfg.Period, minPacedWriteLimit)
	default:
		l.write = unpacedWriteTimeout
	}
	return l, nil
}

func (l limits) perSourceOn() bool {
	return l.perSource > 0 || l.sourceHandshakes > 0 || l.linkRate > 0 || l.setupRate > 0
}

type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newBucket(rate, burst float64, now time.Time) bucket {
	return bucket{rate: rate, burst: burst, tokens: burst, last: now}
}

func (b *bucket) refill(now time.Time) {
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
}

func (b *bucket) take(now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *bucket) full(now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	b.refill(now)
	return b.tokens >= b.burst
}

func (b *bucket) refilledIn(now time.Time) time.Duration {
	if b.rate <= 0 {
		return 0
	}
	b.refill(now)
	// capped so that a tiny rate cannot overflow the duration; an early timer
	// only looks again
	seconds := min((b.burst-b.tokens)/b.rate, time.Hour.Seconds())
	return time.Duration(seconds * float64(time.Second))
}

type source struct {
	open        int
	handshaking int
	links       bucket
	setups      bucket
	// a timer is already set to forget this source once its buckets refill
	forgetting bool
}

func (s *source) forgettable(now time.Time) bool {
	return s.open == 0 && s.links.full(now) && s.setups.full(now)
}

// an IPv6 host usually holds a whole /64, so the prefix is what counts as one peer
func sourceOf(addr net.Addr) netip.Addr {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip := tcp.AddrPort().Addr().Unmap().WithZone("")
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

var (
	errRelayClosed = errors.New("relay: closed")
	errRefused     = errors.New("relay: over a limit")
	errSetupRate   = errors.New("relay: setups from this source too frequent")
)

// every check runs before the connection costs a key pair or an agreement
func (r *Relay) admit(conn net.Conn, src netip.Addr) error {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errRelayClosed
	}
	var s *source
	if r.lim.perSourceOn() {
		if s = r.source(src, now); s == nil {
			r.stats.add(&r.stats.RefusedSource)
			return errRefused
		}
		// every connection costs a token, refused or not, so one retrying
		// against a full node spends its own allowance and not the others'
		if !s.links.take(now) {
			r.stats.add(&r.stats.RefusedRate)
			r.settle(src, s, now)
			return errRefused
		}
		// checked before the shared caps, so one address cannot hold them all
		if (r.lim.perSource > 0 && s.open >= r.lim.perSource) ||
			(r.lim.sourceHandshakes > 0 && s.handshaking >= r.lim.sourceHandshakes) {
			r.stats.add(&r.stats.RefusedSource)
			r.settle(src, s, now)
			return errRefused
		}
	}
	if r.lim.links > 0 && r.inbound >= r.lim.links {
		r.stats.add(&r.stats.RefusedLinks)
		r.settle(src, s, now)
		return errRefused
	}
	if r.lim.handshakes > 0 && r.handshaking >= r.lim.handshakes {
		r.stats.add(&r.stats.RefusedBusy)
		r.settle(src, s, now)
		return errRefused
	}
	if s != nil {
		s.open++
		s.handshaking++
	}
	r.inbound++
	r.handshaking++
	r.conns[conn] = struct{}{}
	r.handlers.Add(1)
	return nil
}

func (r *Relay) source(src netip.Addr, now time.Time) *source {
	if s, ok := r.sources[src]; ok {
		return s
	}
	if len(r.sources) >= r.sourceCap {
		return nil
	}
	s := &source{
		links:  newBucket(r.lim.linkRate, r.lim.linkBurst, now),
		setups: newBucket(r.lim.setupRate, r.lim.setupBurst, now),
	}
	r.sources[src] = s
	return s
}

func (r *Relay) handshakeDone(src netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handshaking--
	if s := r.sources[src]; s != nil {
		s.handshaking--
	}
}

func (r *Relay) leave(conn net.Conn, src netip.Addr) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, conn)
	r.inbound--
	if s := r.sources[src]; s != nil {
		s.open--
		r.settle(src, s, now)
	}
}

// an address stays in memory only while it has links open or tokens to win
// back, so the table does not keep a record of who connected; the caller holds mu
func (r *Relay) settle(src netip.Addr, s *source, now time.Time) {
	if s == nil || s.open > 0 || s.forgetting {
		return
	}
	if s.forgettable(now) {
		delete(r.sources, src)
		return
	}
	s.forgetting = true
	wait := max(s.links.refilledIn(now), s.setups.refilledIn(now)) + time.Millisecond
	time.AfterFunc(wait, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		s.forgetting = false
		if r.sources[src] == s {
			r.settle(src, s, time.Now())
		}
	})
}

func (r *Relay) allowSetup(src netip.Addr) bool {
	if r.lim.setupRate <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sources[src]
	return s == nil || s.setups.take(now)
}

func (s *Stats) timeout(err error) {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		s.add(&s.TimedOut)
	}
}

// the same test net/http applies: descriptor exhaustion and aborted handshakes
// pass, a closed listener does not
func temporary(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

func acceptBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Millisecond
	}
	return min(2*d, time.Second)
}
