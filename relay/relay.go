// Package relay is the forwarding node: it peels one layer and passes the cell
// on, keeping nothing on disk.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
)

// called on the exit node with the delivered message; a non-nil return travels
// back to the client along the same circuit
type Deliver func(circuit uint64, payload []byte) []byte

type Config struct {
	Provider   jcrypto.CryptoProvider
	StaticPriv *secmem.Buffer
	// setups remembered to refuse a copy; once full the node refuses new
	// circuits until it restarts with a new key; zero picks the default
	SetupCache int
	Deliver    Deliver
	Dialer     net.Dialer
	// lets the testbed observe the link to the next hop the way a passive
	// network adversary would; nil means a plain dial. The context carries the
	// deadline a plain dial gets, so a hook cannot hold Close either
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Period sends one frame per tick on each circuit and direction, padding
	// when there is nothing queued; zero forwards every cell at once
	Period     time.Duration
	QueueCells int

	// the limits below take their default at zero and are off when negative
	HandshakeTimeout time.Duration
	SetupTimeout     time.Duration
	// zero picks a few periods when paced and a fixed bound otherwise
	WriteTimeout time.Duration
	// a circuit is idle while no cell passes in either direction; padding
	// does not count
	IdleTimeout     time.Duration
	CircuitLifetime time.Duration
	MaxHandshakes   int
	// zero picks an eighth of MaxHandshakes, at least one
	MaxHandshakesPerSource int
	MaxLinks               int
	MaxLinksPerSource      int
	// events per second from one source, allowed in bursts of the given size;
	// a burst cannot be negative, the rate is what turns the limit off
	SourceLinkRate   float64
	SourceLinkBurst  int
	SourceSetupRate  float64
	SourceSetupBurst int

	// the nodes this one extends to and the link key each must prove; nil
	// extends to any address over an anonymous link, which is the baseline
	// without node authentication
	Peers func(addr string) (linkPub []byte, ok bool)
}

type Relay struct {
	cfg    Config
	lim    limits
	setups *wire.SetupCache

	ctx    context.Context
	cancel context.CancelFunc

	serving atomic.Int32

	mu       sync.Mutex
	circuits map[uint64]*circuit
	// every circuit arrives on a connection of its own; a second one on the same
	// link would add a pacer whose frame rate counts the circuits sharing it
	owners      map[*link.Conn]uint64
	conns       map[net.Conn]struct{}
	inbound     int
	handshaking int
	sources     map[netip.Addr]*source
	sourceCap   int
	closed      bool
	handlers    sync.WaitGroup

	stats Stats
}

// aggregated only: per-circuit counters in a log would be exactly the metadata
// the system is built to withhold
type Stats struct {
	mu sync.Mutex
	Counters
}

type Counters struct {
	Accepted  uint64
	Forwarded uint64
	Delivered uint64
	Dropped   uint64
	Padding   uint64
	// circuits this node closed: a cell out of turn, a backward cell of another
	// kind or one it could not wrap, a cell with no room in its queue, a cell it
	// could not write to either neighbour, or a reply the exit could not seal.
	// a write that ran into its deadline is such a failed write and is counted
	// here and in TimedOut; a circuit closed for idleness or age is not
	Broken uint64

	AcceptRetries uint64
	RefusedLinks  uint64
	RefusedBusy   uint64
	RefusedSource uint64
	RefusedRate   uint64
	RefusedSetups uint64
	// setups whose next address Peers did not know, turned away without a
	// dial; the setup cell is counted in Dropped as well
	RefusedExtend uint64
	// setups whose next hop did not finish the link handshake: it holds
	// another key than the expected one, or answered something else or nothing
	// in time. The setup is not sent on; it is counted in Dropped as well, and
	// in TimedOut when the deadline ran out
	FailedExtend uint64
	// setup, write and handshake deadlines that ran out; a dial to the next
	// hop that times out shows in Dropped only
	TimedOut uint64
	// circuits closed for idleness or age
	Expired uint64
}

func (s *Stats) add(field *uint64) {
	s.mu.Lock()
	*field++
	s.mu.Unlock()
}

func (s *Stats) Snapshot() Counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Counters
}

type circuit struct {
	hop      *wire.Hop
	fwdSeq   wire.Sequence
	bwdSeq   wire.Sequence
	next     *link.Conn
	nextRaw  net.Conn
	in       *link.Conn
	nextID   uint64
	isExit   bool
	writeMu  sync.Mutex
	inMu     sync.Mutex
	inbound  uint64
	hopIndex int
	replies  uint64
	done     chan struct{}
	fwd      *pacer
	bwd      *pacer

	born time.Time
	// time since born of the last cell either way, on the monotonic clock
	active atomic.Int64
	// guards the expiry timer against a reset racing the release that stops it
	expiryMu  sync.Mutex
	expiry    *time.Timer
	unwatched bool
}

func New(cfg Config) (*Relay, error) {
	if cfg.Provider == nil {
		return nil, errors.New("relay: no provider")
	}
	if cfg.StaticPriv == nil {
		return nil, errors.New("relay: no static key")
	}
	if cfg.QueueCells < 0 || cfg.QueueCells > maxQueueCells {
		return nil, fmt.Errorf("relay: queue of %d cells outside 0..%d", cfg.QueueCells, maxQueueCells)
	}
	if cfg.SetupCache < 0 || cfg.SetupCache > MaxSetupCache {
		return nil, fmt.Errorf("relay: setup cache of %d entries outside 0..%d", cfg.SetupCache, MaxSetupCache)
	}
	lim, err := resolveLimits(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{
		cfg:       cfg,
		lim:       lim,
		setups:    wire.NewSetupCache(cfg.SetupCache),
		ctx:       ctx,
		cancel:    cancel,
		circuits:  make(map[uint64]*circuit),
		owners:    make(map[*link.Conn]uint64),
		conns:     make(map[net.Conn]struct{}),
		sources:   make(map[netip.Addr]*source),
		sourceCap: maxSources,
	}, nil
}

// bounds how long a silent next hop can hold a dial or a handshake open, so
// neither can keep Close from reaching the keys
const onwardTimeout = 5 * time.Second

// tags sit on the heap for the life of the node key, about 36 bytes each with
// the map overhead, so this keeps the cache near 36 MiB, inside a 128 MiB pod
const MaxSetupCache = 1 << 20

var (
	errDuplicate = errors.New("relay: circuit id already in use")
	errLinkTaken = errors.New("relay: link already carries a circuit")
	// a cell out of turn or with no room ends its circuit: losing or passing it
	// would leave a mark every node after this one could see
	errBroken    = errors.New("relay: circuit broken")
	errOutOfTurn = fmt.Errorf("%w: counter out of turn", errBroken)
	errQueueFull = fmt.Errorf("%w: send queue full", errBroken)
	errNotPeer   = errors.New("relay: next address is not a known node")
)

func (r *Relay) Stats() *Stats { return &r.stats }

// reports whether some Serve is still accepting, which is what readiness means
func (r *Relay) Serving() bool { return r.serving.Load() > 0 }

// a temporary accept error, such as running out of descriptors, is waited out
// the way net/http does; Serve returns on a closed listener or a permanent error,
// and returns nil only once the relay itself is closed
func (r *Relay) Serve(ln net.Listener) error {
	r.serving.Add(1)
	defer r.serving.Add(-1)
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if r.isClosed() {
				return nil
			}
			if !temporary(err) {
				return err
			}
			r.stats.add(&r.stats.AcceptRetries)
			delay = acceptBackoff(delay)
			wait := time.NewTimer(delay)
			select {
			case <-wait.C:
			case <-r.ctx.Done():
				wait.Stop()
				return nil
			}
			continue
		}
		delay = 0
		src := sourceOf(conn.RemoteAddr())
		switch err := r.admit(conn, src); {
		case err == nil:
			go r.handle(conn, src)
		case errors.Is(err, errRelayClosed):
			_ = conn.Close()
			return nil
		default:
			_ = conn.Close()
		}
	}
}

// returns once every circuit key is released: each connection handler tears
// down its own circuits, so no key is destroyed while a goroutine still uses it.
// outgoing links are in conns too, otherwise a stalled next hop would keep a
// handler, and with it Close, blocked
func (r *Relay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	r.cancel()
	for _, c := range conns {
		_ = c.Close()
	}
	r.handlers.Wait()
}

func (r *Relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *Relay) hold(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[conn] = struct{}{}
	return true
}

func (r *Relay) drop(conn net.Conn) {
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

func (r *Relay) owns(lc *link.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.owners[lc]
	return ok
}

func (r *Relay) handle(conn net.Conn, src netip.Addr) {
	defer r.handlers.Done()
	defer func() {
		r.leave(conn, src)
		_ = conn.Close()
	}()

	// an honest initiator sends its hello at once, so a short deadline costs it
	// nothing and frees the slot of a silent one early
	if r.lim.handshake > 0 {
		_ = conn.SetDeadline(time.Now().Add(r.lim.handshake))
	}
	lc, err := link.Accept(conn, r.cfg.Provider, r.cfg.StaticPriv)
	r.handshakeDone(src)
	if err != nil {
		r.stats.timeout(err)
		return
	}
	lc.SetWriteTimeout(r.lim.write)
	_ = conn.SetDeadline(time.Time{})
	// a link is worth its socket only once it carries a circuit
	awaiting := r.lim.setup > 0
	if awaiting {
		_ = conn.SetReadDeadline(time.Now().Add(r.lim.setup))
	}
	defer func() {
		_ = lc.Close()
		r.teardown(lc)
	}()

	for {
		var cell wire.Cell
		if err := lc.ReadCell(&cell); err != nil {
			r.stats.timeout(err)
			return
		}
		if err := r.route(&cell, lc, src); err != nil {
			if errors.Is(err, errBroken) {
				r.stats.add(&r.stats.Broken)
				return
			}
			r.stats.add(&r.stats.Dropped)
			if errors.Is(err, errFatal) {
				return
			}
		}
		if awaiting && r.owns(lc) {
			awaiting = false
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
}

var errFatal = errors.New("relay: connection unusable")

func (r *Relay) route(cell *wire.Cell, from *link.Conn, src netip.Addr) error {
	hdr, err := cell.Header()
	if err != nil {
		return err
	}
	r.stats.add(&r.stats.Accepted)

	if hdr.Kind == wire.KindControl {
		return r.setup(cell, hdr, from, src)
	}

	r.mu.Lock()
	c := r.circuits[hdr.Circuit]
	r.mu.Unlock()
	// a circuit answers only on the link that set it up, which also keeps its keys
	// in the hands of the one goroutine that later releases them
	if c == nil || c.in != from {
		return fmt.Errorf("relay: unknown circuit")
	}
	// the counter is taken only once the layer opens: a cell nobody sealed is
	// dropped and decides nothing about which counter is due
	if c.isExit {
		payload, cover, err := c.hop.OpenLast(cell)
		if err != nil {
			return err
		}
		if !c.fwdSeq.Next(hdr.Counter) {
			return errOutOfTurn
		}
		c.touch()
		r.stats.add(&r.stats.Delivered)
		var reply []byte
		if !cover && r.cfg.Deliver != nil {
			reply = r.cfg.Deliver(c.inbound, payload)
		}
		// one backward cell for every data cell, cover for cover: replies only to
		// messages would show every node on the way back which cells were real
		return r.reply(c, reply)
	}

	out, err := c.hop.Peel(cell)
	if err != nil {
		return err
	}
	if !c.fwdSeq.Next(hdr.Counter) {
		return errOutOfTurn
	}
	c.touch()
	out.SetCircuit(c.nextID)
	if c.fwd != nil {
		if !c.fwd.push(out, true) {
			return errQueueFull
		}
		return nil
	}
	if err := c.write(out); err != nil {
		r.stats.timeout(err)
		return writeFailure(err)
	}
	r.stats.add(&r.stats.Forwarded)
	return nil
}

// a nil payload goes back as cover
func (r *Relay) reply(c *circuit, payload []byte) error {
	c.writeMu.Lock()
	counter := c.replies
	c.replies++
	c.writeMu.Unlock()

	var cell *wire.Cell
	var err error
	if payload != nil {
		cell, err = c.hop.SealReply(c.inbound, counter, payload)
		// the number is taken and a gap would close the circuit a relay further
		// on, so a reply too long for a cell leaves as cover under the same
		// number; the length is refused before anything is sealed, so the cover
		// reuses no nonce, while any other failure may come after the seal
		if errors.Is(err, wire.ErrPayloadSize) {
			r.stats.add(&r.stats.Dropped)
			cell, err = nil, nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", errBroken, err)
		}
	}
	if cell == nil {
		if cell, err = c.hop.SealCoverReply(c.inbound, counter); err != nil {
			return fmt.Errorf("%w: %v", errBroken, err)
		}
	}
	if c.bwd != nil {
		if !c.bwd.push(cell, false) {
			return errQueueFull
		}
		return nil
	}
	if err := c.writeBack(cell); err != nil {
		r.stats.timeout(err)
		return writeFailure(err)
	}
	return nil
}

// a cell that cannot be written ends its circuit as surely as one out of turn,
// so it is counted the same way; a link this node closed itself belongs to a
// teardown already under way and is not counted again
func writeFailure(err error) error {
	if lostToTeardown(err) {
		return fmt.Errorf("%w: %v", errFatal, err)
	}
	return fmt.Errorf("%w: write: %v", errBroken, err)
}

func lostToTeardown(err error) bool { return errors.Is(err, net.ErrClosed) }

// a circuit dies with the link it came in on; closing the link onwards makes the
// next relay do the same, so a break anywhere reaches both ends of the chain
func (r *Relay) teardown(from *link.Conn) {
	r.mu.Lock()
	id, ok := r.owners[from]
	c := r.circuits[id]
	if ok {
		delete(r.owners, from)
		delete(r.circuits, id)
	}
	r.mu.Unlock()
	if ok && c != nil {
		r.release(c)
	}
}

func (r *Relay) release(c *circuit) {
	c.unwatch()
	if c.next != nil {
		_ = c.next.Close()
		c.fwd.close()
		<-c.done
		r.drop(c.nextRaw)
	}
	c.bwd.close()
	c.hop.Close()
}

// cells coming from the next hop travel towards the client, so this relay adds
// its own layer instead of stripping one
func (r *Relay) backward(c *circuit) {
	defer func() {
		close(c.done)
		// the next hop is gone, so the previous one must learn it too
		_ = c.in.Close()
	}()
	for {
		var cell wire.Cell
		if err := c.next.ReadCell(&cell); err != nil {
			return
		}
		// this node cannot open what comes back, so the header is all it can
		// check, and any break in it ends the circuit
		hdr, err := cell.Header()
		if err != nil || hdr.Kind != wire.KindData || !c.bwdSeq.Next(hdr.Counter) {
			r.stats.add(&r.stats.Broken)
			return
		}
		out, err := c.hop.Wrap(&cell, c.inbound)
		if err != nil {
			r.stats.add(&r.stats.Broken)
			return
		}
		c.touch()
		if c.bwd != nil {
			if !c.bwd.push(out, true) {
				r.stats.add(&r.stats.Broken)
				return
			}
			continue
		}
		if err := c.writeBack(out); err != nil {
			r.stats.timeout(err)
			if !lostToTeardown(err) {
				r.stats.add(&r.stats.Broken)
			}
			return
		}
		r.stats.add(&r.stats.Forwarded)
	}
}

func (r *Relay) setup(cell *wire.Cell, hdr wire.Header, from *link.Conn, src netip.Addr) error {
	// a link carries one circuit, so a further setup on it is turned away before
	// it costs an agreement or a tag: otherwise one link could fill the cache
	if r.owns(from) {
		return errLinkTaken
	}
	if !r.allowSetup(src) {
		r.stats.add(&r.stats.RefusedSetups)
		return r.setupFailed(from, errSetupRate)
	}

	layer, err := wire.OpenSetup(r.cfg.Provider, r.cfg.StaticPriv, cell)
	if err != nil {
		return r.setupFailed(from, err)
	}
	// burned on first sight whatever happens next: a setup that fails further on
	// must not come back later on a fresh link either
	if err := r.setups.Add(layer.Tag); err != nil {
		layer.CellKey.Release()
		return r.setupFailed(from, err)
	}
	index := int(hdr.Counter)

	hop, err := wire.NewHop(r.cfg.Provider, layer.CellKey, layer.Offsets, index)
	layer.CellKey.Release()
	if err != nil {
		return r.setupFailed(from, err)
	}

	c := &circuit{
		hop:      hop,
		nextID:   layer.NextCircuit,
		isExit:   layer.NextAddr == "",
		inbound:  hdr.Circuit,
		in:       from,
		hopIndex: index,
		done:     make(chan struct{}),
		born:     time.Now(),
	}
	if c.isExit {
		c.fwdSeq.Expect(layer.First)
	}

	// registered before the next hop is dialled: a second setup with the same id,
	// replayed or not, must not replace a circuit whose keys only this map can release
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		hop.Close()
		return errFatal
	}
	if _, taken := r.circuits[hdr.Circuit]; taken {
		r.mu.Unlock()
		hop.Close()
		return r.setupFailed(from, errDuplicate)
	}
	if _, taken := r.owners[from]; taken {
		r.mu.Unlock()
		hop.Close()
		return errLinkTaken
	}
	r.circuits[hdr.Circuit] = c
	r.owners[from] = hdr.Circuit
	r.mu.Unlock()

	if c.isExit {
		c.bwd = r.newPacer(from)
		r.watch(c)
		return nil
	}
	if err := r.extend(c, layer, index); err != nil {
		r.mu.Lock()
		delete(r.circuits, hdr.Circuit)
		delete(r.owners, from)
		r.mu.Unlock()
		hop.Close()
		return r.setupFailed(from, err)
	}
	r.watch(c)
	return nil
}

// a link that carries no circuit is of no use to its peer; closing it is how
// the client learns that its setup went nowhere instead of sending into silence
func (r *Relay) setupFailed(from *link.Conn, err error) error {
	r.mu.Lock()
	_, owned := r.owners[from]
	r.mu.Unlock()
	if owned {
		return err
	}
	return fmt.Errorf("%w: %v", errFatal, err)
}

func (r *Relay) extend(c *circuit, layer *wire.SetupLayer, index int) error {
	var peerLink []byte
	if r.cfg.Peers != nil {
		key, ok := r.cfg.Peers(layer.NextAddr)
		// link.Dial reads a missing key as an anonymous link, so an empty one
		// counts as unknown
		if !ok || len(key) == 0 {
			r.stats.add(&r.stats.RefusedExtend)
			return errNotPeer
		}
		peerLink = key
	}
	raw, err := r.dial(layer.NextAddr)
	if err != nil {
		return err
	}
	if !r.hold(raw) {
		_ = raw.Close()
		return errFatal
	}
	fail := func(err error) error {
		r.stats.timeout(err)
		_ = raw.Close()
		r.drop(raw)
		return err
	}

	_ = raw.SetDeadline(time.Now().Add(onwardTimeout))
	// with the next node's link key the frame keys depend on its static key, and
	// the handshake ends only once that node has shown it derived them, so the
	// setup goes to no other; without a key the link is anonymous and hides
	// headers from a passive observer only
	conn, err := link.Dial(raw, r.cfg.Provider, peerLink)
	if err != nil {
		if errors.Is(err, link.ErrHandshake) {
			r.stats.add(&r.stats.FailedExtend)
		}
		return fail(err)
	}
	conn.SetWriteTimeout(r.lim.write)
	fwd, err := wire.ForwardSetup(layer, index)
	if err != nil {
		_ = conn.Close()
		return fail(err)
	}
	if err := conn.WriteCell(fwd); err != nil {
		_ = conn.Close()
		return fail(err)
	}
	_ = raw.SetDeadline(time.Time{})

	c.next = conn
	c.nextRaw = raw
	// both pacers start only once the circuit is complete here, so a failed
	// extend has no writer on the inbound link left to stop
	c.fwd = r.newPacer(conn)
	c.bwd = r.newPacer(c.in)
	go r.backward(c)
	return nil
}

func (r *Relay) newPacer(out *link.Conn) *pacer {
	if r.cfg.Period <= 0 {
		return nil
	}
	return newPacer(out, r.cfg.Period, r.cfg.QueueCells, &r.stats)
}

func (r *Relay) dial(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(r.ctx, onwardTimeout)
	defer cancel()
	if r.cfg.Dial != nil {
		return r.cfg.Dial(ctx, "tcp", addr)
	}
	return r.cfg.Dialer.DialContext(ctx, "tcp", addr)
}

func (c *circuit) write(cell *wire.Cell) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.next.WriteCell(cell)
}

func (c *circuit) writeBack(cell *wire.Cell) error {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	return c.in.WriteCell(cell)
}

func (c *circuit) touch() { c.active.Store(int64(time.Since(c.born))) }

// one timer per circuit that sleeps until the nearer of the idle and the age
// limit; a cell only moves a timestamp, so traffic never resets the timer
func (r *Relay) watch(c *circuit) {
	if r.lim.idle <= 0 && r.lim.lifetime <= 0 {
		return
	}
	c.touch()
	c.expiryMu.Lock()
	defer c.expiryMu.Unlock()
	if c.unwatched {
		return
	}
	c.expiry = time.AfterFunc(time.Until(r.expiresAt(c)), func() { r.expire(c) })
}

func (r *Relay) expiresAt(c *circuit) time.Time {
	var at time.Time
	if r.lim.idle > 0 {
		at = c.born.Add(time.Duration(c.active.Load()) + r.lim.idle)
	}
	if r.lim.lifetime > 0 {
		if end := c.born.Add(r.lim.lifetime); at.IsZero() || end.Before(at) {
			at = end
		}
	}
	return at
}

func (r *Relay) expire(c *circuit) {
	c.expiryMu.Lock()
	if c.unwatched {
		c.expiryMu.Unlock()
		return
	}
	if left := time.Until(r.expiresAt(c)); left > 0 {
		c.expiry.Reset(left)
		c.expiryMu.Unlock()
		return
	}
	c.unwatched = true
	c.expiryMu.Unlock()
	r.stats.add(&r.stats.Expired)
	// the handler reading this link then tears the circuit down as if the
	// previous hop had hung up, and the break travels both ways
	_ = c.in.Close()
}

func (c *circuit) unwatch() {
	c.expiryMu.Lock()
	defer c.expiryMu.Unlock()
	c.unwatched = true
	if c.expiry != nil {
		c.expiry.Stop()
	}
}
