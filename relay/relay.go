// Package relay is the forwarding node: it peels one layer and passes the cell
// on, keeping nothing on disk.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/wire"
)

// called on the exit node with the delivered message; a non-nil return travels
// back to the client along the same circuit
type Deliver func(circuit uint64, payload []byte) []byte

type Config struct {
	Provider   jcrypto.CryptoProvider
	StaticPriv *secmem.Buffer
	ReplaySize uint64
	Deliver    Deliver
	Dialer     net.Dialer
	// lets the testbed observe the link to the next hop the way a passive
	// network adversary would; nil means a plain dial
	Dial func(network, addr string) (net.Conn, error)
}

type Relay struct {
	cfg Config

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	circuits map[uint64]*circuit
	conns    map[net.Conn]struct{}
	closed   bool
	handlers sync.WaitGroup

	stats Stats
}

// aggregated only: per-circuit counters in a log would be exactly the metadata
// the system is built to withhold
type Stats struct {
	mu        sync.Mutex
	Accepted  uint64
	Forwarded uint64
	Delivered uint64
	Dropped   uint64
}

func (s *Stats) add(field *uint64) {
	s.mu.Lock()
	*field++
	s.mu.Unlock()
}

func (s *Stats) Snapshot() (accepted, forwarded, delivered, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Accepted, s.Forwarded, s.Delivered, s.Dropped
}

type circuit struct {
	hop      *wire.Hop
	replay   *wire.ReplayWindow
	back     *wire.ReplayWindow
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
}

func New(cfg Config) (*Relay, error) {
	if cfg.Provider == nil {
		return nil, errors.New("relay: no provider")
	}
	if cfg.StaticPriv == nil {
		return nil, errors.New("relay: no static key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
		circuits: make(map[uint64]*circuit),
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// bounds how long a silent peer can hold a handshake or a dial open, so neither
// can keep Close from reaching the keys
const handshakeTimeout = 5 * time.Second

var errDuplicate = errors.New("relay: circuit id already in use")

func (r *Relay) Stats() *Stats { return &r.stats }

func (r *Relay) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
		if !r.hold(conn, true) {
			_ = conn.Close()
			return nil
		}
		go r.handle(conn)
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

func (r *Relay) hold(conn net.Conn, handler bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[conn] = struct{}{}
	if handler {
		r.handlers.Add(1)
	}
	return true
}

func (r *Relay) drop(conn net.Conn) {
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

func (r *Relay) handle(conn net.Conn) {
	defer r.handlers.Done()
	defer func() {
		r.drop(conn)
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	lc, err := link.Accept(conn, r.cfg.Provider, r.cfg.StaticPriv)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer func() {
		_ = lc.Close()
		r.teardown(lc)
	}()

	for {
		var cell wire.Cell
		if err := lc.ReadCell(&cell); err != nil {
			return
		}
		if err := r.route(&cell, lc); err != nil {
			r.stats.add(&r.stats.Dropped)
			if errors.Is(err, errFatal) {
				return
			}
		}
	}
}

var errFatal = errors.New("relay: connection unusable")

func (r *Relay) route(cell *wire.Cell, from *link.Conn) error {
	hdr, err := cell.Header()
	if err != nil {
		return err
	}
	r.stats.add(&r.stats.Accepted)

	if hdr.Kind == wire.KindControl {
		return r.setup(cell, hdr, from)
	}

	r.mu.Lock()
	c := r.circuits[hdr.Circuit]
	r.mu.Unlock()
	// a circuit answers only on the link that set it up, which also keeps its keys
	// in the hands of the one goroutine that later releases them
	if c == nil || c.in != from {
		return fmt.Errorf("relay: unknown circuit")
	}
	if !c.replay.Accept(hdr.Counter) {
		return fmt.Errorf("relay: replayed counter")
	}

	if c.isExit {
		payload, err := c.hop.OpenLast(cell, wire.Forward)
		if err != nil {
			return err
		}
		if hdr.Kind == wire.KindPayload && r.cfg.Deliver != nil {
			if reply := r.cfg.Deliver(c.inbound, payload); reply != nil {
				if err := r.reply(c, reply); err != nil {
					return err
				}
			}
		}
		r.stats.add(&r.stats.Delivered)
		return nil
	}

	out, err := c.hop.Peel(cell, wire.Forward)
	if err != nil {
		return err
	}
	out.SetCircuit(c.nextID)
	if err := c.write(out); err != nil {
		return fmt.Errorf("%w: %v", errFatal, err)
	}
	r.stats.add(&r.stats.Forwarded)
	return nil
}

func (r *Relay) reply(c *circuit, payload []byte) error {
	c.writeMu.Lock()
	counter := c.replies
	c.replies++
	c.writeMu.Unlock()

	cell, err := c.hop.SealReply(c.inbound, counter, payload)
	if err != nil {
		return err
	}
	return c.writeBack(cell)
}

// a circuit dies with the link it came in on; closing the link onwards makes the
// next relay do the same, so a break anywhere reaches both ends of the chain
func (r *Relay) teardown(from *link.Conn) {
	r.mu.Lock()
	var dead []*circuit
	for id, c := range r.circuits {
		if c.in == from {
			dead = append(dead, c)
			delete(r.circuits, id)
		}
	}
	r.mu.Unlock()
	for _, c := range dead {
		r.release(c)
	}
}

func (r *Relay) release(c *circuit) {
	if c.next != nil {
		_ = c.next.Close()
		<-c.done
		r.drop(c.nextRaw)
	}
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
		hdr, err := cell.Header()
		if err != nil {
			r.stats.add(&r.stats.Dropped)
			continue
		}
		if !c.back.Accept(hdr.Counter) {
			r.stats.add(&r.stats.Dropped)
			continue
		}
		out, err := c.hop.Wrap(&cell, c.inbound)
		if err != nil {
			r.stats.add(&r.stats.Dropped)
			continue
		}
		if err := c.writeBack(out); err != nil {
			return
		}
		r.stats.add(&r.stats.Forwarded)
	}
}

func (r *Relay) setup(cell *wire.Cell, hdr wire.Header, from *link.Conn) error {
	layer, err := wire.OpenSetup(r.cfg.Provider, r.cfg.StaticPriv, cell)
	if err != nil {
		return err
	}
	index := int(hdr.Counter)

	hop, err := wire.NewHop(r.cfg.Provider, layer.CellKey, index)
	layer.CellKey.Release()
	if err != nil {
		return err
	}

	c := &circuit{
		hop:      hop,
		replay:   wire.NewReplayWindow(r.cfg.ReplaySize),
		back:     wire.NewReplayWindow(r.cfg.ReplaySize),
		nextID:   layer.NextCircuit,
		isExit:   layer.NextAddr == "",
		inbound:  hdr.Circuit,
		in:       from,
		hopIndex: index,
		done:     make(chan struct{}),
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
		return errDuplicate
	}
	r.circuits[hdr.Circuit] = c
	r.mu.Unlock()

	if c.isExit {
		return nil
	}
	if err := r.extend(c, layer, index); err != nil {
		r.mu.Lock()
		delete(r.circuits, hdr.Circuit)
		r.mu.Unlock()
		hop.Close()
		return err
	}
	return nil
}

func (r *Relay) extend(c *circuit, layer *wire.SetupLayer, index int) error {
	raw, err := r.dial(layer.NextAddr)
	if err != nil {
		return err
	}
	if !r.hold(raw, false) {
		_ = raw.Close()
		return errFatal
	}
	fail := func(err error) error {
		_ = raw.Close()
		r.drop(raw)
		return err
	}

	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	// the relay does not know the next node's long-term key, so the link to it
	// is anonymous: it hides headers from a passive observer, the onion layers
	// keep the content bound to the nodes the client chose
	conn, err := link.Dial(raw, r.cfg.Provider, nil)
	if err != nil {
		return fail(err)
	}
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
	go r.backward(c)
	return nil
}

func (r *Relay) dial(addr string) (net.Conn, error) {
	if r.cfg.Dial != nil {
		return r.cfg.Dial("tcp", addr)
	}
	d := r.cfg.Dialer
	if d.Timeout == 0 {
		d.Timeout = handshakeTimeout
	}
	return d.DialContext(r.ctx, "tcp", addr)
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
