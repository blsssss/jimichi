// Package relay is the forwarding node: it peels one layer and passes the cell
// on, keeping nothing on disk.
package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
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

	mu       sync.Mutex
	circuits map[uint64]*circuit
	conns    map[net.Conn]struct{}
	closed   bool

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
	next     net.Conn
	in       net.Conn
	nextID   uint64
	isExit   bool
	writeMu  sync.Mutex
	inMu     sync.Mutex
	inbound  uint64
	hopIndex int
	replies  uint64
}

func New(cfg Config) (*Relay, error) {
	if cfg.Provider == nil {
		return nil, errors.New("relay: no provider")
	}
	if cfg.StaticPriv == nil {
		return nil, errors.New("relay: no static key")
	}
	return &Relay{
		cfg:      cfg,
		circuits: make(map[uint64]*circuit),
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

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
		r.track(conn)
		go r.handle(conn)
	}
}

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
	circuits := r.circuits
	r.circuits = make(map[uint64]*circuit)
	r.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	for _, c := range circuits {
		c.hop.Close()
		if c.next != nil {
			_ = c.next.Close()
		}
	}
}

func (r *Relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *Relay) track(conn net.Conn) {
	r.mu.Lock()
	r.conns[conn] = struct{}{}
	r.mu.Unlock()
}

func (r *Relay) handle(conn net.Conn) {
	defer func() {
		r.mu.Lock()
		delete(r.conns, conn)
		r.mu.Unlock()
		_ = conn.Close()
	}()

	for {
		var cell wire.Cell
		if _, err := io.ReadFull(conn, cell[:]); err != nil {
			return
		}
		if err := r.route(&cell, conn); err != nil {
			r.stats.add(&r.stats.Dropped)
			if errors.Is(err, errFatal) {
				return
			}
		}
	}
}

var errFatal = errors.New("relay: connection unusable")

func (r *Relay) route(cell *wire.Cell, from net.Conn) error {
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
	if c == nil {
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

// cells coming from the next hop travel towards the client, so this relay adds
// its own layer instead of stripping one
func (r *Relay) backward(c *circuit) {
	for {
		var cell wire.Cell
		if _, err := io.ReadFull(c.next, cell[:]); err != nil {
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

func (r *Relay) setup(cell *wire.Cell, hdr wire.Header, from net.Conn) error {
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
	}

	if !c.isExit {
		conn, err := r.dial(layer.NextAddr)
		if err != nil {
			hop.Close()
			return err
		}
		c.next = conn
		fwd, err := wire.ForwardSetup(layer, index)
		if err != nil {
			hop.Close()
			_ = conn.Close()
			return err
		}
		if err := c.write(fwd); err != nil {
			hop.Close()
			_ = conn.Close()
			return err
		}
		go r.backward(c)
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		hop.Close()
		return errFatal
	}
	r.circuits[hdr.Circuit] = c
	r.mu.Unlock()
	return nil
}

func (r *Relay) dial(addr string) (net.Conn, error) {
	if r.cfg.Dial != nil {
		return r.cfg.Dial("tcp", addr)
	}
	return r.cfg.Dialer.Dial("tcp", addr)
}

func (c *circuit) write(cell *wire.Cell) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.next.Write(cell[:])
	return err
}

func (c *circuit) writeBack(cell *wire.Cell) error {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	_, err := c.in.Write(cell[:])
	return err
}
