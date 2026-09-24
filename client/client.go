// Package client builds a circuit, sends payload and cover cells through it and
// keeps no state on disk.
package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/wire"
)

// what the client knows about a relay before it builds a circuit
type Node struct {
	Addr      string
	StaticPub []byte
}

type Mode uint8

const (
	// a cell leaves as soon as there is something to send, and cover cells are
	// added on top; the send pattern still follows the conversation
	Immediate Mode = iota
	// cells leave on a fixed schedule and a payload takes the slot of a cover
	// cell, so the pattern on the link does not depend on the conversation
	ConstantRate
)

// Mode, Rate and Jitter are the knobs the experiments sweep
type Config struct {
	Provider  jcrypto.CryptoProvider
	Chain     []Node
	Mode      Mode
	Rate      time.Duration
	CoverRate time.Duration
	Jitter    time.Duration
	// lets the testbed observe the entry link the way a passive network
	// adversary would; nil means a plain dial
	Dial func(network, addr string) (net.Conn, error)
}

type Client struct {
	cfg     Config
	conn    *link.Conn
	circuit *wire.Circuit
	keys    []*secmem.Buffer
	replies chan []byte
	queue   chan []byte
	dropped uint64

	mu      sync.Mutex
	counter uint64
	closed  bool

	stopCover chan struct{}
	coverDone sync.WaitGroup
}

func Dial(cfg Config) (*Client, error) {
	if cfg.Provider == nil {
		return nil, errors.New("client: no provider")
	}
	if len(cfg.Chain) == 0 {
		return nil, errors.New("client: empty chain")
	}

	links := make([]uint64, len(cfg.Chain))
	for i := range links {
		id, err := randomCircuitID()
		if err != nil {
			return nil, err
		}
		links[i] = id
	}

	chain := make([]wire.SetupHop, len(cfg.Chain))
	for i, node := range cfg.Chain {
		hop := wire.SetupHop{StaticPub: node.StaticPub, Link: links[i]}
		if i+1 < len(cfg.Chain) {
			hop.NextAddr = cfg.Chain[i+1].Addr
			hop.NextCircuit = links[i+1]
		}
		chain[i] = hop
	}

	setup, err := wire.BuildSetup(cfg.Provider, chain)
	if err != nil {
		return nil, err
	}
	release := func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}

	circuit, err := wire.NewCircuit(cfg.Provider, setup.CellKeys, links)
	if err != nil {
		release()
		return nil, err
	}

	dial := cfg.Dial
	if dial == nil {
		dial = net.Dial
	}
	raw, err := dial("tcp", cfg.Chain[0].Addr)
	if err != nil {
		circuit.Close()
		release()
		return nil, err
	}
	conn, err := link.Dial(raw, cfg.Provider, cfg.Chain[0].StaticPub)
	if err != nil {
		circuit.Close()
		release()
		_ = raw.Close()
		return nil, err
	}
	if err := conn.WriteCell(setup.Cell); err != nil {
		circuit.Close()
		release()
		_ = conn.Close()
		return nil, err
	}

	c := &Client{
		cfg:     cfg,
		conn:    conn,
		circuit: circuit,
		keys:    setup.CellKeys,
		replies: make(chan []byte, 64),
		queue:   make(chan []byte, 256),
	}
	go c.receive()
	switch {
	case cfg.Mode == ConstantRate && cfg.Rate > 0:
		c.startSchedule()
	case cfg.CoverRate > 0:
		c.startCover()
	}
	return c, nil
}

func (c *Client) MaxPayload() int { return c.circuit.MaxPayload() }

// replies arrive wrapped in one layer per hop, in the reverse order
func (c *Client) Replies() <-chan []byte { return c.replies }

func (c *Client) receive() {
	defer close(c.replies)
	for {
		var cell wire.Cell
		if err := c.conn.ReadCell(&cell); err != nil {
			return
		}
		payload, err := c.circuit.OpenExit(&cell, wire.Backward)
		if err != nil {
			continue
		}
		select {
		case c.replies <- payload:
		default:
		}
	}
}

func (c *Client) Send(payload []byte) error {
	if c.cfg.Mode == ConstantRate && c.cfg.Rate > 0 {
		buf := make([]byte, len(payload))
		copy(buf, payload)
		select {
		case c.queue <- buf:
			return nil
		default:
			// the schedule is full: dropping keeps the link pattern constant,
			// which is the property being measured
			c.mu.Lock()
			c.dropped++
			c.mu.Unlock()
			return nil
		}
	}
	return c.send(wire.KindPayload, payload)
}

// how many messages the fixed schedule could not take
func (c *Client) Dropped() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// one cell per tick, payload if the queue has one and cover otherwise
func (c *Client) startSchedule() {
	c.stopCover = make(chan struct{})
	c.coverDone.Add(1)
	go func() {
		defer c.coverDone.Done()
		ticker := time.NewTicker(c.cfg.Rate)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCover:
				return
			case <-ticker.C:
				var err error
				select {
				case payload := <-c.queue:
					err = c.send(wire.KindPayload, payload)
				default:
					err = c.send(wire.KindCover, nil)
				}
				if err != nil {
					return
				}
			}
		}
	}()
}

func (c *Client) SendCover() error {
	return c.send(wire.KindCover, nil)
}

func (c *Client) send(kind wire.Kind, payload []byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("client: closed")
	}
	counter := c.counter
	c.counter++
	c.mu.Unlock()

	cell, err := c.circuit.Seal(kind, counter, payload)
	if err != nil {
		return err
	}
	if err := c.delay(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client: closed")
	}
	return c.conn.WriteCell(cell)
}

// jitter is drawn per cell, so the send pattern does not repeat
func (c *Client) delay() error {
	if c.cfg.Jitter <= 0 {
		return nil
	}
	n, err := randomBelow(int64(c.cfg.Jitter))
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(n))
	return nil
}

func (c *Client) startCover() {
	c.stopCover = make(chan struct{})
	c.coverDone.Add(1)
	go func() {
		defer c.coverDone.Done()
		ticker := time.NewTicker(c.cfg.CoverRate)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCover:
				return
			case <-ticker.C:
				if err := c.SendCover(); err != nil {
					return
				}
			}
		}
	}()
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	if c.stopCover != nil {
		close(c.stopCover)
		c.coverDone.Wait()
	}
	c.circuit.Close()
	for _, k := range c.keys {
		k.Release()
	}
	return c.conn.Close()
}

func randomCircuitID() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, fmt.Errorf("client: random circuit id: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func randomBelow(n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b[:])>>1) % n, nil
}
