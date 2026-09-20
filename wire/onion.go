package wire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
)

const lengthPrefix = 2

// client side of a chain: one AEAD per hop, ordered from the first hop to the
// exit
type Circuit struct {
	provider jcrypto.CryptoProvider
	hops     []jcrypto.AEAD
	links    []uint64
	overhead int
}

// keys and links are ordered from the first hop to the exit; links[i] is the
// circuit identifier on the channel into hop i, which is what its nonce is
// built from
func NewCircuit(p jcrypto.CryptoProvider, keys []*secmem.Buffer, links []uint64) (*Circuit, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("wire: circuit needs at least one hop")
	}
	if len(links) != len(keys) {
		return nil, fmt.Errorf("wire: %d keys against %d links", len(keys), len(links))
	}
	c := &Circuit{provider: p, hops: make([]jcrypto.AEAD, 0, len(keys)), links: links}
	for i, k := range keys {
		a, err := p.NewAEAD(k)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("wire: hop %d: %w", i, err)
		}
		if c.overhead == 0 {
			c.overhead = a.Overhead()
		} else if a.Overhead() != c.overhead {
			c.Close()
			return nil, fmt.Errorf("wire: hops disagree on overhead")
		}
		c.hops = append(c.hops, a)
	}
	return c, nil
}

func (c *Circuit) Hops() int { return len(c.hops) }

// each layer costs one authentication tag, so a longer chain carries less
func (c *Circuit) MaxPayload() int {
	return BodySize - len(c.hops)*c.overhead - lengthPrefix
}

func (c *Circuit) Close() {
	for _, a := range c.hops {
		if a != nil {
			a.Destroy()
		}
	}
	c.hops = nil
}

// a cover cell is built the same way with an empty payload, so the two are
// indistinguishable once encrypted
func (c *Circuit) Seal(kind Kind, counter uint64, payload []byte) (*Cell, error) {
	if len(c.hops) == 0 {
		return nil, fmt.Errorf("wire: circuit closed")
	}
	if len(payload) > c.MaxPayload() {
		return nil, fmt.Errorf("%w: %d > %d", ErrPayloadSize, len(payload), c.MaxPayload())
	}

	// random padding to the full width the layers leave, so the wire length
	// never depends on the message
	inner := make([]byte, BodySize-len(c.hops)*c.overhead)
	binary.BigEndian.PutUint16(inner[:lengthPrefix], uint16(len(payload)))
	copy(inner[lengthPrefix:], payload)
	if _, err := io.ReadFull(rand.Reader, inner[lengthPrefix+len(payload):]); err != nil {
		return nil, fmt.Errorf("wire: pad: %w", err)
	}

	cell, err := NewCell(Header{Kind: kind, Circuit: c.links[0], Counter: counter}, make([]byte, BodySize))
	if err != nil {
		return nil, err
	}

	// wrap from the exit inwards, so the first hop strips the outermost layer
	body := inner
	for i := len(c.hops) - 1; i >= 0; i-- {
		nonce, err := nonceFor(c.hops[i].NonceSize(), Forward, c.links[i], counter)
		if err != nil {
			return nil, err
		}
		body = c.hops[i].Seal(nil, nonce, body, cell.aad(i))
	}
	if len(body) != BodySize {
		return nil, fmt.Errorf("wire: sealed body %d, want %d", len(body), BodySize)
	}
	copy(cell.Body(), body)
	return cell, nil
}

// strips every layer at once, for the client side of the return path
func (c *Circuit) OpenExit(cell *Cell, dir Direction) ([]byte, error) {
	h, err := cell.Header()
	if err != nil {
		return nil, err
	}
	body := append([]byte(nil), cell.Body()...)
	for i := 0; i < len(c.hops); i++ {
		nonce, err := nonceFor(c.hops[i].NonceSize(), dir, c.links[i], h.Counter)
		if err != nil {
			return nil, err
		}
		body, err = c.hops[i].Open(nil, nonce, body[:layerLen(i, c.overhead)], cell.aad(i))
		if err != nil {
			return nil, err
		}
	}
	return unframe(body)
}

// the meaningful part shrinks by one tag per hop already stripped; the rest of
// the body is padding that keeps the cell the same size on every link
func layerLen(index, overhead int) int {
	return BodySize - index*overhead
}

// relay side: one key, one layer
type Hop struct {
	aead     jcrypto.AEAD
	index    int
	overhead int
}

// index must match the position the client used, or the associated data will
// not verify
func NewHop(p jcrypto.CryptoProvider, key *secmem.Buffer, index int) (*Hop, error) {
	if index < 0 {
		return nil, fmt.Errorf("wire: negative hop index")
	}
	a, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if layerLen(index, a.Overhead()) <= a.Overhead() {
		return nil, fmt.Errorf("wire: hop index %d leaves no room in a cell", index)
	}
	return &Hop{aead: a, index: index, overhead: a.Overhead()}, nil
}

func (h *Hop) Close() {
	if h.aead != nil {
		h.aead.Destroy()
		h.aead = nil
	}
}

// refills with random bytes so the cell that leaves is the size of the cell that
// arrived; without it the position in the chain would be visible on the wire
func (h *Hop) Peel(cell *Cell, dir Direction) (*Cell, error) {
	if h.aead == nil {
		return nil, fmt.Errorf("wire: hop closed")
	}
	hdr, err := cell.Header()
	if err != nil {
		return nil, err
	}
	nonce, err := nonceFor(h.aead.NonceSize(), dir, hdr.Circuit, hdr.Counter)
	if err != nil {
		return nil, err
	}
	// only the prefix belongs to this layer; the tail is padding from earlier hops
	inner, err := h.aead.Open(nil, nonce, cell.Body()[:layerLen(h.index, h.overhead)], cell.aad(h.index))
	if err != nil {
		return nil, err
	}

	body := make([]byte, BodySize)
	copy(body, inner)
	if _, err := io.ReadFull(rand.Reader, body[len(inner):]); err != nil {
		return nil, fmt.Errorf("wire: refill: %w", err)
	}
	return NewCell(hdr, body)
}

func (h *Hop) OpenLast(cell *Cell, dir Direction) ([]byte, error) {
	peeled, err := h.Peel(cell, dir)
	if err != nil {
		return nil, err
	}
	// the refill bytes at the tail are not plaintext: the length prefix says
	// where the real data ends
	return unframe(peeled.Body())
}

func unframe(inner []byte) ([]byte, error) {
	if len(inner) < lengthPrefix {
		return nil, ErrFraming
	}
	n := int(binary.BigEndian.Uint16(inner[:lengthPrefix]))
	if n > len(inner)-lengthPrefix {
		return nil, fmt.Errorf("%w: length %d", ErrFraming, n)
	}
	out := make([]byte, n)
	copy(out, inner[lengthPrefix:lengthPrefix+n])
	return out, nil
}
