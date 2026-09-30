package wire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	lengthPrefix = 2
	// the top bit of the length marks cover; no payload comes near 32 KiB
	coverFlag = 0x8000
)

// client side of a chain: one AEAD per hop, ordered from the first hop to the
// exit
type Circuit struct {
	provider jcrypto.CryptoProvider
	hops     []jcrypto.AEAD
	links    []uint64
	// before[i] sums, per direction, the offsets of the hops between the client
	// and hop i
	before   []Offsets
	total    Offsets
	overhead int
}

// keys, offsets and links are ordered from the first hop to the exit; links[i]
// is the circuit identifier on the channel into hop i, which is what its nonce
// is built from
func NewCircuit(p jcrypto.CryptoProvider, keys []*secmem.Buffer, offsets []Offsets, links []uint64) (*Circuit, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("wire: circuit needs at least one hop")
	}
	if len(links) != len(keys) || len(offsets) != len(keys) {
		return nil, fmt.Errorf("wire: %d keys against %d offsets and %d links", len(keys), len(offsets), len(links))
	}
	c := &Circuit{provider: p, hops: make([]jcrypto.AEAD, 0, len(keys)), links: links, before: make([]Offsets, len(keys))}
	var sum Offsets
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
		c.before[i] = sum
		sum = Offsets{shift(sum[Forward], offsets[i][Forward]), shift(sum[Backward], offsets[i][Backward])}
	}
	c.total = sum
	return c, nil
}

// the counter on the link into hop i, which its layer is bound to, from the one
// on the client's own link: every hop a cell leaves adds its offset
func (c *Circuit) valueAt(i int, dir Direction, first uint64) uint64 {
	if dir == Forward {
		return shift(first, c.before[i][Forward])
	}
	return unshift(first, c.before[i][Backward])
}

// the exit's own number of a reply that reached the client with this counter
func (c *Circuit) ReplyNumber(counter uint64) uint64 {
	return unshift(counter, c.total[Backward])
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

func (c *Circuit) Seal(counter uint64, payload []byte) (*Cell, error) {
	return c.seal(counter, payload, false)
}

// a cover cell goes through the same layers with the same header, so no relay
// on the way can tell it from a payload cell; only the exit reads the flag
func (c *Circuit) SealCover(counter uint64) (*Cell, error) {
	return c.seal(counter, nil, true)
}

func (c *Circuit) seal(counter uint64, payload []byte, cover bool) (*Cell, error) {
	if len(c.hops) == 0 {
		return nil, fmt.Errorf("wire: circuit closed")
	}
	if len(payload) > c.MaxPayload() {
		return nil, fmt.Errorf("%w: %d > %d", ErrPayloadSize, len(payload), c.MaxPayload())
	}
	if counter >= cellLimit {
		return nil, fmt.Errorf("wire: counter exhausted")
	}

	// random padding to the full width the layers leave, so the wire length
	// never depends on the message
	inner := make([]byte, BodySize-len(c.hops)*c.overhead)
	if err := frame(inner, payload, cover); err != nil {
		return nil, err
	}

	cell, err := NewCell(Header{Kind: KindData, Circuit: c.links[0], Counter: counter}, make([]byte, BodySize))
	if err != nil {
		return nil, err
	}

	// wrap from the exit inwards, so the first hop strips the outermost layer
	body := inner
	for i := len(c.hops) - 1; i >= 0; i-- {
		value := c.valueAt(i, Forward, counter)
		nonce, err := nonceFor(c.hops[i].NonceSize(), Forward, c.links[i], value)
		if err != nil {
			return nil, err
		}
		body = c.hops[i].Seal(nil, nonce, body, cell.aad(value, i))
	}
	if len(body) != BodySize {
		return nil, fmt.Errorf("wire: sealed body %d, want %d", len(body), BodySize)
	}
	copy(cell.Body(), body)
	return cell, nil
}

// strips every layer at once, for the client side of the return path
func (c *Circuit) OpenExit(cell *Cell, dir Direction) (payload []byte, cover bool, err error) {
	h, err := cell.Header()
	if err != nil {
		return nil, false, err
	}
	if h.Counter >= counterLimit {
		return nil, false, fmt.Errorf("wire: counter exhausted")
	}
	body := append([]byte(nil), cell.Body()...)
	for i := 0; i < len(c.hops); i++ {
		value := c.valueAt(i, dir, h.Counter)
		nonce, err := nonceFor(c.hops[i].NonceSize(), dir, c.links[i], value)
		if err != nil {
			return nil, false, err
		}
		body, err = c.hops[i].Open(nil, nonce, body[:layerLen(i, c.overhead)], cell.aad(value, i))
		if err != nil {
			return nil, false, err
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
	offset   Offsets
}

// index must match the position the client used, or the associated data will
// not verify
func NewHop(p jcrypto.CryptoProvider, key *secmem.Buffer, off Offsets, index int) (*Hop, error) {
	if index < 0 || index >= MaxHops {
		return nil, fmt.Errorf("wire: hop index %d outside 0..%d", index, MaxHops-1)
	}
	a, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if layerLen(index, a.Overhead()) <= a.Overhead() {
		return nil, fmt.Errorf("wire: hop index %d leaves no room in a cell", index)
	}
	return &Hop{aead: a, index: index, overhead: a.Overhead(), offset: off}, nil
}

func (h *Hop) Close() {
	if h.aead != nil {
		h.aead.Destroy()
		h.aead = nil
	}
}

// refills with random bytes so the cell that leaves is the size of the cell that
// arrived; without it the position in the chain would be visible on the wire.
// The cell leaves with the counter of the next link, this hop's offset added
func (h *Hop) Peel(cell *Cell) (*Cell, error) {
	if h.aead == nil {
		return nil, fmt.Errorf("wire: hop closed")
	}
	hdr, err := cell.Header()
	if err != nil {
		return nil, err
	}
	nonce, err := nonceFor(h.aead.NonceSize(), Forward, hdr.Circuit, hdr.Counter)
	if err != nil {
		return nil, err
	}
	// only the prefix belongs to this layer; the tail is padding from earlier hops
	inner, err := h.aead.Open(nil, nonce, cell.Body()[:layerLen(h.index, h.overhead)], cell.aad(hdr.Counter, h.index))
	if err != nil {
		return nil, err
	}

	body := make([]byte, BodySize)
	copy(body, inner)
	if _, err := io.ReadFull(rand.Reader, body[len(inner):]); err != nil {
		return nil, fmt.Errorf("wire: refill: %w", err)
	}
	hdr.Counter = shift(hdr.Counter, h.offset[Forward])
	return NewCell(hdr, body)
}

// cover tells the exit the cell carried nothing; no earlier hop could see that
func (h *Hop) OpenLast(cell *Cell) (payload []byte, cover bool, err error) {
	peeled, err := h.Peel(cell)
	if err != nil {
		return nil, false, err
	}
	// the refill bytes at the tail are not plaintext: the length prefix says
	// where the real data ends
	return unframe(peeled.Body())
}

// length prefix, data, random fill up to the width the layers leave, so the
// wire length never depends on the message
func frame(inner, payload []byte, cover bool) error {
	if len(payload)+lengthPrefix > len(inner) || len(payload) >= coverFlag {
		return fmt.Errorf("%w: %d > %d", ErrPayloadSize, len(payload), len(inner)-lengthPrefix)
	}
	n := uint16(len(payload))
	if cover {
		n |= coverFlag
	}
	binary.BigEndian.PutUint16(inner[:lengthPrefix], n)
	copy(inner[lengthPrefix:], payload)
	if _, err := io.ReadFull(rand.Reader, inner[lengthPrefix+len(payload):]); err != nil {
		return fmt.Errorf("wire: pad: %w", err)
	}
	return nil
}

func unframe(inner []byte) (payload []byte, cover bool, err error) {
	if len(inner) < lengthPrefix {
		return nil, false, ErrFraming
	}
	v := binary.BigEndian.Uint16(inner[:lengthPrefix])
	cover = v&coverFlag != 0
	n := int(v &^ coverFlag)
	if n > len(inner)-lengthPrefix || (cover && n != 0) {
		return nil, false, fmt.Errorf("%w: length %d", ErrFraming, n)
	}
	out := make([]byte, n)
	copy(out, inner[lengthPrefix:lengthPrefix+n])
	return out, cover, nil
}

// exit builds the first backward layer; the reply travels the chain in reverse,
// every relay adding its own layer instead of stripping one
func (h *Hop) SealReply(inboundCircuit, counter uint64, payload []byte) (*Cell, error) {
	return h.sealReply(inboundCircuit, counter, payload, false)
}

// the exit answers every data cell, cover included, so the replies a node sees
// on the way back say nothing about which cells carried a message
func (h *Hop) SealCoverReply(inboundCircuit, counter uint64) (*Cell, error) {
	return h.sealReply(inboundCircuit, counter, nil, true)
}

func (h *Hop) sealReply(inboundCircuit, counter uint64, payload []byte, cover bool) (*Cell, error) {
	if h.aead == nil {
		return nil, fmt.Errorf("wire: hop closed")
	}
	if counter >= cellLimit {
		return nil, fmt.Errorf("wire: counter exhausted")
	}
	inner := make([]byte, layerLen(h.index, h.overhead)-h.overhead)
	if err := frame(inner, payload, cover); err != nil {
		return nil, err
	}
	return h.seal(Header{Kind: KindData, Circuit: inboundCircuit, Counter: shift(counter, h.offset[Backward])}, inner)
}

// adds this hop's layer to a cell travelling back towards the client
func (h *Hop) Wrap(cell *Cell, inboundCircuit uint64) (*Cell, error) {
	if h.aead == nil {
		return nil, fmt.Errorf("wire: hop closed")
	}
	hdr, err := cell.Header()
	if err != nil {
		return nil, err
	}
	if hdr.Kind != KindData {
		return nil, fmt.Errorf("%w: %s on the way back", ErrKind, hdr.Kind)
	}
	// a value past the limit would wrap onto one already used under this key
	if hdr.Counter >= counterLimit {
		return nil, fmt.Errorf("wire: counter exhausted")
	}
	return h.seal(Header{Kind: KindData, Circuit: inboundCircuit, Counter: shift(hdr.Counter, h.offset[Backward])}, cell.Body()[:layerLen(h.index+1, h.overhead)])
}

// one backward layer under this hop's key, bound to the counter of the link the
// cell leaves on
func (h *Hop) seal(hdr Header, inner []byte) (*Cell, error) {
	out, err := NewCell(hdr, make([]byte, BodySize))
	if err != nil {
		return nil, err
	}
	nonce, err := nonceFor(h.aead.NonceSize(), Backward, hdr.Circuit, hdr.Counter)
	if err != nil {
		return nil, err
	}
	sealed := h.aead.Seal(nil, nonce, inner, out.aad(hdr.Counter, h.index))
	copy(out.Body(), sealed)
	if _, err := io.ReadFull(rand.Reader, out.Body()[len(sealed):]); err != nil {
		return nil, err
	}
	return out, nil
}
