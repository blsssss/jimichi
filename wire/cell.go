// Package wire is the on-the-wire format: fixed-size cells carrying nested
// encryption layers.
package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// changing this changes what an observer can measure, so it is a protocol
	// constant and not a tunable
	CellSize = 512

	headerSize = 18
	BodySize   = CellSize - headerSize

	Version = 1
)

// travels in clear text because a relay routes a cell before it can open it
type Kind uint8

const (
	KindPayload Kind = 1
	KindCover   Kind = 2 // carries nothing, exists to hide when payload flows
	KindControl Kind = 3
	// never enters a circuit: the receiving end of a link drops it
	KindPadding Kind = 4
)

func (k Kind) String() string {
	switch k {
	case KindPayload:
		return "payload"
	case KindCover:
		return "cover"
	case KindControl:
		return "control"
	case KindPadding:
		return "padding"
	default:
		return "unknown"
	}
}

func (k Kind) valid() bool {
	return k == KindPayload || k == KindCover || k == KindControl || k == KindPadding
}

var (
	ErrCellSize    = errors.New("wire: wrong cell size")
	ErrVersion     = errors.New("wire: unsupported version")
	ErrKind        = errors.New("wire: unknown cell kind")
	ErrPayloadSize = errors.New("wire: payload too large")
	ErrFraming     = errors.New("wire: bad framing")
)

// Circuit changes on every link, so two observers cannot match a flow by the
// identifier alone
type Header struct {
	Version uint8
	Kind    Kind
	Circuit uint64
	Counter uint64
}

// an array and not a slice, so a cell is always exactly CellSize bytes
type Cell [CellSize]byte

// body must be exactly BodySize: a shorter cell would be observable
func NewCell(h Header, body []byte) (*Cell, error) {
	if len(body) != BodySize {
		return nil, fmt.Errorf("%w: body %d, want %d", ErrCellSize, len(body), BodySize)
	}
	if !h.Kind.valid() {
		return nil, ErrKind
	}
	var c Cell
	c[0] = Version
	c[1] = byte(h.Kind)
	binary.BigEndian.PutUint64(c[2:10], h.Circuit)
	binary.BigEndian.PutUint64(c[10:18], h.Counter)
	copy(c[headerSize:], body)
	return &c, nil
}

func (c *Cell) Header() (Header, error) {
	if c[0] != Version {
		return Header{}, fmt.Errorf("%w: %d", ErrVersion, c[0])
	}
	k := Kind(c[1])
	if !k.valid() {
		return Header{}, fmt.Errorf("%w: %d", ErrKind, c[1])
	}
	return Header{
		Version: c[0],
		Kind:    k,
		Circuit: binary.BigEndian.Uint64(c[2:10]),
		Counter: binary.BigEndian.Uint64(c[10:18]),
	}, nil
}

func (c *Cell) Body() []byte { return c[headerSize:] }

// the body is random so a padding frame carries nothing a relay could tell apart
// from a real cell, even inside the link encryption
func NewPadding() (*Cell, error) {
	body := make([]byte, BodySize)
	if _, err := io.ReadFull(rand.Reader, body); err != nil {
		return nil, err
	}
	return NewCell(Header{Kind: KindPadding}, body)
}

func (c *Cell) IsPadding() bool { return c[0] == Version && Kind(c[1]) == KindPadding }

// authenticated fields are the ones that stay the same end to end, plus the hop
// index; the circuit identifier is excluded because every link rewrites it
func (c *Cell) aad(hop int) []byte {
	ad := make([]byte, 0, 11)
	ad = append(ad, c[0], c[1])
	ad = append(ad, c[10:18]...)
	return append(ad, byte(hop))
}

func (c *Cell) SetCircuit(id uint64) {
	binary.BigEndian.PutUint64(c[2:10], id)
}
