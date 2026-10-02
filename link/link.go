// Package link encrypts the channel between neighbours, so an observer on the
// wire sees only frames of one size and none of the cell headers.
package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	exchangeLink = "link"

	purposeI2R = "link/i2r"
	purposeR2I = "link/r2i"

	// the initiator has the responder's long-term key only where it comes from a
	// verified descriptor
	modeAnonymous     = 0
	modeAuthenticated = 1
)

var ErrHandshake = errors.New("link: handshake failed")

type Conn struct {
	raw   net.Conn
	send  jcrypto.AEAD
	recv  jcrypto.AEAD
	frame int

	wmu          sync.Mutex
	sendSeq      uint64
	writeTimeout time.Duration
	// a frame cut short leaves the peer's stream out of step, so after one
	// failed write the link carries nothing more
	werr    error
	rmu     sync.Mutex
	recvSeq uint64
	buf     []byte
}

// the provider has no size query, so a key pair is made once per suite and
// the length remembered; a GOST key pair per accepted link would be wasted work
var pubSizes sync.Map

func pubSize(p jcrypto.CryptoProvider) (int, error) {
	if n, ok := pubSizes.Load(p.Suite()); ok {
		return n.(int), nil
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		return 0, err
	}
	priv.Release()
	pubSizes.Store(p.Suite(), len(pub))
	return len(pub), nil
}

// bytes the initiator writes before the first frame, which an observer counts
// as part of the connection and the testbed has to skip
func InitiatorHandshakeSize(p jcrypto.CryptoProvider) (int, error) {
	n, err := pubSize(p)
	return n + 1, err
}

// the responder answers with its public key, without the mode byte, and one
// frame that confirms the keys
func ResponderHandshakeSize(p jcrypto.CryptoProvider) (int, error) {
	n, err := pubSize(p)
	if err != nil {
		return 0, err
	}
	frame, err := FrameSize(p)
	return n + frame, err
}

// FrameSize is what one cell costs on the wire once the link layer wraps it
func FrameSize(p jcrypto.CryptoProvider) (int, error) {
	probe, err := secmem.New(p.KeySize())
	if err != nil {
		return 0, err
	}
	defer probe.Release()
	a, err := p.NewAEAD(probe)
	if err != nil {
		return 0, err
	}
	defer a.Destroy()
	return wire.CellSize + a.Overhead(), nil
}

// peerStatic authenticates the responder when the initiator knows its key; nil
// gives an anonymous channel that still hides everything from a passive observer.
// Dial returns only after the responder's first frame opened under the keys
// derived here, so nothing is sent to a responder that derived other keys; the
// caller's deadline on raw bounds the wait
func Dial(raw net.Conn, p jcrypto.CryptoProvider, peerStatic []byte) (*Conn, error) {
	ephPriv, ephPub, err := p.GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	defer ephPriv.Release()

	mode := byte(modeAnonymous)
	if peerStatic != nil {
		if len(peerStatic) != len(ephPub) {
			return nil, fmt.Errorf("%w: %w", ErrHandshake, jcrypto.ErrBadPublicKey)
		}
		mode = modeAuthenticated
	}
	hello := append([]byte{mode}, ephPub...)
	if _, err := raw.Write(hello); err != nil {
		return nil, err
	}

	peerEph := make([]byte, len(ephPub))
	if _, err := io.ReadFull(raw, peerEph); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	ctx, err := handshakeContext(p, mode, ephPub, peerEph, peerStatic)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	secret, err := chainKey(p, ctx, mode, ephPriv, peerStatic, ephPriv, peerEph)
	if err != nil {
		return nil, err
	}
	defer secret.Release()
	c, err := newConn(raw, p, secret, ctx, purposeI2R, purposeR2I)
	if err != nil {
		return nil, err
	}
	var first wire.Cell
	if err := c.readFrame(&first); err != nil {
		c.discard()
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if !first.IsPadding() {
		c.discard()
		return nil, ErrHandshake
	}
	return c, nil
}

// staticPub is the link key as the responder published it: an initiator in the
// authenticated mode put the same bytes into the transcript. A responder
// without a link key takes anonymous links only
func Accept(raw net.Conn, p jcrypto.CryptoProvider, staticPriv *secmem.Buffer, staticPub []byte) (*Conn, error) {
	n, err := pubSize(p)
	if err != nil {
		return nil, err
	}
	hello := make([]byte, n+1)
	if _, err := io.ReadFull(raw, hello); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	mode, peerEph := hello[0], hello[1:]
	switch mode {
	case modeAnonymous:
		staticPriv, staticPub = nil, nil
	case modeAuthenticated:
		if staticPriv == nil || len(staticPub) != n {
			return nil, ErrHandshake
		}
	default:
		return nil, ErrHandshake
	}

	ephPriv, ephPub, err := p.GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	defer ephPriv.Release()
	if _, err := raw.Write(ephPub); err != nil {
		return nil, err
	}

	ctx, err := handshakeContext(p, mode, peerEph, ephPub, staticPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	secret, err := chainKey(p, ctx, mode, staticPriv, peerEph, ephPriv, peerEph)
	if err != nil {
		return nil, err
	}
	defer secret.Release()
	c, err := newConn(raw, p, secret, ctx, purposeR2I, purposeI2R)
	if err != nil {
		return nil, err
	}
	// the confirmation: a padding cell as frame 0 of this direction, written in
	// both modes so that what a responder sends does not depend on the mode
	if err := c.WriteCell(wire.NewPadding()); err != nil {
		c.discard()
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return c, nil
}

// version, mode, both ephemeral keys as they crossed the wire and, in the
// authenticated mode, the responder's link key
func handshakeContext(p jcrypto.CryptoProvider, mode byte, initiatorEph, responderEph, responderStatic []byte) (jcrypto.Context, error) {
	parts := [][]byte{{wire.Version}, {mode}, initiatorEph, responderEph}
	if mode == modeAuthenticated {
		parts = append(parts, responderStatic)
	}
	return jcrypto.NewContext(p, exchangeLink, parts...)
}

// the ephemeral secret gives forward secrecy, the static one binds the channel
// to the node the initiator chose; chained, so neither alone gives the frame
// keys. esPriv and esPeer are this side's halves of the agreement that involves
// the responder's link key: the initiator brings its ephemeral key to it, the
// responder its link key
func chainKey(p jcrypto.CryptoProvider, ctx jcrypto.Context, mode byte, esPriv *secmem.Buffer, esPeer []byte, ephPriv *secmem.Buffer, ephPeer []byte) (*secmem.Buffer, error) {
	if mode != modeAuthenticated {
		ee, err := p.Agree(ephPriv, ephPeer, ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
		}
		return ee, nil
	}
	es, err := p.Agree(esPriv, esPeer, ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	defer es.Release()
	ee, err := p.Agree(ephPriv, ephPeer, ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	defer ee.Release()
	return p.MixKey(es, ee, ctx)
}

func newConn(raw net.Conn, p jcrypto.CryptoProvider, secret *secmem.Buffer, ctx jcrypto.Context, sendPurpose, recvPurpose string) (*Conn, error) {
	sendKey, err := p.DeriveKey(secret, sendPurpose, ctx, p.KeySize())
	if err != nil {
		return nil, err
	}
	defer sendKey.Release()
	recvKey, err := p.DeriveKey(secret, recvPurpose, ctx, p.KeySize())
	if err != nil {
		return nil, err
	}
	defer recvKey.Release()

	send, err := p.NewAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := p.NewAEAD(recvKey)
	if err != nil {
		send.Destroy()
		return nil, err
	}
	frame := wire.CellSize + send.Overhead()
	return &Conn{raw: raw, send: send, recv: recv, frame: frame, buf: make([]byte, frame)}, nil
}

// a key serves one direction of one connection, so the frame number alone makes
// every nonce unique
func nonce(size int, seq uint64) []byte {
	n := make([]byte, size)
	binary.BigEndian.PutUint64(n[size-8:], seq)
	return n
}

// every later frame must leave within d or its write fails; zero waits forever
func (c *Conn) SetWriteTimeout(d time.Duration) {
	c.wmu.Lock()
	c.writeTimeout = d
	c.wmu.Unlock()
}

func (c *Conn) WriteCell(cell *wire.Cell) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return c.werr
	}
	if c.send == nil {
		return net.ErrClosed
	}
	frame := c.send.Seal(nil, nonce(c.send.NonceSize(), c.sendSeq), cell[:], nil)
	c.sendSeq++
	if c.writeTimeout > 0 {
		if err := c.raw.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			c.werr = err
			return err
		}
	}
	if _, err := c.raw.Write(frame); err != nil {
		c.werr = err
		return err
	}
	return nil
}

// padding is a property of this link only, so it never reaches the caller
func (c *Conn) ReadCell(cell *wire.Cell) error {
	for {
		if err := c.readFrame(cell); err != nil {
			return err
		}
		if !cell.IsPadding() {
			return nil
		}
	}
}

func (c *Conn) readFrame(cell *wire.Cell) error {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if _, err := io.ReadFull(c.raw, c.buf); err != nil {
		return err
	}
	if c.recv == nil {
		return net.ErrClosed
	}
	plain, err := c.recv.Open(nil, nonce(c.recv.NonceSize(), c.recvSeq), c.buf, nil)
	if err != nil {
		return err
	}
	c.recvSeq++
	copy(cell[:], plain)
	return nil
}

func (c *Conn) FrameSize() int { return c.frame }

// the socket closes first: a reader blocked on it holds rmu until it returns
func (c *Conn) Close() error {
	err := c.raw.Close()
	c.discard()
	return err
}

func (c *Conn) discard() {
	c.wmu.Lock()
	if c.send != nil {
		c.send.Destroy()
		c.send = nil
	}
	c.wmu.Unlock()
	c.rmu.Lock()
	if c.recv != nil {
		c.recv.Destroy()
		c.recv = nil
	}
	c.rmu.Unlock()
}
