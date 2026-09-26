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

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/wire"
)

const (
	labelI2R = "jimichi/link/i2r"
	labelR2I = "jimichi/link/r2i"

	// the initiator knows the responder's long-term key only on the first hop
	modeAnonymous     = 0
	modeAuthenticated = 1
)

var ErrHandshake = errors.New("link: handshake failed")

type Conn struct {
	raw   net.Conn
	send  jcrypto.AEAD
	recv  jcrypto.AEAD
	frame int

	wmu     sync.Mutex
	sendSeq uint64
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

// the responder answers with its public key alone, without the mode byte
func ResponderHandshakeSize(p jcrypto.CryptoProvider) (int, error) {
	return pubSize(p)
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
// gives an anonymous channel that still hides everything from a passive observer
func Dial(raw net.Conn, p jcrypto.CryptoProvider, peerStatic []byte) (*Conn, error) {
	ephPriv, ephPub, err := p.GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	defer ephPriv.Release()

	mode := byte(modeAnonymous)
	if peerStatic != nil {
		mode = modeAuthenticated
	}
	hello := append([]byte{mode}, ephPub...)
	if _, err := raw.Write(hello); err != nil {
		return nil, err
	}

	peerEph := make([]byte, len(ephPub))
	if _, err := io.ReadFull(raw, peerEph); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}

	secret, err := combine(func() (*secmem.Buffer, error) {
		return p.Agree(ephPriv, peerEph, ephPub)
	}, func() (*secmem.Buffer, error) {
		if peerStatic == nil {
			return nil, nil
		}
		return p.Agree(ephPriv, peerStatic, ephPub)
	})
	if err != nil {
		return nil, err
	}
	defer secret.Release()
	return newConn(raw, p, secret, labelI2R, labelR2I)
}

func Accept(raw net.Conn, p jcrypto.CryptoProvider, staticPriv *secmem.Buffer) (*Conn, error) {
	n, err := pubSize(p)
	if err != nil {
		return nil, err
	}
	hello := make([]byte, n+1)
	if _, err := io.ReadFull(raw, hello); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	mode, peerEph := hello[0], hello[1:]
	if mode != modeAnonymous && mode != modeAuthenticated {
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

	secret, err := combine(func() (*secmem.Buffer, error) {
		return p.Agree(ephPriv, peerEph, peerEph)
	}, func() (*secmem.Buffer, error) {
		if mode == modeAnonymous {
			return nil, nil
		}
		return p.Agree(staticPriv, peerEph, peerEph)
	})
	if err != nil {
		return nil, err
	}
	defer secret.Release()
	return newConn(raw, p, secret, labelR2I, labelI2R)
}

// the ephemeral secret gives forward secrecy, the static one binds the channel
// to the node the client chose; both go through one KDF so neither alone is enough
func combine(eph, static func() (*secmem.Buffer, error)) (*secmem.Buffer, error) {
	e, err := eph()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	defer e.Release()
	s, err := static()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if s == nil {
		return e.Clone()
	}
	defer s.Release()

	joined, err := secmem.New(e.Len() + s.Len())
	if err != nil {
		return nil, err
	}
	copy(joined.Bytes(), e.Bytes())
	copy(joined.Bytes()[e.Len():], s.Bytes())
	return joined, nil
}

func newConn(raw net.Conn, p jcrypto.CryptoProvider, secret *secmem.Buffer, sendLabel, recvLabel string) (*Conn, error) {
	sendKey, err := p.DeriveKey(secret, []byte(sendLabel), p.KeySize())
	if err != nil {
		return nil, err
	}
	defer sendKey.Release()
	recvKey, err := p.DeriveKey(secret, []byte(recvLabel), p.KeySize())
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

func (c *Conn) WriteCell(cell *wire.Cell) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.send == nil {
		return net.ErrClosed
	}
	frame := c.send.Seal(nil, nonce(c.send.NonceSize(), c.sendSeq), cell[:], nil)
	c.sendSeq++
	_, err := c.raw.Write(frame)
	return err
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
	return err
}
