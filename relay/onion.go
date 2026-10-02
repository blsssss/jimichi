package relay

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

var (
	ErrOnionKey   = errors.New("relay: onion key missing, of the wrong size or already in the ring")
	errRingClosed = errors.New("relay: onion keys released")
)

type onionKey struct {
	epoch uint32
	priv  *secmem.Buffer
	pub   []byte
	// tags of the setups this key opened; they go with the key, since no copy
	// opens once it is released
	setups *wire.SetupCache
}

// OnionRing holds the keys that open setup layers: the one the node publishes
// and, for a grace period after a rotation, the one before it. A setup cell
// recorded earlier stops opening once its key is released
type OnionRing struct {
	pubSize   int
	cacheSize int

	mu       sync.RWMutex
	current  *onionKey
	previous *onionKey
	closed   bool
}

// the ring owns priv once it is returned without an error and releases it on
// Retire or Close; cacheSize bounds the setups remembered per key, zero picks
// the default. pub, here and in Rotate, must be byte for byte what the node
// publishes for priv: it is a part of the setup transcript, so under any other
// bytes the key opens no setup
func NewOnionRing(p jcrypto.CryptoProvider, priv *secmem.Buffer, pub []byte, cacheSize int) (*OnionRing, error) {
	if cacheSize < 0 || cacheSize > MaxSetupCache {
		return nil, fmt.Errorf("relay: setup cache of %d entries outside 0..%d", cacheSize, MaxSetupCache)
	}
	size, err := wire.PublicKeySize(p)
	if err != nil {
		return nil, err
	}
	if priv == nil || len(pub) != size {
		return nil, ErrOnionKey
	}
	return &OnionRing{
		pubSize:   size,
		cacheSize: cacheSize,
		current:   &onionKey{priv: priv, pub: bytes.Clone(pub), setups: wire.NewSetupCache(cacheSize)},
	}, nil
}

// the link key in the onion role as well: the relay that builds this ring
// never rotates or closes it, so the key stays with its owner
func staticRing(priv *secmem.Buffer, pub []byte, cacheSize int) *OnionRing {
	return &OnionRing{
		pubSize:   len(pub),
		cacheSize: cacheSize,
		current:   &onionKey{priv: priv, pub: bytes.Clone(pub), setups: wire.NewSetupCache(cacheSize)},
	}
}

// Rotate makes priv the current key under the next epoch and keeps the key it
// replaces as the previous one; the one held as previous until now is released.
// On an error the caller still owns priv
func (g *OnionRing) Rotate(priv *secmem.Buffer, pub []byte) (uint32, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, errRingClosed
	}
	// two slots under one key would let one setup open twice
	if priv == nil || len(pub) != g.pubSize || bytes.Equal(pub, g.current.pub) {
		return 0, ErrOnionKey
	}
	if g.previous != nil {
		g.previous.priv.Release()
	}
	g.previous = g.current
	g.current = &onionKey{
		epoch:  g.previous.epoch + 1,
		priv:   priv,
		pub:    bytes.Clone(pub),
		setups: wire.NewSetupCache(g.cacheSize),
	}
	return g.current.epoch, nil
}

// Retire releases the previous key and forgets its tags; it waits for the
// setups being opened, so no key is freed under one of them
func (g *OnionRing) Retire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.previous != nil {
		g.previous.priv.Release()
		g.previous = nil
	}
}

func (g *OnionRing) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, k := range []*onionKey{g.current, g.previous} {
		if k != nil {
			k.priv.Release()
		}
	}
	g.current, g.previous, g.closed = nil, nil, true
}

func (g *OnionRing) Current() (epoch uint32, pub []byte) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current == nil {
		return 0, nil
	}
	return g.current.epoch, bytes.Clone(g.current.pub)
}

// Open tries every live key, in one order and to the end even after one has
// opened, so the time a setup takes does not tell which epoch its client used.
// Each key is tried under a transcript that holds its own public half, so a
// layer built for one epoch does not open under the key of another.
// The tag is burned on first sight whatever happens to the setup next: one that
// fails further on must not come back later on a fresh link either
func (g *OnionRing) Open(p jcrypto.CryptoProvider, cell *wire.Cell) (*wire.SetupLayer, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return nil, errRingClosed
	}
	var (
		opened  *wire.SetupLayer
		by      *onionKey
		refused error
	)
	for _, k := range []*onionKey{g.current, g.previous} {
		if k == nil {
			continue
		}
		layer, err := wire.OpenSetup(p, k.priv, k.pub, cell)
		switch {
		case err != nil:
			if refused == nil {
				refused = err
			}
		case opened == nil:
			opened, by = layer, k
		default:
			layer.CellKey.Release()
		}
	}
	if opened == nil {
		return nil, refused
	}
	if err := by.setups.Add(opened.Tag); err != nil {
		opened.CellKey.Release()
		return nil, err
	}
	return opened, nil
}
