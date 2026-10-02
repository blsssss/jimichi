package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	AddrSize   = 64
	setupFlags = 1
	setupHdr   = setupFlags + AddrSize + 8

	exchangeSetup = "setup"

	purposeSetup  = "setup"
	purposeCell   = "cell"
	purposeReplay = "setup/replay"

	// taken from the shared secret like the cell key, so the offsets need no
	// bytes in the setup cell
	purposeCounterForward  = "counter/fwd"
	purposeCounterBackward = "counter/bwd"
)

// no suite fits more layers into one setup cell; the bound also keeps a
// hostile index from reaching slice arithmetic
const MaxHops = 8

var (
	ErrAddrSize  = errors.New("wire: address too long")
	ErrSetupSize = errors.New("wire: chain does not fit in a setup cell")
)

// one cell carries the whole chain setup, so a relay learns its successor
// without another round trip and an observer sees one cell per link either way
type SetupHop struct {
	// public key of the relay this layer is addressed to
	StaticPub []byte
	// address of the next relay, empty at the exit
	NextAddr string
	// circuit identifier the next link will use; the exit has no next link,
	// and BuildSetup puts its first forward counter in the field instead
	NextCircuit uint64
	// identifier of the link into this relay
	Link uint64
}

type SetupResult struct {
	Cell     *Cell
	CellKeys []*secmem.Buffer
	Offsets  []Offsets
}

func setupLayerLen(index, perHop int) int { return BodySize - index*perHop }

type suiteSizes struct{ pub, overhead int }

// the provider has no size query; one probe per suite is enough, where a probe
// per setup cell would cost a relay a GOST key pair for every circuit
var sizeCache sync.Map

func sizesOf(p jcrypto.CryptoProvider) (suiteSizes, error) {
	if v, ok := sizeCache.Load(p.Suite()); ok {
		return v.(suiteSizes), nil
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		return suiteSizes{}, err
	}
	priv.Release()
	probe, err := secmem.New(p.KeySize())
	if err != nil {
		return suiteSizes{}, err
	}
	defer probe.Release()
	a, err := p.NewAEAD(probe)
	if err != nil {
		return suiteSizes{}, err
	}
	sz := suiteSizes{pub: len(pub), overhead: a.Overhead()}
	a.Destroy()
	sizeCache.Store(p.Suite(), sz)
	return sz, nil
}

// length of the agreement keys GenerateEphemeral returns, which setup and link
// expect from a node
func PublicKeySize(p jcrypto.CryptoProvider) (int, error) {
	sz, err := sizesOf(p)
	if err != nil {
		return 0, err
	}
	return sz.pub, nil
}

func perHopCost(pubLen, overhead int) int { return pubLen + overhead + setupHdr }

// how many hops one setup cell of the suite carries
func MaxLayers(p jcrypto.CryptoProvider) (int, error) {
	sz, err := sizesOf(p)
	if err != nil {
		return 0, err
	}
	return min(BodySize/perHopCost(sz.pub, sz.overhead), MaxHops), nil
}

// builds the nested setup and returns the per-hop cell keys the client keeps
func BuildSetup(p jcrypto.CryptoProvider, chain []SetupHop) (*SetupResult, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("wire: empty chain")
	}

	sz, err := sizesOf(p)
	if err != nil {
		return nil, err
	}
	overhead := sz.overhead

	pubLen := len(chain[0].StaticPub)
	perHop := perHopCost(pubLen, overhead)
	if setupLayerLen(len(chain), perHop) < 0 {
		return nil, ErrSetupSize
	}

	cellKeys := make([]*secmem.Buffer, len(chain))
	offsets := make([]Offsets, len(chain))
	setupKeys := make([]*secmem.Buffer, len(chain))
	ephPubs := make([][]byte, len(chain))
	built := false
	release := func() {
		for _, k := range setupKeys {
			if k != nil {
				k.Release()
			}
		}
		if built {
			return
		}
		for _, k := range cellKeys {
			if k != nil {
				k.Release()
			}
		}
	}

	for i, hop := range chain {
		if len(hop.StaticPub) != sz.pub {
			release()
			return nil, fmt.Errorf("wire: key of hop %d: %w", i, jcrypto.ErrBadPublicKey)
		}
		ephPriv, ephPub, err := p.GenerateEphemeral()
		if err != nil {
			release()
			return nil, err
		}
		ctx, err := setupContext(p, i, hop.Link, hop.StaticPub, ephPub)
		if err != nil {
			ephPriv.Release()
			release()
			return nil, err
		}
		secret, err := p.Agree(ephPriv, hop.StaticPub, ctx)
		ephPriv.Release()
		if err != nil {
			release()
			return nil, fmt.Errorf("wire: agree with hop %d: %w", i, err)
		}
		setupKeys[i], err = p.DeriveKey(secret, purposeSetup, ctx, p.KeySize())
		if err != nil {
			secret.Release()
			release()
			return nil, err
		}
		cellKeys[i], err = p.DeriveKey(secret, purposeCell, ctx, p.KeySize())
		if err != nil {
			secret.Release()
			release()
			return nil, err
		}
		offsets[i], err = deriveOffsets(p, secret, ctx)
		secret.Release()
		if err != nil {
			release()
			return nil, err
		}
		ephPubs[i] = ephPub
	}
	defer release()

	body := make([]byte, setupLayerLen(len(chain), perHop))
	if _, err := io.ReadFull(rand.Reader, body); err != nil {
		return nil, err
	}

	for i := len(chain) - 1; i >= 0; i-- {
		plain := make([]byte, setupHdr+len(body))
		next := chain[i].NextCircuit
		if chain[i].NextAddr != "" {
			plain[0] = 1
		} else {
			next = firstForward(offsets[:i])
		}
		if err := putAddr(plain[setupFlags:setupFlags+AddrSize], chain[i].NextAddr); err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint64(plain[setupFlags+AddrSize:setupHdr], next)
		copy(plain[setupHdr:], body)

		aead, err := p.NewAEAD(setupKeys[i])
		if err != nil {
			return nil, err
		}
		nonce, err := nonceFor(aead.NonceSize(), Forward, chain[i].Link, 0)
		if err != nil {
			aead.Destroy()
			return nil, err
		}
		ct := aead.Seal(nil, nonce, plain, setupAAD(i))
		aead.Destroy()

		layer := make([]byte, 0, len(ephPubs[i])+len(ct))
		layer = append(layer, ephPubs[i]...)
		body = append(layer, ct...)
	}

	padded := make([]byte, BodySize)
	copy(padded, body)
	if _, err := io.ReadFull(rand.Reader, padded[len(body):]); err != nil {
		return nil, err
	}

	cell, err := NewCell(Header{Kind: KindControl, Circuit: chain[0].Link, Counter: 0}, padded)
	if err != nil {
		return nil, err
	}
	built = true
	return &SetupResult{Cell: cell, CellKeys: cellKeys, Offsets: offsets}, nil
}

// the counter the first forward cell carries into the hop after these: every
// relay seeds on the first cell it sees, so a prefix lost upstream would go
// unnoticed if the exit did not know where the sequence starts
func firstForward(before []Offsets) uint64 {
	var sum uint64
	for _, o := range before {
		sum = shift(sum, o[Forward])
	}
	return sum
}

type SetupLayer struct {
	NextAddr    string
	NextCircuit uint64
	Inner       []byte
	CellKey     *secmem.Buffer
	Offsets     Offsets
	// at the exit, the counter the first forward cell arrives with
	First uint64
	// the same for every copy of one setup and for no other setup
	Tag SetupTag
}

// index travels in the counter field: a relay must know its position before it
// can tell how much of the body belongs to its layer. staticPub is the key the
// client took from the descriptor: it is part of the transcript, so a layer
// built for another key does not open
func OpenSetup(p jcrypto.CryptoProvider, staticPriv *secmem.Buffer, staticPub []byte, cell *Cell) (*SetupLayer, error) {
	hdr, err := cell.Header()
	if err != nil {
		return nil, err
	}
	if hdr.Kind != KindControl {
		return nil, fmt.Errorf("wire: not a setup cell")
	}
	if hdr.Counter >= MaxHops {
		return nil, ErrSetupSize
	}
	index := int(hdr.Counter)

	sz, err := sizesOf(p)
	if err != nil {
		return nil, err
	}
	pubLen, overhead := sz.pub, sz.overhead
	if len(staticPub) != pubLen {
		return nil, jcrypto.ErrBadPublicKey
	}

	perHop := perHopCost(pubLen, overhead)
	layerLen := setupLayerLen(index, perHop)
	if layerLen <= pubLen+overhead || layerLen > BodySize {
		return nil, ErrSetupSize
	}

	layer := cell.Body()[:layerLen]
	ephPub := layer[:pubLen]

	ctx, err := setupContext(p, index, hdr.Circuit, staticPub, ephPub)
	if err != nil {
		return nil, err
	}
	secret, err := p.Agree(staticPriv, ephPub, ctx)
	if err != nil {
		return nil, err
	}
	setupKey, err := p.DeriveKey(secret, purposeSetup, ctx, p.KeySize())
	if err != nil {
		secret.Release()
		return nil, err
	}
	defer setupKey.Release()
	// the bytes of the ephemeral key are in the transcript, so another encoding
	// of the same point gives another secret and only an exact copy of the
	// layer reaches this tag
	tag, err := setupTag(p, secret, ctx)
	if err != nil {
		secret.Release()
		return nil, err
	}
	cellKey, err := p.DeriveKey(secret, purposeCell, ctx, p.KeySize())
	if err != nil {
		secret.Release()
		return nil, err
	}
	offsets, err := deriveOffsets(p, secret, ctx)
	secret.Release()
	if err != nil {
		cellKey.Release()
		return nil, err
	}

	aead, err := p.NewAEAD(setupKey)
	if err != nil {
		cellKey.Release()
		return nil, err
	}
	defer aead.Destroy()

	nonce, err := nonceFor(aead.NonceSize(), Forward, hdr.Circuit, 0)
	if err != nil {
		cellKey.Release()
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, layer[pubLen:], setupAAD(index))
	if err != nil {
		cellKey.Release()
		return nil, err
	}
	if len(plain) < setupHdr {
		cellKey.Release()
		return nil, ErrFraming
	}

	out := &SetupLayer{CellKey: cellKey, Offsets: offsets, Inner: plain[setupHdr:], Tag: tag}
	next := binary.BigEndian.Uint64(plain[setupFlags+AddrSize : setupHdr])
	if plain[0] == 1 {
		out.NextAddr = takeAddr(plain[setupFlags : setupFlags+AddrSize])
		out.NextCircuit = next
		return out, nil
	}
	if next >= counterLimit {
		cellKey.Release()
		return nil, ErrFraming
	}
	out.First = next
	return out, nil
}

// the forwarded cell is padded back to full size, so every link carries the
// same 512 bytes no matter how far along the chain it is
func ForwardSetup(layer *SetupLayer, index int) (*Cell, error) {
	body := make([]byte, BodySize)
	copy(body, layer.Inner)
	if _, err := io.ReadFull(rand.Reader, body[len(layer.Inner):]); err != nil {
		return nil, err
	}
	return NewCell(Header{Kind: KindControl, Circuit: layer.NextCircuit, Counter: uint64(index + 1)}, body)
}

// the tag is a one-way image of the secret under its own label, so keeping it
// on the heap for the life of the node key reveals none of the layer keys
func setupTag(p jcrypto.CryptoProvider, secret *secmem.Buffer, ctx jcrypto.Context) (SetupTag, error) {
	var tag SetupTag
	b, err := p.DeriveKey(secret, purposeReplay, ctx, len(tag))
	if err != nil {
		return tag, err
	}
	copy(tag[:], b.Bytes())
	b.Release()
	return tag, nil
}

func setupAAD(index int) []byte {
	return []byte{byte(Version), byte(KindControl), byte(index)}
}

// one transcript per hop: version, hop index, identifier of the link into the
// hop, the hop's onion key, the client's ephemeral key
func setupContext(p jcrypto.CryptoProvider, index int, link uint64, staticPub, ephPub []byte) (jcrypto.Context, error) {
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], link)
	return jcrypto.NewContext(p, exchangeSetup, []byte{byte(Version)}, []byte{byte(index)}, id[:], staticPub, ephPub)
}

func putAddr(dst []byte, addr string) error {
	if len(addr) > len(dst) {
		return fmt.Errorf("%w: %q", ErrAddrSize, addr)
	}
	copy(dst, addr)
	return nil
}

func takeAddr(src []byte) string {
	return strings.TrimRight(string(src), "\x00")
}
