package wire_test

import (
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
)

type trackingProvider struct {
	jcrypto.CryptoProvider
	mu   sync.Mutex
	bufs []*secmem.Buffer
}

func (p *trackingProvider) keep(b *secmem.Buffer) *secmem.Buffer {
	if b != nil {
		p.mu.Lock()
		p.bufs = append(p.bufs, b)
		p.mu.Unlock()
	}
	return b
}

func (p *trackingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(priv), pub, err
}

func (p *trackingProvider) Agree(priv *secmem.Buffer, peerPub, ukm []byte) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, peerPub, ukm)
	return p.keep(b), err
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, label []byte, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, label, size)
	return p.keep(b), err
}

func (p *trackingProvider) live(except ...*secmem.Buffer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
outer:
	for _, b := range p.bufs {
		for _, e := range except {
			if b == e {
				continue outer
			}
		}
		if b.Bytes() != nil {
			n++
		}
	}
	return n
}

func staticKeys(t *testing.T, p jcrypto.CryptoProvider, n int) ([]*secmem.Buffer, [][]byte) {
	t.Helper()
	privs := make([]*secmem.Buffer, n)
	pubs := make([][]byte, n)
	for i := range privs {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatalf("static key %d: %v", i, err)
		}
		t.Cleanup(priv.Release)
		privs[i], pubs[i] = priv, pub
	}
	return privs, pubs
}

func chainTo(pubs [][]byte) []wire.SetupHop {
	hops := make([]wire.SetupHop, len(pubs))
	for i, pub := range pubs {
		hops[i] = wire.SetupHop{StaticPub: pub, Link: uint64(200 + i), NextCircuit: uint64(201 + i)}
		if i < len(pubs)-1 {
			hops[i].NextAddr = "relay-next:9000"
		}
	}
	return hops
}

// every relay runs OpenSetup once per circuit, so a buffer left behind costs a
// locked page per circuit until RLIMIT_MEMLOCK runs out
func TestOpenSetupReleasesEverythingButTheCellKey(t *testing.T) {
	tp := &trackingProvider{CryptoProvider: provider()}
	privs, pubs := staticKeys(t, provider(), hops)

	setup, err := wire.BuildSetup(provider(), chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		t.Cleanup(k.Release)
	}

	layer, err := wire.OpenSetup(tp, privs[0], setup.Cell)
	if err != nil {
		t.Fatalf("OpenSetup: %v", err)
	}
	defer layer.CellKey.Release()

	if layer.CellKey.Bytes() == nil {
		t.Fatal("OpenSetup handed back a released cell key")
	}
	if n := tp.live(layer.CellKey); n != 0 {
		t.Fatalf("%d key buffers still held after OpenSetup, want 0", n)
	}
}

func TestBuildSetupReleasesKeysOnError(t *testing.T) {
	tp := &trackingProvider{CryptoProvider: provider()}
	_, pubs := staticKeys(t, provider(), hops)
	chain := chainTo(pubs)
	chain[0].NextAddr = strings.Repeat("x", wire.AddrSize+1)

	if _, err := wire.BuildSetup(tp, chain); err == nil {
		t.Fatal("BuildSetup accepted an address that does not fit")
	}
	if n := tp.live(); n != 0 {
		t.Fatalf("%d key buffers still held after a failed BuildSetup, want 0", n)
	}
}

// hops before the failing one already hold keys, and those must go too
func TestBuildSetupReleasesEarlierHopsWhenOneFails(t *testing.T) {
	tp := &trackingProvider{CryptoProvider: provider()}
	_, pubs := staticKeys(t, provider(), hops)
	chain := chainTo(pubs)
	chain[hops-1].StaticPub = chain[hops-1].StaticPub[:5]

	if _, err := wire.BuildSetup(tp, chain); err == nil {
		t.Fatal("BuildSetup accepted a malformed public key")
	}
	if n := tp.live(); n != 0 {
		t.Fatalf("%d key buffers still held after a failed BuildSetup, want 0", n)
	}
}

func TestBuildSetupKeepsOnlyCellKeys(t *testing.T) {
	tp := &trackingProvider{CryptoProvider: provider()}
	_, pubs := staticKeys(t, provider(), hops)

	setup, err := wire.BuildSetup(tp, chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for i, k := range setup.CellKeys {
		defer k.Release()
		if k.Bytes() == nil {
			t.Fatalf("cell key %d released before it was handed back", i)
		}
	}
	if n := tp.live(setup.CellKeys...); n != 0 {
		t.Fatalf("%d key buffers still held besides the cell keys, want 0", n)
	}
}

// the hop index rides in the counter field; a hostile client must not reach the
// slice arithmetic with a value that no chain could have
func TestOpenSetupRefusesAnImpossibleHopIndex(t *testing.T) {
	privs, pubs := staticKeys(t, provider(), hops)
	setup, err := wire.BuildSetup(provider(), chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		t.Cleanup(k.Release)
	}
	for _, counter := range []uint64{wire.MaxHops, 1 << 40, 1 << 63, ^uint64(0)} {
		cell := *setup.Cell
		binary.BigEndian.PutUint64(cell[10:18], counter)
		if _, err := wire.OpenSetup(provider(), privs[0], &cell); err == nil {
			t.Fatalf("OpenSetup accepted hop index %d", counter)
		}
	}
}

func openTag(t *testing.T, priv *secmem.Buffer, cell *wire.Cell) wire.SetupTag {
	t.Helper()
	layer, err := wire.OpenSetup(provider(), priv, cell)
	if err != nil {
		t.Fatalf("OpenSetup: %v", err)
	}
	layer.CellKey.Release()
	return layer.Tag
}

func TestSetupTagIsStablePerSetup(t *testing.T) {
	privs, pubs := staticKeys(t, provider(), hops)
	var tags [2]wire.SetupTag
	var cells [2]*wire.Cell
	for i := range tags {
		setup, err := wire.BuildSetup(provider(), chainTo(pubs))
		if err != nil {
			t.Fatalf("BuildSetup: %v", err)
		}
		for _, k := range setup.CellKeys {
			t.Cleanup(k.Release)
		}
		cells[i] = setup.Cell
		tags[i] = openTag(t, privs[0], setup.Cell)
	}
	if again := openTag(t, privs[0], cells[0]); again != tags[0] {
		t.Fatal("one setup opened twice gave two tags")
	}
	if tags[0] == tags[1] {
		t.Fatal("two setups share a tag")
	}
}

// X25519 drops the top bit of a point, so a copy with that bit flipped opens
// the same layer; a tag taken from the wire bytes would let it through
func TestSetupTagSurvivesAnotherEncodingOfTheKey(t *testing.T) {
	privs, pubs := staticKeys(t, provider(), hops)
	setup, err := wire.BuildSetup(provider(), chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		t.Cleanup(k.Release)
	}
	want := openTag(t, privs[0], setup.Cell)

	flipped := *setup.Cell
	pubLen := len(pubs[0])
	flipped[wire.CellSize-wire.BodySize+pubLen-1] ^= 0x80
	if got := openTag(t, privs[0], &flipped); got != want {
		t.Fatal("another encoding of the same key gave another tag")
	}
}

func TestSetupCache(t *testing.T) {
	c := wire.NewSetupCache(2)
	a, b, d := wire.SetupTag{1}, wire.SetupTag{2}, wire.SetupTag{3}
	if err := c.Add(a); err != nil {
		t.Fatalf("first tag: %v", err)
	}
	if err := c.Add(a); !errors.Is(err, wire.ErrSetupReplay) {
		t.Fatalf("repeated tag: %v, want ErrSetupReplay", err)
	}
	if err := c.Add(b); err != nil {
		t.Fatalf("second tag: %v", err)
	}
	if err := c.Add(d); !errors.Is(err, wire.ErrSetupCacheFull) {
		t.Fatalf("tag past capacity: %v, want ErrSetupCacheFull", err)
	}
	// a full cache still knows what it holds, so a replay is not mistaken for load
	if err := c.Add(b); !errors.Is(err, wire.ErrSetupReplay) {
		t.Fatalf("repeated tag in a full cache: %v, want ErrSetupReplay", err)
	}
}

// adding the point of order two maps u to 1/u, and the clamped X25519 scalar is
// a multiple of eight, so this is one more key with the same secret
func TestSetupTagSurvivesASmallOrderShift(t *testing.T) {
	privs, pubs := staticKeys(t, provider(), hops)
	setup, err := wire.BuildSetup(provider(), chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		t.Cleanup(k.Release)
	}
	want := openTag(t, privs[0], setup.Cell)

	pubLen := len(pubs[0])
	at := wire.CellSize - wire.BodySize
	u := new(big.Int).SetBytes(reversed(setup.Cell[at : at+pubLen]))
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	inv := new(big.Int).ModInverse(u, prime)
	if inv == nil {
		t.Fatal("ephemeral key has no inverse")
	}
	shifted := *setup.Cell
	copy(shifted[at:at+pubLen], reversed(inv.FillBytes(make([]byte, pubLen))))
	if got := openTag(t, privs[0], &shifted); got != want {
		t.Fatal("a key shifted by a point of small order gave another tag")
	}
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// copies racing on different links reach the cache at once; exactly one wins
func TestSetupCacheAdmitsOneOfConcurrentCopies(t *testing.T) {
	c := wire.NewSetupCache(0)
	tag := wire.SetupTag{7}
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Add(tag) == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := won.Load(); n != 1 {
		t.Fatalf("%d copies were admitted, want 1", n)
	}
}

func TestSetupCacheDefaultSize(t *testing.T) {
	c := wire.NewSetupCache(0)
	for i := 0; i < wire.DefaultSetupCache; i++ {
		var tag wire.SetupTag
		binary.BigEndian.PutUint32(tag[:], uint32(i))
		if err := c.Add(tag); err != nil {
			t.Fatalf("tag %d of the default %d: %v", i, wire.DefaultSetupCache, err)
		}
	}
	if err := c.Add(wire.SetupTag{0xff}); !errors.Is(err, wire.ErrSetupCacheFull) {
		t.Fatalf("tag past the default size: %v, want ErrSetupCacheFull", err)
	}
}

func TestPublicKeySizeIsTheGeneratedKeyLength(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		if n, err := wire.PublicKeySize(p); err != nil || n != len(pub) {
			t.Fatalf("%v: PublicKeySize = %d, %v, want %d", s, n, err, len(pub))
		}
	}
}

// the client and every relay derive a hop's offsets from their shared secret
// alone, so both ends of each link agree on its counter values
func TestSetupHandsBothSidesTheSameOffsets(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			privs, pubs := staticKeys(t, p, hops)
			setup, err := wire.BuildSetup(p, chainTo(pubs))
			if err != nil {
				t.Fatalf("BuildSetup: %v", err)
			}
			for _, k := range setup.CellKeys {
				t.Cleanup(k.Release)
			}
			if len(setup.Offsets) != hops {
				t.Fatalf("%d offsets for %d hops", len(setup.Offsets), hops)
			}
			cell := setup.Cell
			for i := 0; i < hops; i++ {
				layer, err := wire.OpenSetup(p, privs[i], cell)
				if err != nil {
					t.Fatalf("OpenSetup %d: %v", i, err)
				}
				layer.CellKey.Release()
				if layer.Offsets != setup.Offsets[i] {
					t.Fatalf("hop %d derived %x, the client %x", i, layer.Offsets, setup.Offsets[i])
				}
				// the exit learns the value the first forward cell arrives with:
				// the base counter 0 plus the forward offsets of the hops before it
				want := uint64(0)
				if i == hops-1 {
					want = (setup.Offsets[0][wire.Forward] + setup.Offsets[1][wire.Forward]) % (1 << 62)
				}
				if layer.First != want {
					t.Fatalf("hop %d expects the first forward counter %#x, want %#x", i, layer.First, want)
				}
				if cell, err = wire.ForwardSetup(layer, i); err != nil {
					t.Fatalf("ForwardSetup %d: %v", i, err)
				}
			}
			if setup.Offsets[0] == setup.Offsets[1] || setup.Offsets[0][wire.Forward] == setup.Offsets[0][wire.Backward] {
				t.Fatalf("offsets repeat: %x", setup.Offsets)
			}
		})
	}
}
