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

func (p *trackingProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, peerPub, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.MixKey(chain, secret, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
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

	layer, err := wire.OpenSetup(tp, privs[0], pubs[0], setup.Cell)
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

// hops before the failing one already hold keys, and those must go too. A short
// key is refused before the hop makes any buffer; all zeroes at the right
// length (a point of small order on c25519, a point off the curve on GOST) is
// refused inside the agreement, when the hop already holds its ephemeral key
func TestBuildSetupReleasesEarlierHopsWhenOneFails(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		// the size probe of the suite makes a key pair, so it runs before the count
		if _, err := wire.PublicKeySize(p); err != nil {
			t.Fatal(err)
		}
		_, pubs := staticKeys(t, p, hops)
		for name, bad := range map[string][]byte{
			"a short key":                 pubs[hops-1][:5],
			"a key the agreement refuses": make([]byte, len(pubs[0])),
		} {
			t.Run(s.String()+"/"+name, func(t *testing.T) {
				tp := &trackingProvider{CryptoProvider: p}
				chain := chainTo(pubs)
				chain[hops-1].StaticPub = bad

				if _, err := wire.BuildSetup(tp, chain); err == nil {
					t.Fatal("BuildSetup accepted a malformed public key")
				}
				tp.mu.Lock()
				made := len(tp.bufs)
				tp.mu.Unlock()
				// an ephemeral key, a secret, two keys and two offsets per whole hop
				if whole := 6 * (hops - 1); (len(bad) == len(pubs[0])) != (made > whole) {
					t.Fatalf("%d buffers made, %d by the hops before the failing one", made, whole)
				}
				if n := tp.live(); n != 0 {
					t.Fatalf("%d key buffers still held after a failed BuildSetup, want 0", n)
				}
			})
		}
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
		if _, err := wire.OpenSetup(provider(), privs[0], pubs[0], &cell); err == nil {
			t.Fatalf("OpenSetup accepted hop index %d", counter)
		}
	}
}

func openTag(t *testing.T, priv *secmem.Buffer, pub []byte, cell *wire.Cell) wire.SetupTag {
	t.Helper()
	layer, err := wire.OpenSetup(provider(), priv, pub, cell)
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
		tags[i] = openTag(t, privs[0], pubs[0], setup.Cell)
	}
	if again := openTag(t, privs[0], pubs[0], cells[0]); again != tags[0] {
		t.Fatal("one setup opened twice gave two tags")
	}
	if tags[0] == tags[1] {
		t.Fatal("two setups share a tag")
	}
}

// an exact copy of a setup opens again under the same tag, which the cache
// then refuses; a copy changed in the way change says must not open at all
func refusesChangedCopy(t *testing.T, change func(cell *wire.Cell, at, pubLen int)) {
	t.Helper()
	privs, pubs := staticKeys(t, provider(), hops)
	setup, err := wire.BuildSetup(provider(), chainTo(pubs))
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		t.Cleanup(k.Release)
	}
	cache := wire.NewSetupCache(0)
	if err := cache.Add(openTag(t, privs[0], pubs[0], setup.Cell)); err != nil {
		t.Fatalf("first copy: %v", err)
	}
	same := *setup.Cell
	if err := cache.Add(openTag(t, privs[0], pubs[0], &same)); !errors.Is(err, wire.ErrSetupReplay) {
		t.Fatalf("exact copy: %v, want ErrSetupReplay", err)
	}

	changed := *setup.Cell
	change(&changed, wire.CellSize-wire.BodySize, len(pubs[0]))
	if changed == *setup.Cell {
		t.Fatal("the copy was not changed")
	}
	if _, err := wire.OpenSetup(provider(), privs[0], pubs[0], &changed); !errors.Is(err, jcrypto.ErrOpen) {
		t.Fatalf("changed copy: %v, want ErrOpen", err)
	}
}

// X25519 drops the top bit of a point, so a copy with that bit flipped names
// the same point; its bytes are in the transcript, so the layer does not open
func TestSetupRefusesAnotherEncodingOfTheKey(t *testing.T) {
	refusesChangedCopy(t, func(cell *wire.Cell, at, pubLen int) {
		cell[at+pubLen-1] ^= 0x80
	})
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
// a multiple of eight, so this is one more key with the same X25519 output; the
// transcript holds other bytes, so the layer does not open
func TestSetupRefusesASmallOrderShift(t *testing.T) {
	refusesChangedCopy(t, func(cell *wire.Cell, at, pubLen int) {
		u := new(big.Int).SetBytes(reversed(cell[at : at+pubLen]))
		prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
		inv := new(big.Int).ModInverse(u, prime)
		if inv == nil {
			t.Fatal("ephemeral key has no inverse")
		}
		copy(cell[at:at+pubLen], reversed(inv.FillBytes(make([]byte, pubLen))))
	})
}

// a layer opens only at the node, the position and the link it was built for.
// The onion key is held by the transcript alone; the index is also in the AAD
// and the link identifier in the nonce, so their place in the transcript is
// pinned by TestSetupKeyScheduleByHand and TestCounterOffsetKnownAnswer
func TestOpenSetupIsBoundToKeyIndexAndLink(t *testing.T) {
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

			// the private key is the right one, the public key named with it is not
			if _, err := wire.OpenSetup(p, privs[0], pubs[1], setup.Cell); !errors.Is(err, jcrypto.ErrOpen) {
				t.Fatalf("another public key of the right length: %v, want ErrOpen", err)
			}
			for _, pub := range [][]byte{nil, pubs[0][:len(pubs[0])-1], append(append([]byte{}, pubs[0]...), 0)} {
				if _, err := wire.OpenSetup(p, privs[0], pub, setup.Cell); !errors.Is(err, jcrypto.ErrBadPublicKey) {
					t.Fatalf("public key of %d bytes: %v, want ErrBadPublicKey", len(pub), err)
				}
			}

			moved := *setup.Cell
			binary.BigEndian.PutUint64(moved[10:18], 1)
			if _, err := wire.OpenSetup(p, privs[0], pubs[0], &moved); !errors.Is(err, jcrypto.ErrOpen) {
				t.Fatalf("another hop index: %v, want ErrOpen", err)
			}
			relinked := *setup.Cell
			binary.BigEndian.PutUint64(relinked[2:10], 201)
			if _, err := wire.OpenSetup(p, privs[0], pubs[0], &relinked); !errors.Is(err, jcrypto.ErrOpen) {
				t.Fatalf("another link identifier: %v, want ErrOpen", err)
			}

			layer, err := wire.OpenSetup(p, privs[0], pubs[0], setup.Cell)
			if err != nil {
				t.Fatalf("the unchanged cell: %v", err)
			}
			layer.CellKey.Release()
		})
	}
}

func TestBuildSetupRefusesAKeyOfAnotherLength(t *testing.T) {
	_, pubs := staticKeys(t, provider(), hops)
	for _, pub := range [][]byte{nil, pubs[1][:31], append(append([]byte{}, pubs[1]...), 0)} {
		chain := chainTo(pubs)
		chain[1].StaticPub = pub
		if _, err := wire.BuildSetup(provider(), chain); !errors.Is(err, jcrypto.ErrBadPublicKey) {
			t.Fatalf("hop key of %d bytes: %v, want ErrBadPublicKey", len(pub), err)
		}
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

// a setup layer costs the hop's ephemeral key, a 16-byte tag and a 73-byte
// header: 121 bytes on c25519, 153 on GOST. The body is 494 bytes, so four
// layers fit on c25519 (484) and three on GOST (459, a fourth would need 612)
func TestMaxLayersIsWhatASetupCellCarries(t *testing.T) {
	for _, c := range []struct {
		suite jcrypto.Suite
		want  int
	}{{jcrypto.SuiteC25519, 4}, {jcrypto.SuiteGOST, 3}} {
		t.Run(c.suite.String(), func(t *testing.T) {
			p, err := suite.New(c.suite)
			if err != nil {
				t.Fatal(err)
			}
			n, err := wire.MaxLayers(p)
			if err != nil || n != c.want {
				t.Fatalf("MaxLayers = %d, %v, want %d", n, err, c.want)
			}
			privs, pubs := staticKeys(t, p, n+1)
			setup, err := wire.BuildSetup(p, chainTo(pubs[:n]))
			if err != nil {
				t.Fatalf("BuildSetup with %d hops: %v", n, err)
			}
			for _, k := range setup.CellKeys {
				t.Cleanup(k.Release)
			}
			cell := setup.Cell
			for i := 0; i < n; i++ {
				layer, err := wire.OpenSetup(p, privs[i], pubs[i], cell)
				if err != nil {
					t.Fatalf("OpenSetup %d of %d: %v", i, n, err)
				}
				layer.CellKey.Release()
				if exit := layer.NextAddr == ""; exit != (i == n-1) {
					t.Fatalf("hop %d of %d: exit %v", i, n, exit)
				}
				if cell, err = wire.ForwardSetup(layer, i); err != nil {
					t.Fatalf("ForwardSetup %d: %v", i, err)
				}
			}
			if _, err := wire.BuildSetup(p, chainTo(pubs)); !errors.Is(err, wire.ErrSetupSize) {
				t.Fatalf("BuildSetup with %d hops: %v, want ErrSetupSize", n+1, err)
			}
		})
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
				layer, err := wire.OpenSetup(p, privs[i], pubs[i], cell)
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
