package wire_test

import (
	"encoding/binary"
	"strings"
	"sync"
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/wire"
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
