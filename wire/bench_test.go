package wire_test

import (
	"bytes"
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/wire"
)

// these feed the "cost per cell" table: nanoseconds and allocations for sealing
// a full onion and for one relay stripping its layer

func benchKeys(b *testing.B, p jcrypto.CryptoProvider, n int) []*secmem.Buffer {
	b.Helper()
	keys := make([]*secmem.Buffer, n)
	for i := range keys {
		k, err := secmem.New(p.KeySize())
		if err != nil {
			b.Fatalf("key %d: %v", i, err)
		}
		for j := range k.Bytes() {
			k.Bytes()[j] = byte(i*31 + j)
		}
		keys[i] = k
		b.Cleanup(k.Release)
	}
	return keys
}

func BenchmarkSeal(b *testing.B) {
	p := provider()
	keys := benchKeys(b, p, hops)
	links := []uint64{101, 102, 103}
	c, err := wire.NewCircuit(p, keys, links)
	if err != nil {
		b.Fatalf("NewCircuit: %v", err)
	}
	defer c.Close()

	payload := bytes.Repeat([]byte("x"), c.MaxPayload())
	b.ReportAllocs()
	b.SetBytes(wire.CellSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Seal(wire.KindPayload, uint64(i), payload); err != nil {
			b.Fatalf("Seal: %v", err)
		}
	}
}

func BenchmarkPeel(b *testing.B) {
	p := provider()
	keys := benchKeys(b, p, hops)
	links := []uint64{101, 102, 103}
	c, err := wire.NewCircuit(p, keys, links)
	if err != nil {
		b.Fatalf("NewCircuit: %v", err)
	}
	defer c.Close()

	hop, err := wire.NewHop(p, keys[0], 0)
	if err != nil {
		b.Fatalf("NewHop: %v", err)
	}
	defer hop.Close()

	cells := make([]*wire.Cell, 256)
	payload := bytes.Repeat([]byte("x"), 128)
	for i := range cells {
		cell, err := c.Seal(wire.KindPayload, uint64(i), payload)
		if err != nil {
			b.Fatalf("Seal: %v", err)
		}
		cells[i] = cell
	}

	b.ReportAllocs()
	b.SetBytes(wire.CellSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hop.Peel(cells[i%len(cells)], wire.Forward); err != nil {
			b.Fatalf("Peel: %v", err)
		}
	}
}
