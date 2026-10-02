package wire

import (
	"encoding/binary"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// the exit alone can seal a last layer over a length prefix of its choice:
// every layer of such a reply verifies, so only the framing check is left to
// refuse it
func TestOpenExitRefusesBadFramingUnderTheLastLayer(t *testing.T) {
	for _, p := range []jcrypto.CryptoProvider{c25519.New(), gost.New()} {
		t.Run(p.Suite().String(), func(t *testing.T) {
			const n = 3
			links := []uint64{100, 101, 102}
			keys := make([]*secmem.Buffer, n)
			offsets := make([]Offsets, n)
			hops := make([]*Hop, n)
			for i := range keys {
				k, err := secmem.New(p.KeySize())
				if err != nil {
					t.Fatalf("key %d: %v", i, err)
				}
				t.Cleanup(k.Release)
				for j := range k.Bytes() {
					k.Bytes()[j] = byte(i*31 + j)
				}
				keys[i] = k
				offsets[i] = Offsets{uint64(i + 1), uint64(i + 7)}
				if hops[i], err = NewHop(p, k, offsets[i], i); err != nil {
					t.Fatalf("NewHop %d: %v", i, err)
				}
				t.Cleanup(hops[i].Close)
			}
			circuit, err := NewCircuit(p, keys, offsets, links)
			if err != nil {
				t.Fatalf("NewCircuit: %v", err)
			}
			t.Cleanup(circuit.Close)

			room := circuit.MaxPayload()
			for _, tc := range []struct {
				name   string
				prefix uint16
				opens  bool
				cover  bool
				length int
			}{
				{"the longest length that fits", uint16(room), true, false, room},
				{"cover flag over no length", coverFlag, true, true, 0},
				{"one byte more than fits", uint16(room + 1), false, false, 0},
				{"cover flag over a length", coverFlag | 1, false, false, 0},
			} {
				inner := make([]byte, lengthPrefix+room)
				binary.BigEndian.PutUint16(inner, tc.prefix)
				hdr := Header{Kind: KindData, Circuit: links[n-1], Counter: shift(0, offsets[n-1][Backward])}
				cell, err := hops[n-1].seal(hdr, inner)
				if err != nil {
					t.Fatalf("%s: seal the last layer: %v", tc.name, err)
				}
				for i := n - 2; i >= 0; i-- {
					if cell, err = hops[i].Wrap(cell, links[i]); err != nil {
						t.Fatalf("%s: wrap at node %d: %v", tc.name, i, err)
					}
				}
				payload, cover, err := circuit.OpenExit(cell, Backward)
				if !tc.opens {
					if !errors.Is(err, ErrFraming) || payload != nil || cover {
						t.Fatalf("%s: OpenExit = %d bytes, cover %v, %v, want ErrFraming", tc.name, len(payload), cover, err)
					}
					continue
				}
				if err != nil || cover != tc.cover || len(payload) != tc.length {
					t.Fatalf("%s: OpenExit = %d bytes, cover %v, %v, want %d bytes, cover %v", tc.name, len(payload), cover, err, tc.length, tc.cover)
				}
			}
		})
	}
}
