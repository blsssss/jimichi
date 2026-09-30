package wire

import (
	"math/rand/v2"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// shared secret 40 41 .. 5f; the offset is the first 8 bytes of the KDF output,
// big endian, with the top two bits cleared. Computed outside this code:
//
//	c25519, HKDF-Expand(SHA-256, secret, label, 8) = HMAC-SHA256(secret, label || 01)[:8]
//	  fwd ca719545fdd0bc6c -> 0a719545fdd0bc6c, bwd e7442998c5b0b339 -> 27442998c5b0b339
//	gost, KDF_GOSTR3411_2012_256 (R 50.1.113) =
//	  HMAC-Streebog256(secret, 01 || label || 00 || 01 00)[:8]
//	  fwd b7a6a05760e0c351 -> 37a6a05760e0c351, bwd 07a3af1f57ab20fd -> 07a3af1f57ab20fd
func TestCounterOffsetKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		p        jcrypto.CryptoProvider
		fwd, bwd uint64
	}{
		{c25519.New(), 0x0a719545fdd0bc6c, 0x27442998c5b0b339},
		{gost.New(), 0x37a6a05760e0c351, 0x07a3af1f57ab20fd},
	} {
		t.Run(tc.p.Suite().String(), func(t *testing.T) {
			secret, err := secmem.New(32)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Release()
			for i := range secret.Bytes() {
				secret.Bytes()[i] = byte(0x40 + i)
			}
			off, err := deriveOffsets(tc.p, secret)
			if err != nil {
				t.Fatalf("deriveOffsets: %v", err)
			}
			if off[Forward] != tc.fwd || off[Backward] != tc.bwd {
				t.Fatalf("offsets %#x %#x, want %#x %#x", off[Forward], off[Backward], tc.fwd, tc.bwd)
			}
		})
	}
}

func randomOffsets(r *rand.Rand) Offsets {
	return Offsets{r.Uint64() & (counterLimit - 1), r.Uint64() & (counterLimit - 1)}
}

// three hops, the way relays compute it and the way the client does: each
// relay adds its own offset to the value it received, the client adds or takes
// away the sums of the offsets before a hop
func TestLinkValuesNeverCoincide(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 10000; n++ {
		hops := [3]Offsets{randomOffsets(r), randomOffsets(r), randomOffsets(r)}
		base := r.Uint64N(cellLimit)
		c := &Circuit{before: make([]Offsets, 3)}
		for i := 1; i < 3; i++ {
			for _, dir := range []Direction{Forward, Backward} {
				c.before[i][dir] = shift(c.before[i-1][dir], hops[i-1][dir])
			}
		}

		var fwd, bwd [3]uint64
		fwd[0] = base
		for i := 1; i < 3; i++ {
			fwd[i] = shift(fwd[i-1], hops[i-1][Forward])
		}
		bwd[2] = shift(base, hops[2][Backward])
		for i := 1; i >= 0; i-- {
			bwd[i] = shift(bwd[i+1], hops[i][Backward])
		}

		for i := 0; i < 3; i++ {
			if got := c.valueAt(i, Forward, fwd[0]); got != fwd[i] {
				t.Fatalf("circuit %d: forward value on link %d is %#x at the client, %#x at the relays", n, i, got, fwd[i])
			}
			if got := c.valueAt(i, Backward, bwd[0]); got != bwd[i] {
				t.Fatalf("circuit %d: backward value on link %d is %#x at the client, %#x at the relays", n, i, got, bwd[i])
			}
			for j := i + 1; j < 3; j++ {
				if fwd[i] == fwd[j] || bwd[i] == bwd[j] {
					t.Fatalf("circuit %d: links %d and %d carry the same value", n, i, j)
				}
			}
			if fwd[i] >= counterLimit || bwd[i] >= counterLimit {
				t.Fatalf("circuit %d: value on link %d is past the nonce limit", n, i)
			}
		}
	}
}

// the next base counter is the next value on every link, across the wrap too,
// so a window on any link sees a sequence that only grows
func TestLinkValuesStayConsecutive(t *testing.T) {
	for _, off := range []uint64{0, 1, counterLimit - 1, counterLimit - 2, 1 << 61} {
		for _, base := range []uint64{0, 1, cellLimit - 2} {
			a, b := shift(base, off), shift(base+1, off)
			if (b-a)&(counterLimit-1) != 1 {
				t.Fatalf("offset %#x, base %d: %#x then %#x", off, base, a, b)
			}
			if unshift(a, off) != base {
				t.Fatalf("offset %#x, base %d: unshift gives %#x", off, base, unshift(a, off))
			}
		}
	}
}

// a window of 64 on a link whose values cross the modulus: the order holds,
// copies and counters too old are refused on both sides of the wrap
func TestReplayWindowAcrossTheWrap(t *testing.T) {
	w := NewReplayWindow(64)
	start := counterLimit - 3
	for i := uint64(0); i < 6; i++ {
		if !w.Commit(shift(start, i)) {
			t.Fatalf("value %#x refused", shift(start, i))
		}
	}
	for i := uint64(0); i < 6; i++ {
		if w.Check(shift(start, i)) {
			t.Fatalf("copy of %#x accepted", shift(start, i))
		}
	}
	if !w.Commit(shift(start, 70)) {
		t.Fatal("a jump past the wrap refused")
	}
	if w.Check(shift(start, 6)) || w.Check(start) {
		t.Fatal("a value 64 or more behind accepted")
	}
	if !w.Check(shift(start, 7)) {
		t.Fatal("an unseen value 63 behind refused")
	}
}

// no value of one link lies cellLimit or more ahead of the first, and none at
// or past the nonce limit exists at all
func TestReplayWindowBounds(t *testing.T) {
	w := NewReplayWindow(64)
	first := counterLimit - 10
	if !w.Commit(first) {
		t.Fatal("first value refused")
	}
	if w.Check(shift(first, cellLimit)) {
		t.Fatal("a value cellLimit ahead of the first accepted")
	}
	if !w.Check(shift(first, cellLimit-1)) {
		t.Fatal("the last value before cellLimit refused")
	}
	for _, c := range []uint64{counterLimit, counterLimit + first, ^uint64(0)} {
		if w.Check(c) || w.Commit(c) {
			t.Fatalf("value %#x past the nonce limit accepted", c)
		}
	}
}
