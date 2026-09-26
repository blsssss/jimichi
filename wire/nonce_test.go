package wire

import (
	"bytes"
	"testing"
)

// the worst case for the top bit: backward direction, the last counter and a
// circuit id of all ones; MGM rejects a nonce whose top bit is set
func TestSixteenByteNonceKeepsTopBitClear(t *testing.T) {
	for _, dir := range []Direction{Forward, Backward} {
		for _, circuit := range []uint64{0, 1 << 63, ^uint64(0)} {
			n, err := nonceFor(16, dir, circuit, counterLimit-1)
			if err != nil {
				t.Fatalf("nonceFor: %v", err)
			}
			if n[0]&0x80 != 0 {
				t.Fatalf("dir %d circuit %x: top bit set in %x", dir, circuit, n)
			}
		}
	}
}

// the same circuit and counter in two directions must never share a nonce,
// in either layout
func TestNonceSeparatesDirections(t *testing.T) {
	for _, size := range []int{16, 24} {
		f, _ := nonceFor(size, Forward, 7, 9)
		b, _ := nonceFor(size, Backward, 7, 9)
		if bytes.Equal(f, b) {
			t.Fatalf("size %d: forward and backward nonces are equal", size)
		}
	}
	if _, err := nonceFor(16, Forward, 1, counterLimit); err == nil {
		t.Fatal("a counter at the limit must be refused")
	}
}
