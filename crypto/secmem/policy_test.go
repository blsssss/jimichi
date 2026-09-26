package secmem_test

import (
	"bytes"
	"testing"

	"github.com/blsssss/jimichi/crypto/secmem"
)

func TestParsePolicy(t *testing.T) {
	cases := []struct {
		in   string
		want secmem.Policy
	}{
		{"all", secmem.Protected},
		{"none", secmem.Baseline},
		{"offheap,zero", secmem.Policy{OffHeap: true, Zero: true}},
		{"offheap, lock", secmem.Policy{OffHeap: true, Lock: true}},
	}
	for _, c := range cases {
		got, err := secmem.ParsePolicy(c.in)
		if err != nil || got != c.want {
			t.Fatalf("ParsePolicy(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
		if back, _ := secmem.ParsePolicy(got.String()); back != got {
			t.Fatalf("%q does not round-trip through String", c.in)
		}
	}
	for _, bad := range []string{"lock", "dontdump,zero", "offheap,swap"} {
		if _, err := secmem.ParsePolicy(bad); err == nil {
			t.Fatalf("ParsePolicy(%q) accepted", bad)
		}
	}
	if err := secmem.SetPolicy(secmem.Policy{Lock: true}); err == nil {
		t.Fatal("SetPolicy accepted lock without offheap")
	}
}

// the baseline build keeps keys on the heap and leaves them in place: that is
// the reference the protected build is measured against
func TestBaselineNeitherLocksNorZeroes(t *testing.T) {
	defer func() { _ = secmem.SetPolicy(secmem.Protected) }()
	if err := secmem.SetPolicy(secmem.Baseline); err != nil {
		t.Fatal(err)
	}

	src := []byte{1, 2, 3, 4}
	b, err := secmem.NewFrom(src)
	if err != nil {
		t.Fatal(err)
	}
	if b.Locked() {
		t.Fatal("a baseline buffer reports locked")
	}
	if !bytes.Equal(src, []byte{1, 2, 3, 4}) {
		t.Fatal("baseline NewFrom zeroed its source")
	}
	mem := b.Bytes()
	b.Release()
	if !bytes.Equal(mem, []byte{1, 2, 3, 4}) {
		t.Fatal("baseline Release zeroed the key")
	}

	heap := []byte{5, 6}
	secmem.Zero(heap)
	if heap[0] != 5 {
		t.Fatal("baseline Zero cleared a heap copy")
	}
}

func TestProtectedZeroesOnRelease(t *testing.T) {
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	heap := []byte{5, 6}
	secmem.Zero(heap)
	if heap[0] != 0 || heap[1] != 0 {
		t.Fatal("Zero left key bytes in a heap copy")
	}
}
