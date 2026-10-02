package secmem_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestBufferLifecycle(t *testing.T) {
	b, err := secmem.New(64)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := b.Len(); got != 64 {
		t.Fatalf("Len = %d, want 64", got)
	}

	copy(b.Bytes(), bytes.Repeat([]byte{0xAA}, 64))
	if b.Bytes()[0] != 0xAA {
		t.Fatal("write did not stick")
	}

	b.Release()
	if b.Bytes() != nil {
		t.Fatal("Bytes after Release must be nil")
	}
	if b.Len() != 0 {
		t.Fatal("Len after Release must be 0")
	}
	b.Release() // must not panic
}

func TestNewFromZeroesSource(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	b, err := secmem.NewFrom(src)
	if err != nil {
		t.Fatalf("NewFrom: %v", err)
	}
	defer b.Release()

	if !bytes.Equal(b.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("contents = %v", b.Bytes())
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatalf("source not zeroed: %v", src)
	}
}

func TestClone(t *testing.T) {
	b, err := secmem.New(16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.Release()
	copy(b.Bytes(), bytes.Repeat([]byte{7}, 16))

	c, err := b.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer c.Release()

	if !bytes.Equal(b.Bytes(), c.Bytes()) {
		t.Fatal("clone differs from source")
	}
	c.Bytes()[0] = 9
	if b.Bytes()[0] == 9 {
		t.Fatal("clone shares memory with source")
	}

	b.Release()
	if _, err := b.Clone(); err != secmem.ErrReleased {
		t.Fatalf("Clone after Release: %v, want ErrReleased", err)
	}
}

func TestEqual(t *testing.T) {
	fill := func(size int, v byte) *secmem.Buffer {
		b, err := secmem.New(size)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(b.Release)
		copy(b.Bytes(), bytes.Repeat([]byte{v}, size))
		return b
	}
	a, same, shorter, last := fill(32, 7), fill(32, 7), fill(31, 7), fill(32, 7)
	last.Bytes()[31] ^= 1

	if !a.Equal(same) || !a.Equal(a) {
		t.Fatal("equal contents compare unequal")
	}
	if a.Equal(last) || a.Equal(shorter) || shorter.Equal(a) || a.Equal(nil) {
		t.Fatal("another content, another length or no buffer compares equal")
	}
	for i := 0; i < 32; i++ {
		for _, bit := range []byte{0x01, 0x80} {
			other := fill(32, 7)
			other.Bytes()[i] ^= bit
			if a.Equal(other) || other.Equal(a) {
				t.Fatalf("a buffer that differs in byte %d by %#02x compares equal", i, bit)
			}
		}
	}
	gone := fill(32, 7)
	gone.Release()
	if a.Equal(gone) || gone.Equal(a) || gone.Equal(gone) {
		t.Fatal("a released buffer compares equal")
	}
}

// a comparison holds the read locks of both buffers and a release waits for
// the write lock of one, after which no new reader gets in: were the two read
// locks taken in the order of the arguments, a.Equal(b) and b.Equal(a) would
// each hold one buffer and wait behind a release for the other
func TestEqualTakesItsLocksInOneOrder(t *testing.T) {
	a, err := secmem.New(32)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b, err := secmem.New(32)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wg sync.WaitGroup
	for _, f := range []func(){
		func() { a.Equal(b) },
		func() { b.Equal(a) },
		// takes the write lock on every call, also once the buffer is released
		a.Release,
		b.Release,
	} {
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 50000; i++ {
					f()
				}
			}()
		}
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("comparisons and releases of one pair wait on each other")
	}
}

// off the heap a release unmaps the pages, so a comparison still reading them
// would fault. The buffers are large and compared in a loop, and nothing is
// zeroed first, so the unmapping lands inside a comparison that did not hold
// its locks. Where buffers have no pages of their own, on systems other than
// Linux, the test only shows that a released buffer equals nothing
func TestEqualAgainstAConcurrentRelease(t *testing.T) {
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Policy{OffHeap: true}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secmem.SetPolicy(before) }()
	for round := 0; round < 50; round++ {
		a, err := secmem.New(1 << 20)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		b, err := secmem.New(1 << 20)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// fresh buffers are equal, so each comparison repeats until a release
		var comparing, wg sync.WaitGroup
		for _, pair := range [][2]*secmem.Buffer{{a, b}, {b, a}, {a, a}} {
			comparing.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !pair[0].Equal(pair[1]) {
					t.Error("two fresh buffers compare unequal")
				}
				comparing.Done()
				for pair[0].Equal(pair[1]) {
				}
			}()
		}
		comparing.Wait()
		for _, buf := range []*secmem.Buffer{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf.Release()
			}()
		}
		wg.Wait()
		if a.Equal(b) || b.Equal(a) || a.Equal(a) {
			t.Fatal("a released buffer compares equal")
		}
	}
}

func TestBadSize(t *testing.T) {
	if _, err := secmem.New(0); err == nil {
		t.Fatal("New(0) must fail")
	}
}
