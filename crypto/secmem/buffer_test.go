package secmem_test

import (
	"bytes"
	"testing"

	"github.com/blsssss/jimichi/crypto/secmem"
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

func TestBadSize(t *testing.T) {
	if _, err := secmem.New(0); err == nil {
		t.Fatal("New(0) must fail")
	}
}
