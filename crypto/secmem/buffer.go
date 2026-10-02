package secmem

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var created atomic.Uint64

var (
	ErrReleased  = errors.New("secmem: buffer released")
	ErrNotLocked = errors.New("secmem: pages not locked")
)

// under the protected policy the key sits on pages of its own outside the Go
// heap, so it is released and zeroed at a known moment rather than whenever the
// collector happens to reuse the memory
type Buffer struct {
	mu       sync.RWMutex
	mem      []byte
	locked   bool
	released bool
	// the policy the buffer was made under, so a later change cannot free it
	// the wrong way
	policy Policy
	// order of creation, the order two buffers are locked in
	seq uint64
}

// where locking is unavailable Locked() reports false, so a caller that must not
// run unprotected can refuse to start
func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secmem: bad size %d", size)
	}
	p := CurrentPolicy()
	mem, locked, err := alloc(size, p)
	if err != nil {
		return nil, err
	}
	return &Buffer{mem: mem, locked: locked, policy: p, seq: created.Add(1)}, nil
}

// zeroes src: it exists to move key material off the heap the moment a library
// hands it over
func NewFrom(src []byte) (*Buffer, error) {
	b, err := New(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.mem, src)
	if b.policy.Zero {
		zero(src)
	}
	return b, nil
}

// the slice is valid until Release and must not be retained or appended to
func (b *Buffer) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.released {
		return nil
	}
	return b.mem
}

func (b *Buffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.mem)
}

func (b *Buffer) Locked() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.locked && !b.released
}

func (b *Buffer) Clone() (*Buffer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.released {
		return nil, ErrReleased
	}
	c, err := New(len(b.mem))
	if err != nil {
		return nil, err
	}
	copy(c.mem, b.mem)
	return c, nil
}

// constant time in the contents; a released buffer equals nothing
func (b *Buffer) Equal(other *Buffer) bool {
	if other == nil {
		return false
	}
	if b == other {
		b.mu.RLock()
		defer b.mu.RUnlock()
		return !b.released
	}
	// both stay read-locked while the memory is read, so a release cannot unmap
	// it under the comparison; one order for every pair, so two comparisons and
	// two releases cannot wait on each other
	first, second := b, other
	if second.seq < first.seq {
		first, second = second, first
	}
	first.mu.RLock()
	defer first.mu.RUnlock()
	second.mu.RLock()
	defer second.mu.RUnlock()
	if b.released || other.released {
		return false
	}
	return subtle.ConstantTimeCompare(b.mem, other.mem) == 1
}

// safe to call twice: deferred cleanup often runs after an explicit release on
// the error path
func (b *Buffer) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released {
		return
	}
	b.released = true
	free(b.mem, b.locked, b.policy)
	b.mem = nil
}
