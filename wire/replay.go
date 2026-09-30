package wire

import (
	"errors"
	"sync"
)

// a relay that forwards a replayed cell hands an active observer a free timing
// mark, so this is metadata protection and not only integrity
type ReplayWindow struct {
	mu     sync.Mutex
	size   uint64
	top    uint64 // highest counter recorded
	bits   []uint64
	seeded bool
}

// counters older than size behind the highest one are rejected: a delayed cell
// is cheaper to lose than a replay is to accept. The size is rounded up to a
// multiple of 64
func NewReplayWindow(size uint64) *ReplayWindow {
	if size == 0 {
		size = 1024
	}
	words := (size + 63) / 64
	return &ReplayWindow{size: words * 64, bits: make([]uint64, words)}
}

// Check says whether the counter would be accepted without recording it, so a
// cell that later fails authentication cannot move the window
func (w *ReplayWindow) Check(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fresh(counter)
}

// Commit records a counter whose cell has opened; false if it was taken since
func (w *ReplayWindow) Commit(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.fresh(counter) {
		return false
	}
	w.record(counter)
	return true
}

// Accept checks and records at once, for cells this node cannot authenticate,
// such as the ones it wraps on the way back
func (w *ReplayWindow) Accept(counter uint64) bool {
	return w.Commit(counter)
}

func (w *ReplayWindow) fresh(counter uint64) bool {
	if !w.seeded || counter > w.top {
		return true
	}
	if w.top-counter >= w.size {
		return false
	}
	return !w.has(counter)
}

func (w *ReplayWindow) record(counter uint64) {
	switch {
	case !w.seeded:
		w.seeded = true
		w.top = counter
	case counter > w.top:
		// slots between the old top and the new one belong to counters never
		// seen at this distance, so they start empty
		if counter-w.top >= w.size {
			clear(w.bits)
		} else {
			for c := w.top + 1; c < counter; c++ {
				w.unset(c)
			}
			w.unset(counter)
		}
		w.top = counter
	}
	w.set(counter)
}

func (w *ReplayWindow) slot(counter uint64) (int, uint64) {
	i := counter % w.size
	return int(i / 64), uint64(1) << (i % 64)
}

func (w *ReplayWindow) has(counter uint64) bool {
	word, bit := w.slot(counter)
	return w.bits[word]&bit != 0
}

func (w *ReplayWindow) set(counter uint64) {
	word, bit := w.slot(counter)
	w.bits[word] |= bit
}

func (w *ReplayWindow) unset(counter uint64) {
	word, bit := w.slot(counter)
	w.bits[word] &^= bit
}

type SetupTag [16]byte

const DefaultSetupCache = 1 << 16

var (
	ErrSetupReplay    = errors.New("wire: setup already seen")
	ErrSetupCacheFull = errors.New("wire: setup cache full")
)

// one setup cell carries the whole chain, so a copy accepted after the circuit
// is gone rebuilds it to the exit and recreates its hop keys with counters from
// zero; the tags must outlive every circuit built under the node key, so a full
// cache refuses new setups rather than forget a tag a replay could reuse
type SetupCache struct {
	mu   sync.Mutex
	max  int
	seen map[SetupTag]struct{}
}

func NewSetupCache(max int) *SetupCache {
	if max <= 0 {
		max = DefaultSetupCache
	}
	return &SetupCache{max: max, seen: make(map[SetupTag]struct{})}
}

// Add records a tag whose setup layer has opened
func (c *SetupCache) Add(tag SetupTag) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[tag]; ok {
		return ErrSetupReplay
	}
	if len(c.seen) >= c.max {
		return ErrSetupCacheFull
	}
	c.seen[tag] = struct{}{}
	return nil
}
