package wire

import (
	"errors"
	"sync"
)

// a relay that forwards a replayed cell hands an active observer a free timing
// mark, so this is metadata protection and not only integrity
type ReplayWindow struct {
	mu   sync.Mutex
	size uint64
	top  uint64 // highest counter recorded, as it came off the wire
	// counters wrap at the nonce limit, so the window keeps them on a line of
	// its own where the order is plain; pos is where top sits on it
	pos    uint64
	bits   []uint64
	seeded bool
}

// high enough that a counter behind the first one still lands on the line
const origin = counterLimit

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

// place puts a counter on the line: of the two ways round the modulus the
// shorter one says whether it is ahead of top or behind it. Values of one link
// stay within cellLimit of the first, so the shorter way is always the true
// one, and a counter further ahead has no place at all
func (w *ReplayWindow) place(counter uint64) (uint64, bool) {
	if counter >= counterLimit {
		return 0, false
	}
	if !w.seeded {
		return origin, true
	}
	d := (counter - w.top) & (counterLimit - 1)
	if d < counterLimit/2 {
		p := w.pos + d
		return p, p-origin < cellLimit
	}
	return w.pos - (counterLimit - d), true
}

func (w *ReplayWindow) fresh(counter uint64) bool {
	p, ok := w.place(counter)
	if !ok {
		return false
	}
	if !w.seeded || p > w.pos {
		return true
	}
	if w.pos-p >= w.size {
		return false
	}
	return !w.has(p)
}

func (w *ReplayWindow) record(counter uint64) {
	p, _ := w.place(counter)
	switch {
	case !w.seeded:
		w.seeded = true
		w.top, w.pos = counter, p
	case p > w.pos:
		// slots between the old top and the new one belong to counters never
		// seen at this distance, so they start empty
		if p-w.pos >= w.size {
			clear(w.bits)
		} else {
			for q := w.pos + 1; q < p; q++ {
				w.unset(q)
			}
			w.unset(p)
		}
		w.top, w.pos = counter, p
	}
	w.set(p)
}

func (w *ReplayWindow) slot(p uint64) (int, uint64) {
	i := p % w.size
	return int(i / 64), uint64(1) << (i % 64)
}

func (w *ReplayWindow) has(p uint64) bool {
	word, bit := w.slot(p)
	return w.bits[word]&bit != 0
}

func (w *ReplayWindow) set(p uint64) {
	word, bit := w.slot(p)
	w.bits[word] |= bit
}

func (w *ReplayWindow) unset(p uint64) {
	word, bit := w.slot(p)
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
