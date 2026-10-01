package wire

import (
	"errors"
	"sync"
)

// a relay that let a copied, lost or reordered cell pass would hand the nodes
// after it a mark they could see, so a link takes counters strictly one after
// another; the first is taken as it comes, since it depends on the offsets of
// hops this node does not know. A Sequence belongs to the one goroutine that
// reads its link
type Sequence struct {
	next   uint64
	taken  uint64
	seeded bool
}

// Expect fixes the first value instead of taking it from the first cell
func (s *Sequence) Expect(first uint64) {
	s.seeded = true
	s.next = first
}

// Next reports whether counter is the one due and takes it if so. No more than
// cellLimit values are taken, so a link never comes round the modulus to a
// value it has carried already
func (s *Sequence) Next(counter uint64) bool {
	if counter >= counterLimit || s.taken >= cellLimit {
		return false
	}
	if s.seeded && counter != s.next {
		return false
	}
	s.seeded = true
	s.next = shift(counter, 1)
	s.taken++
	return true
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
