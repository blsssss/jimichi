package wire

import "sync"

// a relay that forwards a replayed cell hands an active observer a free timing
// mark, so this is metadata protection and not only integrity
type ReplayWindow struct {
	mu     sync.Mutex
	size   uint64
	top    uint64 // highest counter seen
	bitmap map[uint64]struct{}
	seeded bool
}

// counters older than size behind the highest one are rejected: a delayed cell
// is cheaper to lose than a replay is to accept
func NewReplayWindow(size uint64) *ReplayWindow {
	if size == 0 {
		size = 1024
	}
	return &ReplayWindow{size: size, bitmap: make(map[uint64]struct{})}
}

func (w *ReplayWindow) Accept(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.seeded {
		w.seeded = true
		w.top = counter
		w.bitmap[counter] = struct{}{}
		return true
	}

	if counter+w.size <= w.top {
		return false
	}
	if _, seen := w.bitmap[counter]; seen {
		return false
	}

	w.bitmap[counter] = struct{}{}
	if counter > w.top {
		w.top = counter
	}
	for c := range w.bitmap {
		if c+w.size <= w.top {
			delete(w.bitmap, c)
		}
	}
	return true
}
