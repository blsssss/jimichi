package lab

import (
	"net"
	"sync"
	"time"
)

// what a passive observer on one link can see: the moment a cell crossed it.
// nothing else is recorded, because nothing else is visible from the wire
type Trace struct {
	mu     sync.Mutex
	start  time.Time
	events []time.Duration
}

func NewTrace(start time.Time) *Trace { return &Trace{start: start} }

func (t *Trace) Mark(at time.Time) {
	t.mu.Lock()
	t.events = append(t.events, at.Sub(t.start))
	t.mu.Unlock()
}

func (t *Trace) Events() []time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]time.Duration, len(t.events))
	copy(out, t.events)
	return out
}

func (t *Trace) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events)
}

// counts whole frames as they pass: after the link handshake the wire carries
// nothing but encrypted frames of one size, so a frame is all the observer sees
type tappedConn struct {
	net.Conn
	trace   *Trace
	skip    int
	frame   int
	pending int
}

func (c *tappedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.count(n)
	return n, err
}

func (c *tappedConn) count(n int) {
	now := time.Now()
	if c.skip > 0 {
		used := n
		if used > c.skip {
			used = c.skip
		}
		c.skip -= used
		n -= used
	}
	c.pending += n
	for c.pending >= c.frame {
		c.pending -= c.frame
		c.trace.Mark(now)
	}
}
