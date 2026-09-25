package relay

import (
	"math/rand/v2"
	"sync"
	"time"

	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/wire"
)

const defaultQueueCells = 64

type queued struct {
	cell *wire.Cell
	// replies from the exit are new cells, not forwarded ones
	forwarded bool
}

// sends one frame per tick on a clock of this node, so the timing a cell arrived
// with does not travel further along the chain
type pacer struct {
	out    *link.Conn
	period time.Duration
	queue  chan queued
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	stats  *Stats
}

func newPacer(out *link.Conn, period time.Duration, size int, stats *Stats) *pacer {
	if size <= 0 {
		size = defaultQueueCells
	}
	p := &pacer{
		out:    out,
		period: period,
		queue:  make(chan queued, size),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		stats:  stats,
	}
	go p.run()
	return p
}

// a full queue drops the cell: the node's own clock decides what the wire sees,
// so a burst from the client costs a loss and never a longer backlog
func (p *pacer) push(cell *wire.Cell, forwarded bool) bool {
	select {
	case p.queue <- queued{cell: cell, forwarded: forwarded}:
		return true
	default:
		return false
	}
}

func (p *pacer) run() {
	defer close(p.done)

	// setup crosses the chain within a millisecond, so a timer started with it
	// would share the client's phase; a random offset breaks that
	first := time.NewTimer(rand.N(p.period))
	select {
	case <-p.stop:
		first.Stop()
		return
	case <-first.C:
	}

	ticker := time.NewTicker(p.period)
	defer ticker.Stop()
	for {
		if err := p.send(); err != nil {
			// the link is broken; closing it lets the circuit teardown run the
			// same way it does for a failed read
			_ = p.out.Close()
			return
		}
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
	}
}

func (p *pacer) send() error {
	select {
	case q := <-p.queue:
		if err := p.out.WriteCell(q.cell); err != nil {
			return err
		}
		if q.forwarded {
			p.stats.add(&p.stats.Forwarded)
		}
		return nil
	default:
		if err := p.out.WritePadding(); err != nil {
			return err
		}
		p.stats.add(&p.stats.Padding)
		return nil
	}
}

// safe on a nil pacer, which is what a circuit without pacing holds
func (p *pacer) close() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.stop) })
	<-p.done
}
