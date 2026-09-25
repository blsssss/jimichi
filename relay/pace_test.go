package relay

import (
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/wire"
)

// net.Pipe is synchronous, so the far side must be closed before the pacer is
// stopped, or a pending write would hold it forever
func pacedPipe(t *testing.T, period time.Duration, size int) (*pacer, net.Conn, *Stats) {
	t.Helper()
	p := c25519.New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()

	a, b := net.Pipe()
	accepted := make(chan error, 1)
	go func() {
		_, err := link.Accept(b, p, priv)
		accepted <- err
	}()
	out, err := link.Dial(a, p, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}

	stats := &Stats{}
	pc := newPacer(out, period, size, stats)
	t.Cleanup(func() {
		_ = b.Close()
		pc.close()
		_ = out.Close()
	})
	return pc, b, stats
}

// frame arrival times on the far side of a paced link, padding included
func frameTimes(t *testing.T, raw net.Conn, frame int, want int, limit time.Duration) []time.Time {
	t.Helper()
	times := make([]time.Time, 0, want)
	buf := make([]byte, frame)
	deadline := time.Now().Add(limit)
	_ = raw.SetReadDeadline(deadline)
	got := 0
	for len(times) < want {
		n, err := raw.Read(buf[got:])
		if err != nil {
			t.Fatalf("read after %d frames: %v", len(times), err)
		}
		got += n
		if got == frame {
			times = append(times, time.Now())
			got = 0
		}
	}
	return times
}

// the first tick is the only thing that ties a node's clock to the moment the
// circuit was set up; if it were not random, every node would share the
// client's phase and pacing would change nothing
func TestFirstTickIsSpreadOverThePeriod(t *testing.T) {
	const pacers = 16
	period := 80 * time.Millisecond
	frame, _ := link.FrameSize(c25519.New())

	start := time.Now()
	firsts := make([]time.Duration, pacers)
	var wg sync.WaitGroup
	for i := 0; i < pacers; i++ {
		_, raw, _ := pacedPipe(t, period, 4)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := make([]byte, frame)
			got := 0
			for got < frame {
				n, err := raw.Read(buf[got:])
				if err != nil {
					return
				}
				got += n
			}
			firsts[i] = time.Since(start)
		}(i)
	}
	wg.Wait()

	lo, hi := firsts[0], firsts[0]
	for _, f := range firsts {
		if f == 0 {
			t.Fatal("a pacer never sent its first frame")
		}
		lo, hi = min(lo, f), max(hi, f)
	}
	// 16 uniform draws all inside a quarter of the period: probability 16 * 0.25^15
	if hi-lo < period/4 {
		t.Fatalf("first frames spread over %v, want at least %v of an %v period", hi-lo, period/4, period)
	}
}

// a burst from the previous hop leaves at the node's own pace, not as a burst
func TestBurstLeavesOnePerTick(t *testing.T) {
	period := 20 * time.Millisecond
	frame, _ := link.FrameSize(c25519.New())
	p, raw, stats := pacedPipe(t, period, 64)

	body := make([]byte, wire.BodySize)
	for i := 0; i < 30; i++ {
		cell, err := wire.NewCell(wire.Header{Kind: wire.KindPayload, Counter: uint64(i)}, body)
		if err != nil {
			t.Fatal(err)
		}
		if !p.push(cell, true) {
			t.Fatalf("queue refused cell %d", i)
		}
	}

	times := frameTimes(t, raw, frame, 31, 5*time.Second)
	span := times[len(times)-1].Sub(times[0])
	// 30 gaps of one period; a burst forwarded at once would take microseconds
	if span < 20*period {
		t.Fatalf("31 frames left within %v, want about %v", span, 30*period)
	}
	checkGaps(t, times, period)
	if s := stats.Snapshot(); s.Forwarded != 30 {
		t.Fatalf("forwarded %d cells, want 30", s.Forwarded)
	}
}

func TestIdleLinkCarriesPadding(t *testing.T) {
	period := 10 * time.Millisecond
	frame, _ := link.FrameSize(c25519.New())
	p, raw, stats := pacedPipe(t, period, 4)

	checkGaps(t, frameTimes(t, raw, frame, 11, 5*time.Second), period)
	_ = raw.Close()
	p.close()
	s := stats.Snapshot()
	if s.Padding < 11 || s.Forwarded != 0 {
		t.Fatalf("padding %d, forwarded %d; want at least 11 padding frames and nothing forwarded", s.Padding, s.Forwarded)
	}
}

func TestFullQueueRefuses(t *testing.T) {
	p, _, _ := pacedPipe(t, time.Hour, 2)

	body := make([]byte, wire.BodySize)
	cell, _ := wire.NewCell(wire.Header{Kind: wire.KindPayload}, body)
	if !p.push(cell, true) || !p.push(cell, true) {
		t.Fatal("queue refused a cell below its size")
	}
	if p.push(cell, true) {
		t.Fatal("queue took a cell above its size")
	}
}

// close must return even while the pacer waits for a first tick an hour away
func TestCloseDoesNotWaitForTheTick(t *testing.T) {
	p, _, _ := pacedPipe(t, time.Hour, 2)
	done := make(chan struct{})
	go func() {
		p.close()
		p.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close blocked")
	}
}

// what the wire shows must not depend on how much the previous hop sent: a
// queue overflowing still yields exactly one frame per tick
func TestOverfullQueueKeepsOneFramePerTick(t *testing.T) {
	period := 20 * time.Millisecond
	frame, _ := link.FrameSize(c25519.New())
	p, raw, stats := pacedPipe(t, period, 4)

	body := make([]byte, wire.BodySize)
	accepted := 0
	for i := 0; i < 30; i++ {
		cell, _ := wire.NewCell(wire.Header{Kind: wire.KindPayload, Counter: uint64(i)}, body)
		if p.push(cell, true) {
			accepted++
		}
	}
	// the first tick may already have taken one cell off the queue
	if accepted < 4 || accepted > 5 {
		t.Fatalf("queue of 4 took %d cells", accepted)
	}

	times := frameTimes(t, raw, frame, 16, 5*time.Second)
	if span := times[len(times)-1].Sub(times[0]); span < 10*period {
		t.Fatalf("16 frames left within %v, want about %v", span, 15*period)
	}
	s := stats.Snapshot()
	if s.Forwarded != uint64(accepted) || s.Padding < 10 {
		t.Fatalf("forwarded %d, padding %d; want %d forwarded and the rest padding", s.Forwarded, s.Padding, accepted)
	}
}

// a scheduler hiccup may stretch one gap and shorten the next, so the check
// is on the median and on most gaps rather than on every one
func checkGaps(t *testing.T, times []time.Time, period time.Duration) {
	t.Helper()
	gaps := make([]time.Duration, 0, len(times)-1)
	within := 0
	for i := 1; i < len(times); i++ {
		g := times[i].Sub(times[i-1])
		gaps = append(gaps, g)
		if g >= period/2 && g <= period*3/2 {
			within++
		}
	}
	slices.Sort(gaps)
	median := gaps[len(gaps)/2]
	if median < period*8/10 || median > period*12/10 {
		t.Fatalf("median gap %v, want within 20%% of %v", median, period)
	}
	if within*10 < len(gaps)*9 {
		t.Fatalf("%d of %d gaps within half a period of %v", within, len(gaps), period)
	}
}
