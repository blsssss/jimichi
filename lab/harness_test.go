package lab

import (
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/relay"
)

// in immediate mode every cell on the entry link crosses the observed link
// once, so a flow's two traces hold the same number of frames; flows draw
// their own random gaps, so a swapped pair shows up as a count mismatch
func TestExitTracesMatchTheirFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live chain for seconds")
	}
	run, err := Execute(Config{Flows: 6, Duration: 2 * time.Second, SendEvery: 40 * time.Millisecond, Seed: 3})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(run.Exit) != len(run.Entry) {
		t.Fatalf("%d exit traces for %d flows", len(run.Exit), len(run.Entry))
	}
	if run.RelayTimedOut != 0 || run.RelayExpired != 0 || run.RelayRefused != 0 {
		t.Fatalf("relay limits acted on a plain run: %d timed out, %d expired, %d refused",
			run.RelayTimedOut, run.RelayExpired, run.RelayRefused)
	}
	for i := range run.Entry {
		in, out := run.Entry[i].Len(), run.Exit[i].Len()
		if in != out {
			t.Fatalf("flow %d: %d frames at the entry, %d at the exit", i, in, out)
		}
		// every message is echoed, so the replies cross both links backwards
		back, exitBack := run.EntryBack[i].Len(), run.ExitBack[i].Len()
		if back != exitBack || back == 0 {
			t.Fatalf("flow %d: %d replies at the entry, %d at the exit", i, back, exitBack)
		}
	}
}

// one flow, sent at once and without cover: n messages are n cells out and,
// echoed by the exit, n cells back. Forwards each tap counts n+1 frames after
// the initiator's hello, the setup and the n cells. Backwards it counts n: the
// responder of a link first sends its key and one frame that confirms the
// handshake, and a tap that took that frame for traffic would count n+1
func TestTapsCountTheCellsOfAFlowWithoutTheHandshake(t *testing.T) {
	run, err := Execute(Config{Flows: 1, Duration: 300 * time.Millisecond, SendEvery: 20 * time.Millisecond, Seed: 11})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	n := run.Sent
	if n == 0 || len(run.Latency) != n || run.Unanswered != 0 {
		t.Fatalf("%d messages sent, %d echoes back, %d unanswered; want every message of a quiet run echoed",
			n, len(run.Latency), run.Unanswered)
	}
	if len(run.Exit) != 1 || len(run.ExitBack) != 1 {
		t.Fatalf("%d and %d exit traces for one flow", len(run.Exit), len(run.ExitBack))
	}
	for _, tc := range []struct {
		name  string
		trace *Trace
		want  int
	}{
		{"entry", run.Entry[0], n + 1},
		{"exit", run.Exit[0], n + 1},
		{"entry back", run.EntryBack[0], n},
		{"exit back", run.ExitBack[0], n},
	} {
		if got := tc.trace.Len(); got != tc.want {
			t.Errorf("%s: %d frames for %d messages, want %d", tc.name, got, n, tc.want)
		}
	}
}

// a paced chain keeps both directions of both links busy while flows are quiet
func TestPacedRunFillsBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live chain for seconds")
	}
	period := 20 * time.Millisecond
	run, err := Execute(Config{Flows: 2, Duration: time.Second, SendEvery: 500 * time.Millisecond, RelayPeriod: period, Seed: 5})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// one second at 20 ms is 50 ticks; the setup frame and timer slack aside,
	// every direction but the client's own should carry at least 40
	for i := range run.Entry {
		for name, tr := range map[string]*Trace{"entry back": run.EntryBack[i], "exit": run.Exit[i], "exit back": run.ExitBack[i]} {
			if n := tr.Len(); n < 40 {
				t.Fatalf("flow %d %s: %d frames in a second of 20 ms ticks", i, name, n)
			}
		}
	}
	if run.RelayDropped != 0 || run.RelayBroken != 0 || run.BrokenFlows != 0 {
		t.Fatalf("relays dropped %d cells and closed %d circuits, %d clients closed theirs on an idle run", run.RelayDropped, run.RelayBroken, run.BrokenFlows)
	}
	if len(run.Closures) != 2 || run.Closures[0].Closed || run.Closures[1].Closed {
		t.Fatalf("closures %+v on an idle run, want two open flows", run.Closures)
	}
}

// relays ticking at 10 ms while a flow sends every millisecond on average fill
// their queues at once: every circuit closes, and each flow's client records
// when, after the flows started
func TestClosedCircuitsReachTheRun(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a live chain for seconds")
	}
	run, err := Execute(Config{Flows: 2, Duration: 2 * time.Second, SendEvery: time.Millisecond, RelayPeriod: 10 * time.Millisecond, Seed: 7})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.RelayBroken == 0 {
		t.Fatal("no relay closed a circuit under a load its queues cannot hold")
	}
	if len(run.Closures) != 2 {
		t.Fatalf("%d closures for 2 flows", len(run.Closures))
	}
	for i, c := range run.Closures {
		if !c.Closed || c.At < run.Origin {
			t.Fatalf("flow %d: %+v, want closed after the flows started at %v", i, c, run.Origin)
		}
	}
}

// skip 3, frame 4, reads of 2, 3, 4, 1 and 6 bytes: the first read and one
// byte of the second are handshake, then 2, 6, 3 and 9 bytes pending, which
// completes a frame on the third read and two more on the fifth
func TestCounterSkipsHandshakeAndCountsFrames(t *testing.T) {
	tr := NewTrace(time.Now())
	c := &counter{trace: tr, skip: 3, frame: 4}
	for _, n := range []int{2, 3, 4, 1, 6} {
		c.count(n)
	}
	if got := tr.Len(); got != 3 || c.pending != 1 {
		t.Fatalf("%d frames with %d bytes pending, want 3 and 1", got, c.pending)
	}
}

// two relays with the same counters: dropped 1+1, closed circuits 4+4, timed out
// 2+2, expired 3+3, refused (1+1+1+1+1)+(1+1+1+1+1)
func TestRelayLimitsReachTheRun(t *testing.T) {
	var run Run
	c := relay.Counters{Dropped: 1, Broken: 4, TimedOut: 2, Expired: 3,
		RefusedLinks: 1, RefusedBusy: 1, RefusedSource: 1, RefusedRate: 1, RefusedSetups: 1}
	run.addRelay(c)
	run.addRelay(c)
	if run.RelayDropped != 2 || run.RelayBroken != 8 || run.RelayTimedOut != 4 || run.RelayExpired != 6 || run.RelayRefused != 10 {
		t.Fatalf("dropped %d, closed %d, timed out %d, expired %d, refused %d; want 2, 8, 4, 6, 10",
			run.RelayDropped, run.RelayBroken, run.RelayTimedOut, run.RelayExpired, run.RelayRefused)
	}
}
