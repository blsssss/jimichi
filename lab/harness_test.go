package lab

import (
	"testing"
	"time"
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
	if run.RelayDropped != 0 {
		t.Fatalf("relays dropped %d cells on an idle run", run.RelayDropped)
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
