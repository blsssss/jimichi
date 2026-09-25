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
	}
}
