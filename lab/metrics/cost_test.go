package metrics_test

import (
	"testing"
	"time"

	"github.com/blsssss/jimichi/lab/metrics"
)

// hand counted with a 10 ms window: flow one has 0, 5 and 9.999 ms inside and
// 10 ms on the boundary outside; flow two has 3 ms inside and 12 ms outside;
// flow three is empty. 3 + 1 + 0 = 4
func TestCellsWithinKnownAnswer(t *testing.T) {
	ms := time.Millisecond
	traces := [][]time.Duration{
		{0, 5 * ms, 9999 * time.Microsecond, 10 * ms},
		{3 * ms, 12 * ms},
		nil,
	}
	if got := metrics.CellsWithin(traces, 10*ms); got != 4 {
		t.Fatalf("CellsWithin = %d, want 4", got)
	}
	if got := metrics.CellsWithin(nil, 10*ms); got != 0 {
		t.Fatalf("CellsWithin(nil) = %d, want 0", got)
	}
}

// 4 cells for 2 messages is 2.0; 3 for 4 is 0.75; no messages gives 0
func TestMultiplierKnownAnswer(t *testing.T) {
	cases := []struct {
		cells, messages int
		want            float64
	}{
		{4, 2, 2},
		{3, 4, 0.75},
		{5, 0, 0},
	}
	for _, c := range cases {
		if got := metrics.Multiplier(c.cells, c.messages); !near(got, c.want) {
			t.Fatalf("Multiplier(%d, %d) = %v, want %v", c.cells, c.messages, got, c.want)
		}
	}
}
