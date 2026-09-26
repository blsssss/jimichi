package metrics_test

import (
	"math"
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

// 4 cells for 2 messages is 2.0; 3 for 4 is 0.75; no messages is undefined
func TestMultiplierKnownAnswer(t *testing.T) {
	cases := []struct {
		cells, messages int
		want            float64
	}{
		{4, 2, 2},
		{3, 4, 0.75},
	}
	for _, c := range cases {
		if got := metrics.Multiplier(c.cells, c.messages); !near(got, c.want) {
			t.Fatalf("Multiplier(%d, %d) = %v, want %v", c.cells, c.messages, got, c.want)
		}
	}
	if got := metrics.Multiplier(5, 0); !math.IsNaN(got) {
		t.Fatalf("Multiplier(5, 0) = %v, want NaN", got)
	}
}

// samples 4, 1, 3, 2 ms sort to 1 2 3 4; position q*(n-1):
// median 1.5 -> 2 + 0.5*1 = 2.5 ms; p95 2.85 -> 3 + 0.85*1 = 3.85 ms;
// p99 2.97 -> 3.97 ms; p0 is the minimum and p100 the maximum
func TestPercentileKnownAnswer(t *testing.T) {
	ms := time.Millisecond
	samples := []time.Duration{4 * ms, 1 * ms, 3 * ms, 2 * ms}
	cases := []struct {
		q    float64
		want time.Duration
	}{
		{0.5, 2500 * time.Microsecond},
		{0.95, 3850 * time.Microsecond},
		{0.99, 3970 * time.Microsecond},
		{0, 1 * ms},
		{1, 4 * ms},
	}
	for _, c := range cases {
		got, ok := metrics.Percentile(samples, c.q)
		if !ok || got != c.want {
			t.Fatalf("Percentile(q=%v) = %v, %v; want %v", c.q, got, ok, c.want)
		}
	}
	if samples[0] != 4*ms {
		t.Fatal("Percentile reordered its input")
	}
	if got, ok := metrics.Percentile([]time.Duration{7 * ms}, 0.95); !ok || got != 7*ms {
		t.Fatalf("single sample: %v, %v", got, ok)
	}
	if _, ok := metrics.Percentile(nil, 0.5); ok {
		t.Fatal("Percentile of no samples must report false")
	}
}

// 0.9, 0.5, 0.7 sorts to 0.5 0.7 0.9, median 0.7; adding 0.6 gives
// 0.5 0.6 0.7 0.9, median (0.6 + 0.7) / 2 = 0.65; none is undefined
func TestMedianKnownAnswer(t *testing.T) {
	if got := metrics.Median([]float64{0.9, 0.5, 0.7}); !near(got, 0.7) {
		t.Fatalf("odd median = %v, want 0.7", got)
	}
	if got := metrics.Median([]float64{0.9, 0.5, 0.7, 0.6}); !near(got, 0.65) {
		t.Fatalf("even median = %v, want 0.65", got)
	}
	if got := metrics.Median(nil); !math.IsNaN(got) {
		t.Fatalf("median of nothing = %v, want NaN", got)
	}
	if _, ok := metrics.Percentile([]time.Duration{1}, math.NaN()); ok {
		t.Fatal("Percentile accepted a NaN quantile")
	}
}
