package metrics_test

import (
	"math"
	"testing"
	"time"

	"github.com/blsssss/jimichi/lab/metrics"
)

const eps = 1e-9

func near(a, b float64) bool { return math.Abs(a-b) < eps }

func scored(pos, neg []float64) []metrics.Score {
	out := make([]metrics.Score, 0, len(pos)+len(neg))
	for _, v := range pos {
		out = append(out, metrics.Score{Value: v, True: true})
	}
	for _, v := range neg {
		out = append(out, metrics.Score{Value: v})
	}
	return out
}

// hand computed: of the four positive-negative pairs, three are ordered
// correctly (0.9>0.5, 0.9>0.1, 0.4>0.1) and one is not (0.4<0.5), so 3/4
func TestAUCKnownAnswer(t *testing.T) {
	cases := []struct {
		name     string
		pos, neg []float64
		want     float64
	}{
		{"perfect", []float64{0.9, 0.8}, []float64{0.2, 0.1}, 1},
		{"inverted", []float64{0.1, 0.2}, []float64{0.8, 0.9}, 0},
		{"all ties", []float64{0.5, 0.5}, []float64{0.5, 0.5}, 0.5},
		{"three of four", []float64{0.9, 0.4}, []float64{0.5, 0.1}, 0.75},
		// a tie between a positive and a negative counts as half a pair: 1.5/2
		{"half tie", []float64{0.7}, []float64{0.7, 0.2}, 0.75},
	}
	for _, c := range cases {
		if got := metrics.AUC(scored(c.pos, c.neg)); !near(got, c.want) {
			t.Errorf("%s: AUC = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAUCUndefinedWithoutBothClasses(t *testing.T) {
	if !math.IsNaN(metrics.AUC(scored([]float64{0.3}, nil))) {
		t.Fatal("AUC without negatives must be NaN, not a number that looks like a result")
	}
}

func TestPearsonKnownAnswer(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5}
	cases := []struct {
		name string
		b    []float64
		want float64
	}{
		{"identical", []float64{1, 2, 3, 4, 5}, 1},
		{"scaled and shifted", []float64{10, 12, 14, 16, 18}, 1},
		{"negated", []float64{5, 4, 3, 2, 1}, -1},
		{"constant has no correlation", []float64{3, 3, 3, 3, 3}, 0},
		// deviations of a: -2 -1 0 1 2; of b (mean 2.8): -0.8 -1.8 1.2 0.2 1.2
		// cross sum 6, squares 10 and 6.8, so r = 6 / sqrt(68)
		{"hand computed", []float64{2, 1, 4, 3, 4}, 6 / math.Sqrt(10*6.8)},
	}
	for _, c := range cases {
		if got := metrics.Pearson(a, c.b); !near(got, c.want) {
			t.Errorf("%s: r = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBinCountsEveryEventOnce(t *testing.T) {
	events := []time.Duration{0, 50 * time.Millisecond, 100 * time.Millisecond, 950 * time.Millisecond}
	bins := metrics.Bin(events, time.Second, 100*time.Millisecond)
	if len(bins) != 11 {
		t.Fatalf("bins = %d, want 11", len(bins))
	}
	want := map[int]float64{0: 2, 1: 1, 9: 1}
	total := 0.0
	for i, v := range bins {
		total += v
		if v != want[i] {
			t.Errorf("bin %d = %v, want %v", i, v, want[i])
		}
	}
	if total != float64(len(events)) {
		t.Fatalf("binned %v events, want %d", total, len(events))
	}
}

// with ten negatives, FPR 0.1 allows exactly one false positive: the positives
// ranked above the second negative are the ones found
func TestTPRAtFPR(t *testing.T) {
	pos := []float64{0.95, 0.9, 0.6, 0.3}
	neg := []float64{0.92, 0.8, 0.5, 0.4, 0.35, 0.2, 0.15, 0.1, 0.05, 0.01}
	if got := metrics.TPRAtFPR(scored(pos, neg), 0.1); !near(got, 0.5) {
		t.Fatalf("TPR at FPR 0.1 = %v, want 0.5", got)
	}
	if got := metrics.TPRAtFPR(scored(pos, neg), 0); !near(got, 0.25) {
		t.Fatalf("TPR at FPR 0 = %v, want 0.25", got)
	}
}

func matrixScores(m [][]float64) []metrics.Score {
	var out []metrics.Score
	for i, row := range m {
		for j, v := range row {
			out = append(out, metrics.Score{Entry: i, Exit: j, Value: v, True: i == j})
		}
	}
	return out
}

func TestTopOneAccuracy(t *testing.T) {
	m := [][]float64{
		{0.9, 0.1, 0.2},
		{0.3, 0.2, 0.8},
		{0.1, 0.2, 0.7},
	}
	if got := metrics.TopOneAccuracy(matrixScores(m), 3); !near(got, 2.0/3) {
		t.Fatalf("top-1 = %v, want 2/3", got)
	}
}

func TestBootstrapBracketsThePoint(t *testing.T) {
	m := [][]float64{
		{0.9, 0.2, 0.1, 0.3},
		{0.4, 0.8, 0.3, 0.2},
		{0.2, 0.5, 0.6, 0.1},
		{0.3, 0.1, 0.4, 0.7},
	}
	ci := metrics.BootstrapAUC(matrixScores(m), 4, 2000, 1)
	if ci.Low > ci.Point || ci.High < ci.Point {
		t.Fatalf("interval [%v, %v] does not contain the point %v", ci.Low, ci.High, ci.Point)
	}
	if ci.Low < 0 || ci.High > 1 {
		t.Fatalf("interval [%v, %v] leaves [0, 1]", ci.Low, ci.High)
	}

	perfect := [][]float64{{1, 0}, {0, 1}}
	ci = metrics.BootstrapAUC(matrixScores(perfect), 2, 500, 1)
	if !near(ci.Point, 1) || !near(ci.Low, 1) || !near(ci.High, 1) {
		t.Fatalf("perfect separation must give [1, 1], got %+v", ci)
	}
}

func TestBootstrapIsReproducible(t *testing.T) {
	m := [][]float64{{0.9, 0.2, 0.4}, {0.3, 0.6, 0.5}, {0.4, 0.3, 0.2}}
	a := metrics.BootstrapAUC(matrixScores(m), 3, 1000, 42)
	b := metrics.BootstrapAUC(matrixScores(m), 3, 1000, 42)
	if a != b {
		t.Fatalf("same seed gave %+v and %+v", a, b)
	}
}
