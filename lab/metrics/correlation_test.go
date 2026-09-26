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

func TestPearsonUndefinedWithoutVariation(t *testing.T) {
	if r := metrics.Pearson([]float64{1, 2, 3}, []float64{4, 4, 4}); !math.IsNaN(r) {
		t.Fatalf("a constant series has no correlation to report, got %v", r)
	}
}

// window 1 s, bin 100 ms: ten bins over [0, 1 s). 0 and 50 ms land in bin 0,
// 100 ms in bin 1, 950 ms and 1 s minus 1 ns in bin 9; 1 s itself and 1.05 s
// are outside the window, as they are for CellsWithin. 5 of 7 are counted
func TestBinCountsInsideTheWindowOnly(t *testing.T) {
	ms := time.Millisecond
	events := []time.Duration{0, 50 * ms, 100 * ms, 950 * ms, time.Second - 1, time.Second, 1050 * ms}
	bins := metrics.Bin(events, time.Second, 100*ms)
	if len(bins) != 10 {
		t.Fatalf("bins = %d, want 10", len(bins))
	}
	want := map[int]float64{0: 2, 1: 1, 9: 2}
	total := 0.0
	for i, v := range bins {
		total += v
		if v != want[i] {
			t.Errorf("bin %d = %v, want %v", i, v, want[i])
		}
	}
	if total != 5 {
		t.Fatalf("binned %v events, want 5", total)
	}
	if n := metrics.CellsWithin([][]time.Duration{events}, time.Second); n != 5 {
		t.Fatalf("CellsWithin counts %d of the same events, want 5", n)
	}
}

// window 250 ms, bin 100 ms: three bins, the last covering [200, 250) ms only;
// 240 ms is in it and 260 ms is not
func TestBinShortLastBin(t *testing.T) {
	ms := time.Millisecond
	bins := metrics.Bin([]time.Duration{240 * ms, 260 * ms}, 250*ms, 100*ms)
	if len(bins) != 3 || bins[2] != 1 || bins[0]+bins[1] != 0 {
		t.Fatalf("bins = %v, want [0 0 1]", bins)
	}
}

// one flow of each kind: entry 0 varies and pairs with a varying exit (defined)
// and with a constant exit (undefined); entry 1 is constant, so both of its
// pairs are undefined. 3 of 4
func TestUndefinedPairsKnownAnswer(t *testing.T) {
	entry := [][]float64{{1, 2, 3}, {5, 5, 5}}
	exit := [][]float64{{1, 2, 4}, {7, 7, 7}}
	scores := metrics.ScorePairs(entry, exit, map[int]int{0: 0, 1: 1})
	if n := metrics.UndefinedPairs(scores); n != 3 {
		t.Fatalf("UndefinedPairs = %d, want 3", n)
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

// positives 0.9 and 0.5, negatives 0.5 and 0.1. the curve goes (0,0) to (0,0.5)
// at 0.9, then the tie at 0.5 moves it straight to (0.5,1). at FPR 0.25 the
// straight segment gives 0.5 + 0.5 * 0.5 = 0.75
func TestTPRInterpolatesAcrossATie(t *testing.T) {
	if got := metrics.TPRAtFPR(scored([]float64{0.9, 0.5}, []float64{0.5, 0.1}), 0.25); !near(got, 0.75) {
		t.Fatalf("TPR at FPR 0.25 = %v, want 0.75", got)
	}
}

// when every pair looks the same the adversary can only guess: the curve is the
// diagonal, so TPR equals FPR, AUC is one half and top-1 is one in N
func TestAllTiedIsChance(t *testing.T) {
	m := [][]float64{{0.3, 0.3, 0.3}, {0.3, 0.3, 0.3}, {0.3, 0.3, 0.3}}
	s := matrixScores(m)
	if got := metrics.AUC(s); !near(got, 0.5) {
		t.Errorf("AUC = %v, want 0.5", got)
	}
	for _, fpr := range []float64{0.01, 0.1, 0.5} {
		if got := metrics.TPRAtFPR(s, fpr); !near(got, fpr) {
			t.Errorf("TPR at FPR %v = %v, want %v", fpr, got, fpr)
		}
	}
	if got := metrics.TopOneAccuracy(s, 3); !near(got, 1.0/3) {
		t.Errorf("top-1 = %v, want 1/3", got)
	}
}

// entry 0 ties its own exit with one other exit: half a hit; entry 1 is found;
// entry 2 prefers a wrong exit. (0.5 + 1 + 0) / 3 = 0.5
func TestTopOneBreaksTiesAtRandom(t *testing.T) {
	m := [][]float64{
		{0.8, 0.8, 0.1},
		{0.2, 0.9, 0.3},
		{0.6, 0.1, 0.4},
	}
	if got := metrics.TopOneAccuracy(matrixScores(m), 3); !near(got, 0.5) {
		t.Fatalf("top-1 = %v, want 0.5", got)
	}
}

func TestScorePairsTreatsUndefinedAsTie(t *testing.T) {
	flat := []float64{1, 1, 1, 1}
	s := metrics.ScorePairs([][]float64{flat, flat}, [][]float64{flat, flat}, map[int]int{0: 0, 1: 1})
	if got := metrics.AUC(s); !near(got, 0.5) {
		t.Fatalf("flat series must leave the observer at chance, AUC = %v", got)
	}
}

// the second exit series is 3x + 1 of the first, so in exact arithmetic both
// pairs have the same correlation while the floating point results differ in
// the last bits; they must still rank as a tie
func TestRoundingNoiseIsATie(t *testing.T) {
	base := []float64{0.1, 0.7, 0.2, 0.9, 0.3, 0.45, 0.05}
	stretched := make([]float64, len(base))
	for i, v := range base {
		stretched[i] = 3*v + 1
	}
	entry := [][]float64{{0.3, 0.5, 0.1, 0.8, 0.2, 0.6, 0.15}}
	exit := [][]float64{base, stretched}
	if raw0, raw1 := metrics.Pearson(entry[0], base), metrics.Pearson(entry[0], stretched); raw0 == raw1 {
		t.Log("this platform computed both correlations bit-identically; rounding is not exercised")
	}
	s := metrics.ScorePairs(entry, exit, map[int]int{0: 0})
	if s[0].Value != s[1].Value {
		t.Fatalf("identical pairs scored %v and %v", s[0].Value, s[1].Value)
	}
	if got := metrics.TopOneAccuracy(s, 1); !near(got, 0.5) {
		t.Fatalf("top-1 = %v, want 0.5 for a two-way tie", got)
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
	ci := metrics.BootstrapAUC(matrixScores(m), 4, 10000, 1)
	if ci.Method != "bca" {
		t.Fatalf("method = %q, want bca", ci.Method)
	}
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
