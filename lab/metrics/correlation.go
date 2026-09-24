// Package metrics turns observed cell timings into the numbers the thesis
// reports: how well an adversary links flows, and how sure we are of that.
package metrics

import (
	"math"
	"math/rand"
	"sort"
	"time"
)

// counts cells per time bin, which is all a passive observer can build from a
// link that carries fixed-size cells
func Bin(events []time.Duration, window, bin time.Duration) []float64 {
	if bin <= 0 {
		bin = 100 * time.Millisecond
	}
	n := int(window/bin) + 1
	out := make([]float64, n)
	for _, e := range events {
		idx := int(e / bin)
		if idx >= 0 && idx < n {
			out[idx]++
		}
	}
	return out
}

// NaN when either series never varies: a correlation is undefined there, and a
// zero would look like a measured absence of correlation
func Pearson(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return math.NaN()
	}
	var ma, mb float64
	for i := 0; i < n; i++ {
		ma += a[i]
		mb += b[i]
	}
	ma /= float64(n)
	mb /= float64(n)

	var num, da, db float64
	for i := 0; i < n; i++ {
		x, y := a[i]-ma, b[i]-mb
		num += x * y
		da += x * x
		db += y * y
	}
	if da == 0 || db == 0 {
		return math.NaN()
	}
	return num / math.Sqrt(da*db)
}

type Score struct {
	Entry int
	Exit  int
	Value float64
	True  bool
}

// an undefined correlation gives the observer nothing to rank the pair by, so it
// enters the ranking as a tie with every other undefined pair
const undefined = -2

func ScorePairs(entry, exit [][]float64, truth map[int]int) []Score {
	scores := make([]Score, 0, len(entry)*len(exit))
	for i, a := range entry {
		for j, b := range exit {
			v := Pearson(a, b)
			if math.IsNaN(v) {
				v = undefined
			}
			// equal correlations computed in a different order differ in the last
			// bits; rounding keeps them a tie instead of an accidental ranking
			v = math.Round(v*1e9) / 1e9
			scores = append(scores, Score{Entry: i, Exit: j, Value: v, True: truth[i] == j})
		}
	}
	return scores
}

// ties between a positive and a negative count as half a pair
func AUC(scores []Score) float64 {
	sorted := make([]Score, len(scores))
	copy(sorted, scores)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value < sorted[j].Value })

	ranks := make([]float64, len(sorted))
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1].Value == sorted[i].Value {
			j++
		}
		avg := float64(i+j)/2 + 1
		for k := i; k <= j; k++ {
			ranks[k] = avg
		}
		i = j + 1
	}

	var positives, negatives, rankSum float64
	for i, s := range sorted {
		if s.True {
			positives++
			rankSum += ranks[i]
		} else {
			negatives++
		}
	}
	if positives == 0 || negatives == 0 {
		return math.NaN()
	}
	return (rankSum - positives*(positives+1)/2) / (positives * negatives)
}

type rocPoint struct{ fpr, tpr float64 }

// one point per group of tied scores: inside a tie the adversary can only pick
// at random, so the curve runs straight between the points (Fawcett, 2006)
func roc(scores []Score) []rocPoint {
	sorted := make([]Score, len(scores))
	copy(sorted, scores)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })

	var positives, negatives float64
	for _, s := range sorted {
		if s.True {
			positives++
		} else {
			negatives++
		}
	}
	if positives == 0 || negatives == 0 {
		return nil
	}

	points := []rocPoint{{0, 0}}
	var tp, fp float64
	for i := 0; i < len(sorted); {
		j := i
		for j < len(sorted) && sorted[j].Value == sorted[i].Value {
			if sorted[j].True {
				tp++
			} else {
				fp++
			}
			j++
		}
		points = append(points, rocPoint{fp / negatives, tp / positives})
		i = j
	}
	return points
}

// the best true positive rate reachable at a false positive rate of at most
// target, reading the curve with ties as straight segments
func TPRAtFPR(scores []Score, target float64) float64 {
	points := roc(scores)
	if points == nil {
		return math.NaN()
	}
	best := 0.0
	for i := 1; i < len(points); i++ {
		a, b := points[i-1], points[i]
		switch {
		case b.fpr <= target:
			best = math.Max(best, b.tpr)
		case a.fpr <= target:
			frac := (target - a.fpr) / (b.fpr - a.fpr)
			best = math.Max(best, a.tpr+frac*(b.tpr-a.tpr))
		}
	}
	return best
}

// expected share of entry flows matched to their own exit when the adversary
// picks the highest score and breaks ties at random
func TopOneAccuracy(scores []Score, flows int) float64 {
	best := make([]float64, flows)
	for i := range best {
		best[i] = math.Inf(-1)
	}
	for _, s := range scores {
		if s.Value > best[s.Entry] {
			best[s.Entry] = s.Value
		}
	}
	tied := make([]int, flows)
	hit := make([]bool, flows)
	for _, s := range scores {
		if s.Value == best[s.Entry] {
			tied[s.Entry]++
			if s.True {
				hit[s.Entry] = true
			}
		}
	}
	total := 0.0
	for i := 0; i < flows; i++ {
		if hit[i] {
			total += 1 / float64(tied[i])
		}
	}
	return total / float64(flows)
}

type Interval struct {
	Point  float64
	Low    float64
	High   float64
	Method string
}

func normCDF(x float64) float64 { return 0.5 * (1 + math.Erf(x/math.Sqrt2)) }

func normQuantile(p float64) float64 { return math.Sqrt2 * math.Erfinv(2*p-1) }

func quantile(sorted []float64, p float64) float64 {
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	return sorted[lo] + (pos-float64(lo))*(sorted[hi]-sorted[lo])
}

func byEntry(scores []Score, flows int) [][]Score {
	out := make([][]Score, flows)
	for _, s := range scores {
		out[s.Entry] = append(out[s.Entry], s)
	}
	return out
}

// BCa bootstrap over flows rather than over pairs: the pairs of one flow are not
// independent, so resampling them would give an interval that is too narrow.
// the acceleration comes from a jackknife that leaves one flow out at a time
func BootstrapAUC(scores []Score, flows, resamples int, seed int64) Interval {
	point := AUC(scores)
	out := Interval{Point: point, Low: math.NaN(), High: math.NaN(), Method: "bca"}
	if resamples <= 0 || flows <= 1 || math.IsNaN(point) {
		return out
	}
	groups := byEntry(scores, flows)

	rng := rand.New(rand.NewSource(seed))
	samples := make([]float64, 0, resamples)
	below, equal := 0, 0
	for r := 0; r < resamples; r++ {
		pool := make([]Score, 0, len(scores))
		for i := 0; i < flows; i++ {
			pool = append(pool, groups[rng.Intn(flows)]...)
		}
		v := AUC(pool)
		if math.IsNaN(v) {
			continue
		}
		samples = append(samples, v)
		switch {
		case v < point:
			below++
		case v == point:
			equal++
		}
	}
	if len(samples) == 0 {
		return out
	}
	sort.Float64s(samples)
	if samples[0] == samples[len(samples)-1] {
		out.Low, out.High = samples[0], samples[0]
		return out
	}

	b := float64(len(samples))
	p0 := (float64(below) + 0.5*float64(equal)) / b
	p0 = math.Min(math.Max(p0, 0.5/b), 1-0.5/b)
	z0 := normQuantile(p0)

	jack := make([]float64, 0, flows)
	for leave := 0; leave < flows; leave++ {
		pool := make([]Score, 0, len(scores))
		for i := 0; i < flows; i++ {
			if i != leave {
				pool = append(pool, groups[i]...)
			}
		}
		if v := AUC(pool); !math.IsNaN(v) {
			jack = append(jack, v)
		}
	}
	accel := 0.0
	if len(jack) > 1 {
		var mean float64
		for _, v := range jack {
			mean += v
		}
		mean /= float64(len(jack))
		var num, den float64
		for _, v := range jack {
			d := mean - v
			num += d * d * d
			den += d * d
		}
		if den > 0 {
			accel = num / (6 * math.Pow(den, 1.5))
		}
	}

	adjust := func(alpha float64) float64 {
		z := normQuantile(alpha)
		return normCDF(z0 + (z0+z)/(1-accel*(z0+z)))
	}
	out.Low = quantile(samples, adjust(0.025))
	out.High = quantile(samples, adjust(0.975))
	return out
}
