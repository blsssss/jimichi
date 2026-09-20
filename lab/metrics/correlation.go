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

func Pearson(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
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
		return 0
	}
	return num / math.Sqrt(da*db)
}

type Score struct {
	Entry int
	Exit  int
	Value float64
	True  bool
}

// every entry flow is scored against every exit flow, which is the situation of
// an adversary that sees both ends and has to decide which pairs belong together
func ScorePairs(entry, exit [][]float64, truth map[int]int) []Score {
	scores := make([]Score, 0, len(entry)*len(exit))
	for i, a := range entry {
		for j, b := range exit {
			scores = append(scores, Score{
				Entry: i,
				Exit:  j,
				Value: Pearson(a, b),
				True:  truth[i] == j,
			})
		}
	}
	return scores
}

// area under the ROC curve, computed from ranks so that ties are handled
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

// true positive rate at a fixed false positive rate: an attack matters where it
// produces few false links, not on average
func TPRAtFPR(scores []Score, targetFPR float64) float64 {
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
		return math.NaN()
	}

	var tp, fp, best float64
	for _, s := range sorted {
		if s.True {
			tp++
		} else {
			fp++
		}
		if fp/negatives <= targetFPR {
			best = tp / positives
		}
	}
	return best
}

// fraction of entry flows whose highest scoring exit flow is the right one
func TopOneAccuracy(scores []Score, flows int) float64 {
	best := make([]Score, flows)
	seen := make([]bool, flows)
	for _, s := range scores {
		if !seen[s.Entry] || s.Value > best[s.Entry].Value {
			best[s.Entry] = s
			seen[s.Entry] = true
		}
	}
	correct := 0
	for i := range best {
		if seen[i] && best[i].True {
			correct++
		}
	}
	return float64(correct) / float64(flows)
}

type Interval struct {
	Point float64
	Low   float64
	High  float64
}

// bootstrap over flows rather than over pairs: the pairs of one flow are not
// independent, so resampling them would give an interval that is too narrow
func BootstrapAUC(scores []Score, flows, resamples int, seed int64) Interval {
	point := AUC(scores)
	if resamples <= 0 || flows <= 1 {
		return Interval{Point: point, Low: math.NaN(), High: math.NaN()}
	}
	byEntry := make([][]Score, flows)
	for _, s := range scores {
		byEntry[s.Entry] = append(byEntry[s.Entry], s)
	}

	rng := rand.New(rand.NewSource(seed))
	samples := make([]float64, 0, resamples)
	for r := 0; r < resamples; r++ {
		pool := make([]Score, 0, len(scores))
		for i := 0; i < flows; i++ {
			pool = append(pool, byEntry[rng.Intn(flows)]...)
		}
		if v := AUC(pool); !math.IsNaN(v) {
			samples = append(samples, v)
		}
	}
	if len(samples) == 0 {
		return Interval{Point: point, Low: math.NaN(), High: math.NaN()}
	}
	sort.Float64s(samples)
	low := samples[int(0.025*float64(len(samples)))]
	high := samples[int(math.Min(0.975*float64(len(samples)), float64(len(samples)-1)))]
	return Interval{Point: point, Low: low, High: high}
}
