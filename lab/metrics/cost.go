package metrics

import (
	"math"
	"slices"
	"time"
)

// counts frames that crossed a link before the end of the observation window;
// the drain after it is not something the observer was scored on
func CellsWithin(traces [][]time.Duration, window time.Duration) int {
	n := 0
	for _, t := range traces {
		for _, e := range t {
			if e < window {
				n++
			}
		}
	}
	return n
}

// cells on a link per message the flows handed to the client; NaN when no
// message was sent, since a zero would read as a measured absence of cost
func Multiplier(cells, messages int) float64 {
	if messages <= 0 {
		return math.NaN()
	}
	return float64(cells) / float64(messages)
}

// middle of the values, the mean of the two middle ones for an even count;
// NaN for none. Runs of one configuration are summarised by it
func Median(values []float64) float64 {
	if len(values) == 0 {
		return math.NaN()
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// linear interpolation between order statistics, the type 7 estimator; false
// when there is nothing to take a percentile of
func Percentile(samples []time.Duration, q float64) (time.Duration, bool) {
	if len(samples) == 0 || !(q >= 0 && q <= 1) {
		return 0, false
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	pos := q * float64(len(sorted)-1)
	lo := int(pos)
	if lo+1 >= len(sorted) {
		return sorted[lo], true
	}
	frac := pos - float64(lo)
	return sorted[lo] + time.Duration(math.Round(frac*float64(sorted[lo+1]-sorted[lo]))), true
}
