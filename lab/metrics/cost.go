package metrics

import "time"

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

// cells on a link per message the flows handed to the client; zero when no
// message was sent, since there is no cost to express
func Multiplier(cells, messages int) float64 {
	if messages <= 0 {
		return 0
	}
	return float64(cells) / float64(messages)
}
