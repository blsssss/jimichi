package metrics

import "math"

// two shares of the paths: those whose first and last node are both rogue,
// which lets the adversary link the two ends of the circuit, and those with a
// rogue node anywhere. A path of one node counts for the first when that node
// is rogue. NaN for no paths: a zero would read as a measured absence of
// compromise
func CompromiseFraction(paths [][]int, rogue map[int]bool) (ends, touched float64) {
	if len(paths) == 0 {
		return math.NaN(), math.NaN()
	}
	var bothEnds, anyNode int
	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		if rogue[path[0]] && rogue[path[len(path)-1]] {
			bothEnds++
		}
		for _, node := range path {
			if rogue[node] {
				anyNode++
				break
			}
		}
	}
	return float64(bothEnds) / float64(len(paths)), float64(anyNode) / float64(len(paths))
}

// what CompromiseFraction tends to when a path of h distinct nodes is drawn
// uniformly among N nodes, k of them rogue: k(k-1)/(N(N-1)) for both ends, k/N
// when the path is one node, and 1 - C(N-k, h)/C(N, h) for any node. The ratio
// of the binomials is the product of (N-k-i)/(N-i) over the h positions, the
// chance that every draw without replacement misses the rogue nodes; with
// fewer than h honest nodes a factor is zero before any turns negative. NaN
// when there is no such choice
func CompromiseProbability(nodes, hops, rogue int) (ends, touched float64) {
	if hops < 1 || hops > nodes || rogue < 0 || rogue > nodes {
		return math.NaN(), math.NaN()
	}
	n, k := float64(nodes), float64(rogue)
	ends = k / n
	if hops > 1 {
		ends = k * max(k-1, 0) / (n * (n - 1))
	}
	clean := 1.0
	for i := 0; i < hops; i++ {
		clean *= (n - k - float64(i)) / (n - float64(i))
	}
	return ends, 1 - clean
}
