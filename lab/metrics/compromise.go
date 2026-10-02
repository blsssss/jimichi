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

// the same shares when the mirror of an entry need not be full, over the
// chains a client builds, and the share of its attempts that build none. The
// client draws the entry among the N listed nodes, refuses a mirror that lacks
// more than min(missing, N-h) of them and draws the other h-1 nodes uniformly
// among the nodes the mirror holds. The k rogue nodes act together: as an
// entry each serves every rogue node and leaves leftOut honest nodes out, and
// withheld of them keep their descriptors from the honest nodes, whose mirrors
// then lack those. An honest entry is never both ends; its chain misses the
// rogue nodes with the product of (N-k-1-i)/(N-withheld-1-i) over the h-1
// draws. A rogue entry draws its exit among the N-leftOut-1 other nodes it
// serves, k-1 of them rogue. NaN shares when no entry is accepted, NaN for all
// three when there is no such configuration
func MirrorCompromiseProbability(nodes, hops, rogue, missing, leftOut, withheld int) (ends, touched, refused float64) {
	honest := nodes - rogue
	if hops < 1 || hops > nodes || rogue < 0 || rogue > nodes || missing < 0 ||
		leftOut < 0 || leftOut > honest || withheld < 0 || withheld > rogue {
		return math.NaN(), math.NaN(), math.NaN()
	}
	allowed := min(missing, nodes-hops)
	n, k := float64(nodes), float64(rogue)
	// entries whose mirror the client accepts, and those of them that give a
	// chain with both ends rogue or with a rogue node, each weighted by the
	// share of such chains among the chains of that entry
	var built, bothEnds, anyNode float64
	if honest > 0 && withheld <= allowed {
		clean := 1.0
		for i := 0; i < hops-1; i++ {
			clean *= (n - k - 1 - float64(i)) / (n - float64(withheld) - 1 - float64(i))
		}
		built += n - k
		anyNode += (n - k) * (1 - clean)
	}
	if rogue > 0 && leftOut <= allowed {
		built += k
		anyNode += k
		if hops == 1 {
			bothEnds += k
		} else {
			bothEnds += k * (k - 1) / (n - float64(leftOut) - 1)
		}
	}
	if built == 0 {
		return math.NaN(), math.NaN(), 1
	}
	return bothEnds / built, anyNode / built, 1 - built/n
}

// the standard error of a share of n independent draws, each counted with
// probability p: sqrt(p(1-p)/n). Zero for p of 0 or 1, where every draw gives
// the same answer. NaN without draws or for p outside [0, 1]
func BinomialStdErr(p float64, n int) float64 {
	if n < 1 || math.IsNaN(p) || p < 0 || p > 1 {
		return math.NaN()
	}
	return math.Sqrt(p * (1 - p) / float64(n))
}
