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
// chains that come up, with the shares of a client's attempts that are refused
// and that fail at setup. The client draws the entry among the N listed nodes,
// refuses a mirror that lacks more than min(missing, N-h) of them and draws
// the other h-1 nodes uniformly among the nodes the mirror holds. The k rogue
// nodes act together: as an entry each serves every rogue node and leaves
// leftOut honest nodes out, and withheld of them keep their descriptors from
// the honest nodes. An honest node then neither serves a withholding node nor
// extends a circuit to it, so a chosen chain with an honest node directly
// before a withholding one fails at setup. An honest entry is never both ends
// and all its chains come up; they miss the rogue nodes with the product of
// (N-k-1-i)/(N-withheld-1-i) over the h-1 draws. The chains of a rogue entry
// are summed by rogueEntryChains. The ratios are 0/0, NaN, when no entry is
// accepted; NaN for all four when there is no such configuration
func MirrorCompromiseProbability(nodes, hops, rogue, missing, leftOut, withheld int) (ends, touched, refused, failed float64) {
	honest := nodes - rogue
	if hops < 1 || hops > nodes || missing < 0 || leftOut < 0 || leftOut > honest || withheld < 0 || withheld > rogue {
		return math.NaN(), math.NaN(), math.NaN(), math.NaN()
	}
	allowed := min(missing, nodes-hops)
	// entries whose mirror the client accepts, and for them the chains that
	// come up, fail at setup, have both ends rogue and hold a rogue node, each
	// entry weighted by the share of such chains among the chains it gives
	accepted := 0
	var up, down, bothEnds, anyNode float64
	if honest > 0 && withheld <= allowed {
		clean := 1.0
		for i := 0; i < hops-1; i++ {
			clean *= float64(honest-1-i) / float64(nodes-withheld-1-i)
		}
		accepted += honest
		up += float64(honest)
		anyNode += float64(honest) * (1 - clean)
	}
	if leftOut <= allowed {
		accepted += rogue
		// a withholding entry has one withholding node fewer among the others
		for _, kind := range []struct{ entries, withholding int }{{withheld, withheld - 1}, {rogue - withheld, withheld}} {
			if kind.entries == 0 {
				continue
			}
			entries := float64(kind.entries)
			chains := rogueEntryChains(honest-leftOut, kind.withholding, rogue-1-kind.withholding, hops-1)
			up += entries * chains.comeUp
			down += entries * chains.failed
			bothEnds += entries * chains.rogueExit
			anyNode += entries * chains.comeUp
		}
	}
	n := float64(nodes)
	return bothEnds / up, anyNode / up, 1 - float64(accepted)/n, down / n
}

// the nodes a rogue entry has not yet drawn for its chain, by kind, and
// whether the node drawn last is honest
type undrawn struct {
	honest, withholding, others int
	afterHonest                 bool
}

// the shares of the chains of one rogue entry that come up, that fail at
// setup, and that come up with a rogue last node
type entryChains struct{ comeUp, failed, rogueExit float64 }

// the chains of one rogue entry, summed over the kind of node in each further
// position: honest, withholding and other rogue nodes are drawn without
// replacement, a kind with the share it makes up of the nodes still left. A
// chain fails once a withholding node follows an honest one; with no further
// position the entry is the exit. What follows from a state is worked out
// once, so the steps grow with the number of nodes and not as 3^draws
func rogueEntryChains(honest, withholding, others, draws int) entryChains {
	known := map[undrawn]entryChains{}
	var from func(at undrawn, draws int) entryChains
	from = func(at undrawn, draws int) entryChains {
		if draws == 0 {
			if at.afterHonest {
				return entryChains{comeUp: 1}
			}
			return entryChains{comeUp: 1, rogueExit: 1}
		}
		if sum, ok := known[at]; ok {
			return sum
		}
		pool := float64(at.honest + at.withholding + at.others)
		var sum entryChains
		add := func(count int, next undrawn) {
			if count == 0 {
				return
			}
			share, chains := float64(count)/pool, from(next, draws-1)
			sum.comeUp += share * chains.comeUp
			sum.failed += share * chains.failed
			sum.rogueExit += share * chains.rogueExit
		}
		add(at.honest, undrawn{at.honest - 1, at.withholding, at.others, true})
		if at.afterHonest {
			sum.failed += float64(at.withholding) / pool
		} else {
			add(at.withholding, undrawn{at.honest, at.withholding - 1, at.others, false})
		}
		add(at.others, undrawn{at.honest, at.withholding, at.others - 1, false})
		known[at] = sum
		return sum
	}
	return from(undrawn{honest, withholding, others, false}, draws)
}

// the standard error of a share of n independent draws, each counted with
// probability p: sqrt(p(1-p)/n). Zero for p of 0 or 1, where every draw gives
// the same answer. NaN without draws, for a NaN p, and for p outside [0, 1],
// where the root is of a negative number
func BinomialStdErr(p float64, n int) float64 {
	if n < 1 {
		return math.NaN()
	}
	return math.Sqrt(p * (1 - p) / float64(n))
}
