package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// every ordered path of hops distinct nodes among n
func orderedPaths(n, hops int) [][]int {
	var out [][]int
	var extend func(path []int)
	extend = func(path []int) {
		if len(path) == hops {
			out = append(out, append([]int(nil), path...))
			return
		}
	next:
		for node := 0; node < n; node++ {
			for _, taken := range path {
				if taken == node {
					continue next
				}
			}
			extend(append(path, node))
		}
	}
	extend(nil)
	return out
}

// counted by hand with nodes 0 and 1 rogue:
//
//	0 1 2: entry rogue, exit not; a rogue node on the path
//	2 3 4: no rogue node
//	0 3 1: entry and exit rogue
//	3 4 2: no rogue node
//	4 0 3: only the middle is rogue
//
// one path of five has both ends rogue, 0.2; three of five hold a rogue node, 0.6
func TestCompromiseFractionKnownAnswer(t *testing.T) {
	paths := [][]int{{0, 1, 2}, {2, 3, 4}, {0, 3, 1}, {3, 4, 2}, {4, 0, 3}}
	ends, touched := metrics.CompromiseFraction(paths, map[int]bool{0: true, 1: true})
	if !near(ends, 0.2) || !near(touched, 0.6) {
		t.Fatalf("CompromiseFraction = %v, %v, want 0.2 and 0.6", ends, touched)
	}
	// a path of one node is its own entry and exit; an empty one holds no node
	ends, touched = metrics.CompromiseFraction([][]int{{1}, {2}, {}, {0}}, map[int]bool{0: true, 1: true})
	if !near(ends, 0.5) || !near(touched, 0.5) {
		t.Fatalf("CompromiseFraction of one-node paths = %v, %v, want 0.5 and 0.5", ends, touched)
	}
	ends, touched = metrics.CompromiseFraction(paths, nil)
	if ends != 0 || touched != 0 {
		t.Fatalf("CompromiseFraction with no rogue node = %v, %v, want 0 and 0", ends, touched)
	}
	ends, touched = metrics.CompromiseFraction(nil, map[int]bool{0: true})
	if !math.IsNaN(ends) || !math.IsNaN(touched) {
		t.Fatalf("CompromiseFraction of no paths = %v, %v, want NaN", ends, touched)
	}
}

// N = 5 nodes, k = 2 of them rogue, paths of h = 3. There are 5*4*3 = 60
// ordered paths.
//
//	both ends rogue: 2 choices of the entry, the other rogue node as the exit,
//	any of the 3 honest nodes between them: 2*1*3 = 6 paths, 6/60 = 0.1,
//	which is k(k-1)/(N(N-1)) = 2*1/(5*4)
//	no rogue node: the 3 honest nodes in any order, 3*2*1 = 6 paths, so
//	54 of 60 hold a rogue node, 0.9, which is 1 - C(3,3)/C(5,3) = 1 - 1/10
//
// the enumeration must give exactly these, whichever two nodes are rogue
func TestCompromiseOfThreeHopsAmongFiveNodes(t *testing.T) {
	paths := orderedPaths(5, 3)
	if len(paths) != 60 {
		t.Fatalf("%d ordered paths, want 60", len(paths))
	}
	for _, rogue := range []map[int]bool{{0: true, 1: true}, {1: true, 3: true}, {2: true, 4: true}} {
		ends, touched := metrics.CompromiseFraction(paths, rogue)
		if ends != 6.0/60 || touched != 54.0/60 || !near(ends, 0.1) || !near(touched, 0.9) {
			t.Fatalf("rogue %v: CompromiseFraction = %v, %v, want 0.1 and 0.9", rogue, ends, touched)
		}
	}
	ends, touched := metrics.CompromiseProbability(5, 3, 2)
	if !near(ends, 0.1) || !near(touched, 0.9) {
		t.Fatalf("CompromiseProbability(5, 3, 2) = %v, %v, want 0.1 and 0.9", ends, touched)
	}
}

// worked by hand:
//
//	N=5 h=3 k=3: 3*2/(5*4) = 0.3; the honest nodes are two, so no path of three
//	misses the rogue ones: (2/5)(1/4)(0/3) = 0, any node 1
//	N=5 h=3 k=1: one rogue node cannot be both ends, 0; 1 - (4/5)(3/4)(2/3) = 0.6
//	N=5 h=3 k=0: 0 and 0; k=5: 5*4/(5*4) = 1 and 1
//	N=5 h=1 k=2: the one node is entry and exit, 2/5 = 0.4; 1 - 3/5 = 0.4
//	N=5 h=2 k=2: 2/20 = 0.1; 1 - (3/5)(2/4) = 0.7
//	N=10 h=3 k=3: 3*2/(10*9) = 1/15; 1 - (7/10)(6/9)(5/8) = 1 - 210/720 = 17/24
//	N=3 h=3 k=2: 2/(3*2) = 1/3; every path holds all three nodes, 1
func TestCompromiseProbabilityKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		nodes, hops, rogue int
		ends, touched      float64
	}{
		{5, 3, 3, 0.3, 1},
		{5, 3, 1, 0, 0.6},
		{5, 3, 0, 0, 0},
		{5, 3, 5, 1, 1},
		{5, 1, 2, 0.4, 0.4},
		{5, 2, 2, 0.1, 0.7},
		{10, 3, 3, 1.0 / 15, 17.0 / 24},
		{3, 3, 2, 1.0 / 3, 1},
	} {
		ends, touched := metrics.CompromiseProbability(c.nodes, c.hops, c.rogue)
		if !near(ends, c.ends) || !near(touched, c.touched) || math.Signbit(ends) {
			t.Errorf("CompromiseProbability(%d, %d, %d) = %v, %v, want %v and %v", c.nodes, c.hops, c.rogue, ends, touched, c.ends, c.touched)
		}
		// the enumeration of every path agrees, the first k nodes being rogue
		rogue := make(map[int]bool, c.rogue)
		for node := 0; node < c.rogue; node++ {
			rogue[node] = true
		}
		gotEnds, gotTouched := metrics.CompromiseFraction(orderedPaths(c.nodes, c.hops), rogue)
		if !near(gotEnds, c.ends) || !near(gotTouched, c.touched) {
			t.Errorf("all paths of %d hops among %d nodes with %d rogue: %v, %v, want %v and %v", c.hops, c.nodes, c.rogue, gotEnds, gotTouched, c.ends, c.touched)
		}
	}
	for _, c := range []struct{ nodes, hops, rogue int }{{5, 6, 2}, {5, 0, 2}, {5, 3, 6}, {5, 3, -1}, {0, 0, 0}} {
		ends, touched := metrics.CompromiseProbability(c.nodes, c.hops, c.rogue)
		if !math.IsNaN(ends) || !math.IsNaN(touched) {
			t.Errorf("CompromiseProbability(%d, %d, %d) = %v, %v, want NaN", c.nodes, c.hops, c.rogue, ends, touched)
		}
	}
}
