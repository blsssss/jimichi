package metrics_test

import (
	"math"
	"slices"
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

// every chain a client can choose over the mirrors and the number of entries it
// refuses; mirrors[e][i] says whether entry e serves node i. The entry is any
// of the n nodes, each as likely; a mirror without the entry itself or lacking
// more than min(missing, n-hops) nodes is refused; the other hops are every
// ordered choice among the other nodes the mirror holds. An entry with c
// chains gives each of them 1/(n*c), so the chains of an entry are repeated
// m/c times, m being the least common multiple of the c: every accepted entry
// then holds m chains, the number returned as each, all the chains returned
// are equally likely and one of them is 1/(n*m) of the attempts
func mirrorChains(mirrors [][]bool, hops, missing int) (chains [][]int, refused, each int) {
	n := len(mirrors)
	perEntry := make([][][]int, 0, n)
	multiple := 1
	for entry, mirror := range mirrors {
		var held []int
		for node, served := range mirror {
			if served {
				held = append(held, node)
			}
		}
		if !mirror[entry] || n-len(held) > min(missing, n-hops) {
			refused++
			continue
		}
		var own [][]int
		var extend func(path []int)
		extend = func(path []int) {
			if len(path) == hops {
				own = append(own, append([]int(nil), path...))
				return
			}
		next:
			for _, node := range held {
				for _, taken := range path {
					if taken == node {
						continue next
					}
				}
				extend(append(path, node))
			}
		}
		extend([]int{entry})
		perEntry = append(perEntry, own)
		multiple = lcm(multiple, len(own))
	}
	for _, own := range perEntry {
		for _, path := range own {
			for range multiple / len(own) {
				chains = append(chains, path)
			}
		}
	}
	return chains, refused, multiple
}

// the chains every node of which extends a circuit to the next, and the number
// of the others, which fail at setup; extends[x][y] says whether x extends to y
func comeUp(chains [][]int, extends [][]bool) (up [][]int, failed int) {
next:
	for _, chain := range chains {
		for i := 1; i < len(chain); i++ {
			if !extends[chain[i-1]][chain[i]] {
				failed++
				continue next
			}
		}
		up = append(up, chain)
	}
	return up, failed
}

// which node extends a circuit to which among n nodes, the first k of them
// rogue: a rogue node extends to every node, an honest one to the nodes whose
// descriptors it holds, all but the first withheld
func extendsOf(n, k, withheld int) [][]bool {
	extends := make([][]bool, n)
	for from := range extends {
		extends[from] = make([]bool, n)
		for to := range extends[from] {
			extends[from][to] = from < k || to >= withheld
		}
	}
	return extends
}

func lcm(a, b int) int {
	x, y := a, b
	for y != 0 {
		x, y = y, x%y
	}
	return a / x * b
}

// the mirrors of n nodes, the first k of them rogue: a rogue entry serves all
// but the last leftOut nodes, which are honest, and an honest entry all but
// the first withheld nodes, which are rogue
func mirrorsOf(n, k, leftOut, withheld int) [][]bool {
	mirrors := make([][]bool, n)
	for entry := range mirrors {
		mirrors[entry] = make([]bool, n)
		for node := range mirrors[entry] {
			if entry < k {
				mirrors[entry][node] = node < n-leftOut
			} else {
				mirrors[entry][node] = node >= withheld
			}
		}
	}
	return mirrors
}

// five nodes, 0 and 1 rogue, chains of three; the client lets an entry leave
// one node out (missing 1) and a rogue entry leaves out the honest node 4.
//
//	a rogue entry (0 or 1) serves four nodes; the two further hops are an
//	ordered pair of the three others it serves, 3*2 = 6 chains, each
//	1/(5*6) = 2/60. For entry 0: 0 1 2, 0 1 3, 0 2 1, 0 2 3, 0 3 1, 0 3 2;
//	the exit is rogue in 0 2 1 and 0 3 1, and in the same two of six for
//	entry 1
//	an honest entry (2, 3 or 4) serves all five; 4*3 = 12 chains, each
//	1/(5*12) = 1/60, none with a rogue entry; no rogue node only when the two
//	further hops are the two other honest nodes, 2 chains of 12
//
// both ends rogue: 2 entries * 2 chains * 2/60 = 8/60 = 2/15, against
// 6/60 = 0.1 for full mirrors. A rogue node: all 6 chains of each rogue entry,
// 12 * 2/60 = 24/60, and 10 of 12 for each honest entry, 30 * 1/60 = 30/60:
// 54/60 = 0.9, as for full mirrors. No entry is refused
func TestCompromiseWhenARogueEntryLeavesOutAnHonestNode(t *testing.T) {
	mirrors := [][]bool{
		{true, true, true, true, false},
		{true, true, true, true, false},
		{true, true, true, true, true},
		{true, true, true, true, true},
		{true, true, true, true, true},
	}
	chains, refused, each := mirrorChains(mirrors, 3, 1)
	if len(chains) != 60 || refused != 0 || each != 12 {
		t.Fatalf("%d equally likely chains, %d to an entry, and %d refused entries, want 60, 12 and 0", len(chains), each, refused)
	}
	// no node withholds, so every node extends to every other and no chain fails
	if up, failed := comeUp(chains, extendsOf(5, 2, 0)); len(up) != 60 || failed != 0 {
		t.Fatalf("%d chains come up and %d fail, want 60 and 0", len(up), failed)
	}
	rogue := map[int]bool{0: true, 1: true}
	ends, touched := metrics.CompromiseFraction(chains, rogue)
	if ends != 8.0/60 || touched != 54.0/60 || !near(ends, 2.0/15) || !near(touched, 0.9) {
		t.Fatalf("CompromiseFraction = %v, %v, want 2/15 and 0.9", ends, touched)
	}
	ends, touched, refusedShare, failedShare := metrics.MirrorCompromiseProbability(5, 3, 2, 1, 1, 0)
	if !near(ends, 2.0/15) || !near(touched, 0.9) || refusedShare != 0 || failedShare != 0 {
		t.Fatalf("MirrorCompromiseProbability(5, 3, 2, 1, 1, 0) = %v, %v, %v, %v, want 2/15, 0.9, 0 and 0", ends, touched, refusedShare, failedShare)
	}
	full, _ := metrics.CompromiseProbability(5, 3, 2)
	if !near(full, 0.1) || ends <= full {
		t.Fatalf("full mirrors give %v, want 0.1 and less than %v", full, ends)
	}
	// which honest node the rogue entries leave out does not change the shares
	for _, out := range []int{2, 3} {
		moved := mirrorsOf(5, 2, 0, 0)
		moved[0][out], moved[1][out] = false, false
		chains, refused, _ := mirrorChains(moved, 3, 1)
		ends, touched := metrics.CompromiseFraction(chains, rogue)
		if refused != 0 || !near(ends, 2.0/15) || !near(touched, 0.9) {
			t.Fatalf("node %d left out: %v, %v with %d refused, want 2/15, 0.9 and 0", out, ends, touched, refused)
		}
	}
}

// five nodes, 0 and 1 rogue, chains of three, the client lets an entry leave
// one node out (missing 1) and both rogue nodes keep their descriptors from
// the honest nodes 2, 3 and 4. An honest node then neither serves 0 and 1 nor
// extends a circuit to them.
//
//	an honest entry serves three nodes of five, two fewer than listed and
//	more than the one allowed: refused, 3 entries of 5
//	a rogue entry serves all five: 4*3 = 12 chains, each 1/(5*12) = 1/60 of
//	the attempts. For entry 0:
//	  0 1 2, 0 1 3, 0 1 4: 0 extends to 1 and 1 to an honest node, come up
//	  0 2 1, 0 3 1, 0 4 1: the honest node does not extend to 1, fail
//	  0 2 3, 0 2 4, 0 3 2, 0 3 4, 0 4 2, 0 4 3: come up
//	and the same nine and three for entry 1
//
// refused 3/5; failed at setup 2 * 3/60 = 1/10; 18/60 = 3/10 come up. The only
// chains with both ends rogue are the six that fail, so of the chains that
// come up none has both ends rogue, 0, against the 6/24 = 1/4 of the chains
// the client chose; all of them enter through a rogue node, 1
func TestCompromiseWhenRogueNodesWithholdTheirDescriptors(t *testing.T) {
	mirrors := [][]bool{
		{true, true, true, true, true},
		{true, true, true, true, true},
		{false, false, true, true, true},
		{false, false, true, true, true},
		{false, false, true, true, true},
	}
	extends := mirrors
	rogue := map[int]bool{0: true, 1: true}
	chains, refused, each := mirrorChains(mirrors, 3, 1)
	if len(chains) != 24 || refused != 3 || each != 12 {
		t.Fatalf("%d chosen chains, %d to an entry, and %d refused entries, want 24, 12 and 3", len(chains), each, refused)
	}
	if ends, _ := metrics.CompromiseFraction(chains, rogue); ends != 6.0/24 {
		t.Fatalf("both ends rogue in %v of the chains chosen, want 1/4", ends)
	}
	up, failed := comeUp(chains, extends)
	if len(up) != 18 || failed != 6 {
		t.Fatalf("%d chains come up and %d fail, want 18 and 6", len(up), failed)
	}
	for _, chain := range up {
		if chain[0] > 1 || chain[2] < 2 {
			t.Fatalf("chain %v came up: want a rogue entry and an honest exit", chain)
		}
	}
	ends, touched := metrics.CompromiseFraction(up, rogue)
	if ends != 0 || touched != 1 {
		t.Fatalf("CompromiseFraction of the chains that come up = %v, %v, want 0 and 1", ends, touched)
	}
	ends, touched, refusedShare, failedShare := metrics.MirrorCompromiseProbability(5, 3, 2, 1, 0, 2)
	if ends != 0 || touched != 1 || !near(refusedShare, 0.6) || !near(failedShare, 0.1) || !near(failedShare, float64(failed)/float64(5*each)) {
		t.Fatalf("MirrorCompromiseProbability(5, 3, 2, 1, 0, 2) = %v, %v, %v, %v, want 0, 1, 0.6 and 0.1", ends, touched, refusedShare, failedShare)
	}
	if !same2D(extends, extendsOf(5, 2, 2)) || !same2D(mirrors, mirrorsOf(5, 2, 0, 2)) {
		t.Fatal("the helpers do not build the mirrors written out above")
	}

	// one withholding node, 0, stays within the bound: nothing is refused.
	//
	//	entry 0 serves all five, 12 chains at 1/60; no other node withholds, so
	//	all come up; the exit is 1 in 0 2 1, 0 3 1, 0 4 1
	//	entry 1 serves all five, 12 chains at 1/60; 1 2 0, 1 3 0, 1 4 0 fail, the
	//	nine others come up and none of them ends at 0
	//	an honest entry serves four nodes, 3*2 = 6 chains at 1/30 = 2/60, all up;
	//	no rogue node only when the two further hops are the two other honest
	//	nodes, 2 chains of 6
	//
	// failed 3/60 = 1/20, so 57/60 come up; both ends rogue 3/57 = 1/19; a rogue
	// node in 12 + 9 + 3 * 4 * 2 = 45 of 57, 15/19
	ends, touched, refusedShare, failedShare = metrics.MirrorCompromiseProbability(5, 3, 2, 1, 0, 1)
	if !near(ends, 1.0/19) || !near(touched, 15.0/19) || refusedShare != 0 || !near(failedShare, 0.05) {
		t.Fatalf("MirrorCompromiseProbability(5, 3, 2, 1, 0, 1) = %v, %v, %v, %v, want 1/19, 15/19, 0 and 1/20", ends, touched, refusedShare, failedShare)
	}
	chains, refused, each = mirrorChains(mirrorsOf(5, 2, 0, 1), 3, 1)
	up, failed = comeUp(chains, extendsOf(5, 2, 1))
	if len(chains) != 60 || refused != 0 || each != 12 || len(up) != 57 || failed != 3 {
		t.Fatalf("%d chains, %d to an entry, %d refused entries, %d come up and %d fail; want 60, 12, 0, 57 and 3", len(chains), each, refused, len(up), failed)
	}
	if ends, touched := metrics.CompromiseFraction(up, rogue); ends != 3.0/57 || touched != 45.0/57 {
		t.Fatalf("CompromiseFraction of the chains that come up = %v, %v, want 3/57 and 45/57", ends, touched)
	}
}

func same2D(a, b [][]bool) bool {
	return slices.EqualFunc(a, b, slices.Equal[[]bool])
}

// worked by hand, N nodes with the first k rogue, chains of h, the bound
// min(missing, N-h); a rogue entry leaves out leftOut honest nodes; withheld
// rogue nodes are absent from the mirrors of the honest entries, and an honest
// node does not extend a circuit to them, so a chain in which an honest node
// comes directly before a withholding one fails at setup. H is an honest node,
// W a withholding one, R another rogue node; the shares of chains are over the
// chains that come up:
//
//	N=5 h=3 k=2 missing=0 leftOut=1: the bound is 0, the two rogue entries
//	lack a node and are refused, 2/5 = 0.4 of the attempts. The honest entries
//	serve all five: never both ends; the two further hops miss the rogue
//	nodes with (2/4)(1/3) = 1/6, so 5/6 hold one. Nothing fails
//	N=5 h=3 k=2 missing=2 leftOut=2: the bound is min(2, 5-3) = 2. A rogue
//	entry serves itself, the other rogue node and one honest node: two
//	chains, the exit rogue in one, 1/2. Both ends (2 * 1/2)/5 = 0.2; a rogue
//	node (2 + 3 * 5/6)/5 = 0.9
//	N=5 h=3 k=2 missing=3 leftOut=3: the bound stays min(3, 5-3) = 2, since a
//	mirror of two nodes holds no chain of three; the rogue entries are
//	refused, 0.4, and the rest is the first case: 0 and 5/6
//	N=5 h=1 k=2 missing=1 leftOut=1: the chain is the entry alone, rogue with
//	2/5 = 0.4, which is both shares
//	N=5 h=1 k=2 missing=1 withheld=1: the same, 0.4 and 0.4: a chain of one
//	node extends nowhere, so nothing fails
//	N=5 h=3 k=2 missing=2 withheld=2: the bound is 2 and the honest mirrors,
//	which lack two nodes, are accepted: an honest entry serves the three
//	honest nodes, 1 share of chains, none with a rogue node. A rogue entry W
//	serves all five, 12 chains: W H W' fails, 3 of 12; W W' H and W H H' come
//	up, 9 of 12, the exit honest. Failed (2 * 3/12)/5 = 1/10; up
//	3 + 2 * 9/12 = 9/2 entries of 5; both ends 0; a rogue node (3/2)/(9/2) = 1/3
//	N=5 h=3 k=2 missing=1 leftOut=1 withheld=1: nothing is refused. An honest
//	entry serves itself, two honest nodes and R: 6 chains, all up, 4 of them
//	with R, 2/3. The entry W serves itself, R and two honest nodes: 6 chains,
//	all up, the exit R in 2. The entry R serves itself, W and two honest
//	nodes: R H W fails, 2 of 6; R W H and R H H' come up, 4 of 6, the exit
//	honest. Failed (2/6)/5 = 1/15; up 3 + 1 + 4/6 = 14/3 entries of 5; both
//	ends (2/6)/(14/3) = 1/14; a rogue node (3 * 2/3 + 1 + 4/6)/(14/3) = 11/14
//	N=4 h=2 k=1 missing=1 leftOut=1 withheld=1: the one rogue node cannot be
//	both ends, 0; the honest entries do not see it, so only its own chains
//	hold a rogue node, 1/4; it is never behind an honest node, nothing fails
//	N=6 h=3 k=3 missing=2 leftOut=1 withheld=2: the bound is min(2, 6-3) = 2,
//	nothing is refused. An honest entry serves itself, two honest nodes and
//	R: 2/3 with a rogue node, all up. A withholding entry serves itself, W',
//	R and two honest nodes, 12 chains: H W' fails, 2; of the 10 that come up
//	the exit is rogue in R W', W' R, H R, H' R, 4. The entry R serves itself,
//	W, W' and two honest nodes, 12 chains: H W, H W', H' W, H' W' fail, 4; of
//	the 8 that come up the exit is rogue in W W' and W' W, 2. Failed
//	(2 * 2/12 + 4/12)/6 = 1/9; up 3 + 2 * 10/12 + 8/12 = 16/3 entries of 6;
//	both ends (2 * 4/12 + 2/12)/(16/3) = 5/32; a rogue node
//	(3 * 2/3 + 2 * 10/12 + 8/12)/(16/3) = 13/16
//	N=5 h=4 k=2 missing=1 withheld=1: the bound is min(1, 5-4) = 1. An honest
//	entry serves itself, two honest nodes and R, and a chain of four takes
//	them all: a rogue node always, all up. The entry W serves all five, 24
//	chains, all up, the exit R in 3*2 = 6. The entry R draws three of W and
//	the three honest nodes, 24 chains: W in the second or third further
//	position follows an honest node, 12 fail; W first or absent, 12 come up,
//	the exit honest. Failed (12/24)/5 = 1/10; up 3 + 1 + 1/2 = 9/2 entries of
//	5; both ends (6/24)/(9/2) = 1/18; a rogue node 1
//	N=5 h=3 k=2 missing=0 leftOut=1 withheld=2: every entry lacks a node and
//	the bound is 0: all attempts are refused, 1, none fails at setup, and
//	there is no chain to take a share of
//
// the two rows with nothing left out are worked chain by chain in
// TestCompromiseWhenRogueNodesWithholdTheirDescriptors. The enumeration of
// every chain the client can choose, split by whether every node extends to
// the next, must agree
func TestMirrorCompromiseProbabilityKnownAnswer(t *testing.T) {
	nan := math.NaN()
	for _, c := range []struct {
		nodes, hops, rogue, missing, leftOut, withheld int
		ends, touched, refused, failed                 float64
	}{
		{5, 3, 2, 0, 1, 0, 0, 5.0 / 6, 0.4, 0},
		{5, 3, 2, 2, 2, 0, 0.2, 0.9, 0, 0},
		{5, 3, 2, 3, 3, 0, 0, 5.0 / 6, 0.4, 0},
		{5, 1, 2, 1, 1, 0, 0.4, 0.4, 0, 0},
		{5, 1, 2, 1, 0, 1, 0.4, 0.4, 0, 0},
		{5, 3, 2, 1, 0, 2, 0, 1, 0.6, 0.1},
		{5, 3, 2, 1, 0, 1, 1.0 / 19, 15.0 / 19, 0, 0.05},
		{5, 3, 2, 2, 0, 2, 0, 1.0 / 3, 0, 0.1},
		{5, 3, 2, 1, 1, 1, 1.0 / 14, 11.0 / 14, 0, 1.0 / 15},
		{4, 2, 1, 1, 1, 1, 0, 0.25, 0, 0},
		{6, 3, 3, 2, 1, 2, 5.0 / 32, 13.0 / 16, 0, 1.0 / 9},
		{5, 4, 2, 1, 0, 1, 1.0 / 18, 1, 0, 0.1},
		{5, 3, 2, 0, 1, 2, nan, nan, 1, 0},
	} {
		same := func(got, want float64) bool {
			return near(got, want) || math.IsNaN(got) && math.IsNaN(want)
		}
		ends, touched, refused, failed := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
		if !same(ends, c.ends) || !same(touched, c.touched) || !near(refused, c.refused) || !near(failed, c.failed) || ends == 0 && math.Signbit(ends) {
			t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d) = %v, %v, %v, %v, want %v, %v, %v, %v",
				c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld, ends, touched, refused, failed, c.ends, c.touched, c.refused, c.failed)
		}
		// a share the choice makes 0 or 1 is exactly that, and so is its standard error 0
		for _, share := range [][2]float64{{ends, c.ends}, {touched, c.touched}, {refused, c.refused}, {failed, c.failed}} {
			if (share[1] == 0 || share[1] == 1) && share[0] != share[1] {
				t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d): share %v, want exactly %v",
					c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld, share[0], share[1])
			}
		}
		rogue := make(map[int]bool, c.rogue)
		for node := 0; node < c.rogue; node++ {
			rogue[node] = true
		}
		chains, refusedEntries, each := mirrorChains(mirrorsOf(c.nodes, c.rogue, c.leftOut, c.withheld), c.hops, c.missing)
		up, failedChains := comeUp(chains, extendsOf(c.nodes, c.rogue, c.withheld))
		gotEnds, gotTouched := metrics.CompromiseFraction(up, rogue)
		gotRefused := float64(refusedEntries) / float64(c.nodes)
		gotFailed := float64(failedChains) / float64(c.nodes*each)
		if !same(gotEnds, c.ends) || !same(gotTouched, c.touched) || !near(gotRefused, c.refused) || !near(gotFailed, c.failed) {
			t.Errorf("all chains of %d hops among %d nodes, %d rogue, missing %d, left out %d, withheld %d: %v, %v, %v, %v, want %v, %v, %v, %v",
				c.hops, c.nodes, c.rogue, c.missing, c.leftOut, c.withheld, gotEnds, gotTouched, gotRefused, gotFailed, c.ends, c.touched, c.refused, c.failed)
		}
	}
	for _, c := range []struct{ nodes, hops, rogue, missing, leftOut, withheld int }{
		{5, 6, 2, 1, 0, 0}, {5, 0, 2, 1, 0, 0}, {5, 3, 6, 1, 0, 0}, {5, 3, -1, 1, 0, 0},
		{5, 3, 2, -1, 0, 0}, {5, 3, 2, 1, -1, 0}, {5, 3, 2, 1, 4, 0}, {5, 3, 2, 1, 0, -1}, {5, 3, 2, 1, 0, 3},
	} {
		ends, touched, refused, failed := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
		if !math.IsNaN(ends) || !math.IsNaN(touched) || !math.IsNaN(refused) || !math.IsNaN(failed) {
			t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d) = %v, %v, %v, %v, want NaN",
				c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld, ends, touched, refused, failed)
		}
	}
}

// the closed form agrees with every chain counted one by one for each
// configuration of up to six nodes: any number of rogue nodes, of withholding
// ones among them, of honest nodes left out, any bound and chains of up to
// four nodes
func TestMirrorCompromiseProbabilityAgreesWithEveryChain(t *testing.T) {
	checked := 0
	for nodes := 1; nodes <= 6; nodes++ {
		for hops := 1; hops <= min(nodes, 4); hops++ {
			for k := 0; k <= nodes; k++ {
				for missing := 0; missing <= 2; missing++ {
					for leftOut := 0; leftOut <= min(nodes-k, 2); leftOut++ {
						for withheld := 0; withheld <= k; withheld++ {
							rogue := make(map[int]bool, k)
							for node := 0; node < k; node++ {
								rogue[node] = true
							}
							chains, refusedEntries, each := mirrorChains(mirrorsOf(nodes, k, leftOut, withheld), hops, missing)
							up, failedChains := comeUp(chains, extendsOf(nodes, k, withheld))
							wantEnds, wantTouched := metrics.CompromiseFraction(up, rogue)
							wantRefused := float64(refusedEntries) / float64(nodes)
							wantFailed := float64(failedChains) / float64(nodes*each)
							ends, touched, refused, failed := metrics.MirrorCompromiseProbability(nodes, hops, k, missing, leftOut, withheld)
							same := func(got, want float64) bool {
								return near(got, want) || math.IsNaN(got) && math.IsNaN(want)
							}
							if !same(ends, wantEnds) || !same(touched, wantTouched) || !near(refused, wantRefused) || !near(failed, wantFailed) {
								t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d) = %v, %v, %v, %v, every chain gives %v, %v, %v, %v",
									nodes, hops, k, missing, leftOut, withheld, ends, touched, refused, failed, wantEnds, wantTouched, wantRefused, wantFailed)
							}
							for _, share := range [][2]float64{{ends, wantEnds}, {touched, wantTouched}, {refused, wantRefused}, {failed, wantFailed}} {
								if (share[1] == 0 || share[1] == 1) && share[0] != share[1] {
									t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d): share %v, want exactly %v",
										nodes, hops, k, missing, leftOut, withheld, share[0], share[1])
								}
							}
							checked++
						}
					}
				}
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("%d configurations checked, want more than a thousand", checked)
	}
}

// a chain of thirty nodes among forty: the sum over the kinds of node takes a
// number of steps that grows with the nodes, where one step per ordering of
// the kinds would be 3^29. With nothing withheld the values are those of the
// uniform choice; with rogue nodes that withhold some chains fail, and the
// chains that come up still all hold a rogue node when the honest nodes are
// fewer than the chain is long
func TestMirrorCompromiseProbabilityOfALongChain(t *testing.T) {
	wantEnds, wantTouched := metrics.CompromiseProbability(40, 30, 15)
	ends, touched, refused, failed := metrics.MirrorCompromiseProbability(40, 30, 15, 3, 0, 0)
	if !near(ends, wantEnds) || !near(touched, wantTouched) || refused != 0 || failed != 0 {
		t.Fatalf("MirrorCompromiseProbability(40, 30, 15, 3, 0, 0) = %v, %v, %v, %v, want %v, %v, 0, 0", ends, touched, refused, failed, wantEnds, wantTouched)
	}
	// only the chains of the 15 rogue entries of 40 can fail
	ends, touched, refused, failed = metrics.MirrorCompromiseProbability(40, 30, 15, 3, 2, 3)
	if !(ends > 0 && ends < 1) || touched != 1 || refused != 0 || !(failed > 0 && failed < 15.0/40) {
		t.Fatalf("MirrorCompromiseProbability(40, 30, 15, 3, 2, 3) = %v, %v, %v, %v, want shares inside (0, 1), 1, 0 and a share inside (0, 15/40)", ends, touched, refused, failed)
	}
}

// with nothing left out and nothing withheld every mirror is full, every node
// extends to every other and the choice is the uniform one, whatever the
// bound; the shares that are 0 or 1 are exactly so
func TestMirrorCompromiseOfFullMirrorsIsTheUniformChoice(t *testing.T) {
	for _, c := range []struct{ nodes, hops, rogue int }{
		{5, 3, 2}, {5, 3, 0}, {5, 3, 5}, {5, 3, 1}, {5, 3, 3}, {5, 1, 2}, {3, 3, 1}, {10, 3, 3}, {7, 4, 2},
	} {
		wantEnds, wantTouched := metrics.CompromiseProbability(c.nodes, c.hops, c.rogue)
		for _, missing := range []int{0, 1, 4} {
			ends, touched, refused, failed := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, missing, 0, 0)
			if !near(ends, wantEnds) || !near(touched, wantTouched) || refused != 0 || failed != 0 {
				t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, 0, 0) = %v, %v, %v, %v, want %v, %v, 0, 0",
					c.nodes, c.hops, c.rogue, missing, ends, touched, refused, failed, wantEnds, wantTouched)
			}
			for _, share := range [][2]float64{{ends, wantEnds}, {touched, wantTouched}} {
				if (share[1] == 0 || share[1] == 1) && share[0] != share[1] {
					t.Errorf("%d nodes, %d hops, %d rogue: share %v, want exactly %v", c.nodes, c.hops, c.rogue, share[0], share[1])
				}
			}
		}
	}
}

// worked by hand:
//
//	p = 0.1, n = 100: sqrt(0.1 * 0.9 / 100) = sqrt(0.0009) = 0.03
//	p = 0.5, n = 100: sqrt(0.25 / 100) = 0.05
//	p = 0.2, n = 400: sqrt(0.16 / 400) = sqrt(0.0004) = 0.02
//	p = 0.9, n = 100: the same 0.03 as for 0.1
//	p = 0 or 1: every draw gives the same answer, 0
//
// and from the distribution itself for two draws with p = 0.5: the share is 0
// with 1/4, 0.5 with 1/2 and 1 with 1/4, its mean 0.5, its variance
// (1/4)(0.5)^2 + (1/4)(0.5)^2 = 0.125 = 0.5 * 0.5 / 2
func TestBinomialStdErrKnownAnswer(t *testing.T) {
	for _, c := range []struct {
		p    float64
		n    int
		want float64
	}{
		{0.1, 100, 0.03}, {0.5, 100, 0.05}, {0.2, 400, 0.02}, {0.9, 100, 0.03},
		{0, 100, 0}, {1, 100, 0}, {0.5, 2, math.Sqrt(0.125)},
	} {
		if got := metrics.BinomialStdErr(c.p, c.n); !near(got, c.want) {
			t.Errorf("BinomialStdErr(%v, %d) = %v, want %v", c.p, c.n, got, c.want)
		}
	}
	for _, c := range []struct {
		p float64
		n int
	}{{0.5, 0}, {0.5, -1}, {-0.1, 10}, {1.1, 10}, {math.NaN(), 10}} {
		if got := metrics.BinomialStdErr(c.p, c.n); !math.IsNaN(got) {
			t.Errorf("BinomialStdErr(%v, %d) = %v, want NaN", c.p, c.n, got)
		}
	}
}

// the deviation of the share taken from every outcome of n draws, each with
// its probability, not from the formula: for n = 4 and p = 0.25 the 16
// outcomes with x counted draws weigh 0.25^x * 0.75^(4-x), the mean share is
// 0.25 and the variance 0.25 * 0.75 / 4 = 0.046875
func TestBinomialStdErrIsTheDeviationOfTheShare(t *testing.T) {
	for _, c := range []struct {
		p float64
		n int
	}{{0.25, 4}, {0.5, 2}, {0.1, 6}, {2.0 / 15, 5}} {
		var mean, square float64
		for outcome := 0; outcome < 1<<c.n; outcome++ {
			weight, counted := 1.0, 0
			for draw := 0; draw < c.n; draw++ {
				if outcome>>draw&1 == 1 {
					weight *= c.p
					counted++
				} else {
					weight *= 1 - c.p
				}
			}
			share := float64(counted) / float64(c.n)
			mean += weight * share
			square += weight * share * share
		}
		if got, want := metrics.BinomialStdErr(c.p, c.n), math.Sqrt(square-mean*mean); !near(mean, c.p) || !near(got, want) {
			t.Errorf("BinomialStdErr(%v, %d) = %v, the outcomes give %v around a mean of %v", c.p, c.n, got, want, mean)
		}
	}
	if got := metrics.BinomialStdErr(0.25, 4); !near(got*got, 0.046875) {
		t.Errorf("BinomialStdErr(0.25, 4) squared = %v, want 0.046875", got*got)
	}
}
