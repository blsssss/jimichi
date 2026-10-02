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

// every chain a client can build over the mirrors and the number of entries it
// refuses; mirrors[e][i] says whether entry e serves node i. The entry is any
// of the n nodes, each as likely; a mirror without the entry itself or lacking
// more than min(missing, n-hops) nodes is refused; the other hops are every
// ordered choice among the other nodes the mirror holds. An entry with c
// chains gives each of them 1/(n*c), so the chains of an entry are repeated
// m/c times, m being the least common multiple of the c: every accepted entry
// then holds m chains and all the chains returned are equally likely
func mirrorChains(mirrors [][]bool, hops, missing int) (chains [][]int, refused int) {
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
	return chains, refused
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
	chains, refused := mirrorChains(mirrors, 3, 1)
	if len(chains) != 60 || refused != 0 {
		t.Fatalf("%d equally likely chains and %d refused entries, want 60 and 0", len(chains), refused)
	}
	rogue := map[int]bool{0: true, 1: true}
	ends, touched := metrics.CompromiseFraction(chains, rogue)
	if ends != 8.0/60 || touched != 54.0/60 || !near(ends, 2.0/15) || !near(touched, 0.9) {
		t.Fatalf("CompromiseFraction = %v, %v, want 2/15 and 0.9", ends, touched)
	}
	ends, touched, refusedShare := metrics.MirrorCompromiseProbability(5, 3, 2, 1, 1, 0)
	if !near(ends, 2.0/15) || !near(touched, 0.9) || refusedShare != 0 {
		t.Fatalf("MirrorCompromiseProbability(5, 3, 2, 1, 1, 0) = %v, %v, %v, want 2/15, 0.9 and 0", ends, touched, refusedShare)
	}
	full, _ := metrics.CompromiseProbability(5, 3, 2)
	if !near(full, 0.1) || ends <= full {
		t.Fatalf("full mirrors give %v, want 0.1 and less than %v", full, ends)
	}
	// which honest node the rogue entries leave out does not change the shares
	for _, out := range []int{2, 3} {
		moved := mirrorsOf(5, 2, 0, 0)
		moved[0][out], moved[1][out] = false, false
		chains, refused := mirrorChains(moved, 3, 1)
		ends, touched := metrics.CompromiseFraction(chains, rogue)
		if refused != 0 || !near(ends, 2.0/15) || !near(touched, 0.9) {
			t.Fatalf("node %d left out: %v, %v with %d refused, want 2/15, 0.9 and 0", out, ends, touched, refused)
		}
	}
}

// worked by hand, N nodes with the first k rogue, chains of h, the bound
// min(missing, N-h); a rogue entry leaves out leftOut honest nodes, withheld
// rogue nodes are absent from the mirrors of the honest entries:
//
//	N=5 h=3 k=2 missing=0 leftOut=1: the bound is 0, the two rogue entries
//	lack a node and are refused, 2/5 = 0.4 of the attempts. The honest entries
//	serve all five: never both ends; the two further hops miss the rogue
//	nodes with (2/4)(1/3) = 1/6, so 5/6 hold one
//	N=5 h=3 k=2 missing=1 withheld=2: the honest mirrors lack two nodes, more
//	than one, and are refused, 3/5 = 0.6. Every chain enters through a rogue
//	node, which serves all five: the exit is the other rogue node among four,
//	1/4; a rogue node always, 1
//	N=5 h=3 k=2 missing=1 withheld=1: nothing is refused. An honest entry
//	serves itself, two honest nodes and one rogue: it misses the rogue one
//	with (2/3)(1/2) = 1/3, so 2/3. A rogue entry serves all five, exit rogue
//	1/4. Both ends (2 * 1/4)/5 = 0.1; a rogue node (2 + 3 * 2/3)/5 = 0.8
//	N=5 h=3 k=2 missing=2 leftOut=2: the bound is min(2, 5-3) = 2. A rogue
//	entry serves itself, the other rogue node and one honest node: two
//	chains, the exit rogue in one, 1/2. Both ends (2 * 1/2)/5 = 0.2; a rogue
//	node (2 + 3 * 5/6)/5 = 0.9
//	N=5 h=3 k=2 missing=3 leftOut=3: the bound stays min(3, 5-3) = 2, since a
//	mirror of two nodes holds no chain of three; the rogue entries are
//	refused, 0.4, and the rest is the first case: 0 and 5/6
//	N=5 h=1 k=2 missing=1 leftOut=1: the chain is the entry alone, rogue with
//	2/5 = 0.4, which is both shares
//	N=5 h=3 k=2 missing=1 leftOut=1 withheld=1: a rogue entry serves itself,
//	the other rogue node and two honest ones, exit rogue 1/3; an honest entry
//	as two cases above, 2/3. Both ends (2 * 1/3)/5 = 2/15; a rogue node
//	(2 + 3 * 2/3)/5 = 0.8
//	N=4 h=2 k=1 missing=1 leftOut=1 withheld=1: the one rogue node cannot be
//	both ends, 0; the honest entries do not see it, so only its own chains
//	hold a rogue node, 1/4
//	N=6 h=3 k=3 missing=2 leftOut=1 withheld=2: the bound is min(2, 6-3) = 2.
//	An honest entry serves itself, two honest nodes and one rogue: 2/3 as
//	above. A rogue entry serves itself, two rogue and two honest nodes: exit
//	rogue 2/4. Both ends (3 * 1/2)/6 = 0.25; a rogue node (3 + 3 * 2/3)/6 = 5/6
//	N=5 h=3 k=2 missing=0 leftOut=1 withheld=2: every entry lacks a node and
//	the bound is 0: all attempts are refused, 1, and there is no chain to
//	take a share of
//
// the enumeration of every chain the client can build must agree
func TestMirrorCompromiseProbabilityKnownAnswer(t *testing.T) {
	nan := math.NaN()
	for _, c := range []struct {
		nodes, hops, rogue, missing, leftOut, withheld int
		ends, touched, refused                         float64
	}{
		{5, 3, 2, 0, 1, 0, 0, 5.0 / 6, 0.4},
		{5, 3, 2, 1, 0, 2, 0.25, 1, 0.6},
		{5, 3, 2, 1, 0, 1, 0.1, 0.8, 0},
		{5, 3, 2, 2, 2, 0, 0.2, 0.9, 0},
		{5, 3, 2, 3, 3, 0, 0, 5.0 / 6, 0.4},
		{5, 1, 2, 1, 1, 0, 0.4, 0.4, 0},
		{5, 3, 2, 1, 1, 1, 2.0 / 15, 0.8, 0},
		{4, 2, 1, 1, 1, 1, 0, 0.25, 0},
		{6, 3, 3, 2, 1, 2, 0.25, 5.0 / 6, 0},
		{5, 3, 2, 0, 1, 2, nan, nan, 1},
	} {
		same := func(got, want float64) bool {
			return near(got, want) || math.IsNaN(got) && math.IsNaN(want)
		}
		ends, touched, refused := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
		if !same(ends, c.ends) || !same(touched, c.touched) || !near(refused, c.refused) || math.Signbit(ends) {
			t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d) = %v, %v, %v, want %v, %v, %v",
				c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld, ends, touched, refused, c.ends, c.touched, c.refused)
		}
		rogue := make(map[int]bool, c.rogue)
		for node := 0; node < c.rogue; node++ {
			rogue[node] = true
		}
		chains, refusedEntries := mirrorChains(mirrorsOf(c.nodes, c.rogue, c.leftOut, c.withheld), c.hops, c.missing)
		gotEnds, gotTouched := metrics.CompromiseFraction(chains, rogue)
		gotRefused := float64(refusedEntries) / float64(c.nodes)
		if !same(gotEnds, c.ends) || !same(gotTouched, c.touched) || !near(gotRefused, c.refused) {
			t.Errorf("all chains of %d hops among %d nodes, %d rogue, missing %d, left out %d, withheld %d: %v, %v, %v, want %v, %v, %v",
				c.hops, c.nodes, c.rogue, c.missing, c.leftOut, c.withheld, gotEnds, gotTouched, gotRefused, c.ends, c.touched, c.refused)
		}
	}
	for _, c := range []struct{ nodes, hops, rogue, missing, leftOut, withheld int }{
		{5, 6, 2, 1, 0, 0}, {5, 0, 2, 1, 0, 0}, {5, 3, 6, 1, 0, 0}, {5, 3, -1, 1, 0, 0},
		{5, 3, 2, -1, 0, 0}, {5, 3, 2, 1, -1, 0}, {5, 3, 2, 1, 4, 0}, {5, 3, 2, 1, 0, -1}, {5, 3, 2, 1, 0, 3},
	} {
		ends, touched, refused := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
		if !math.IsNaN(ends) || !math.IsNaN(touched) || !math.IsNaN(refused) {
			t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, %d, %d) = %v, %v, %v, want NaN",
				c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld, ends, touched, refused)
		}
	}
}

// with nothing left out and nothing withheld every mirror is full and the
// choice is the uniform one, whatever the bound; the shares that are 0 or 1
// are exactly so
func TestMirrorCompromiseOfFullMirrorsIsTheUniformChoice(t *testing.T) {
	for _, c := range []struct{ nodes, hops, rogue int }{
		{5, 3, 2}, {5, 3, 0}, {5, 3, 5}, {5, 3, 1}, {5, 3, 3}, {5, 1, 2}, {3, 3, 1}, {10, 3, 3}, {7, 4, 2},
	} {
		wantEnds, wantTouched := metrics.CompromiseProbability(c.nodes, c.hops, c.rogue)
		for _, missing := range []int{0, 1, 4} {
			ends, touched, refused := metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, missing, 0, 0)
			if !near(ends, wantEnds) || !near(touched, wantTouched) || refused != 0 {
				t.Errorf("MirrorCompromiseProbability(%d, %d, %d, %d, 0, 0) = %v, %v, %v, want %v, %v, 0",
					c.nodes, c.hops, c.rogue, missing, ends, touched, refused, wantEnds, wantTouched)
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
