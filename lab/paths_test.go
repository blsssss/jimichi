package lab

import (
	"errors"
	"math/rand"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/client"
)

func TestSamplePathsRepeatsForASeed(t *testing.T) {
	first, err := SamplePaths(5, 3, 2000, 7)
	if err != nil {
		t.Fatal(err)
	}
	again, err := SamplePaths(5, 3, 2000, 7)
	if err != nil {
		t.Fatal(err)
	}
	other, err := SamplePaths(5, 3, 2000, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2000 {
		t.Fatalf("%d paths, want 2000", len(first))
	}
	differ := 0
	for i, path := range first {
		if !slices.Equal(path, again[i]) {
			t.Fatalf("path %d is %v and then %v for one seed", i, path, again[i])
		}
		if !slices.Equal(path, other[i]) {
			differ++
		}
		seen := map[int]bool{}
		for _, node := range path {
			if node < 0 || node >= 5 || seen[node] {
				t.Fatalf("path %d is %v: a node out of range or taken twice", i, path)
			}
			seen[node] = true
		}
		if len(path) != 3 {
			t.Fatalf("path %d has %d hops, want 3", i, len(path))
		}
	}
	// two of 60 equally likely paths agree once in 60 draws, about 33 of 2000
	if differ < 1800 {
		t.Fatalf("only %d of 2000 paths differ between two seeds", differ)
	}
}

// the sample is the client's own choice read from the path stream of the seed
func TestSamplePathsIsTheChoiceOfTheClient(t *testing.T) {
	paths, err := SamplePaths(7, 4, 300, 3)
	if err != nil {
		t.Fatal(err)
	}
	stream := rand.New(rand.NewSource(Derive(3, streamPaths)))
	for i, path := range paths {
		want, err := client.Choose(7, 4, stream)
		if err != nil || !slices.Equal(path, want) {
			t.Fatalf("path %d is %v, the client draws %v on that stream (%v)", i, path, want, err)
		}
	}
	if Derive(3, streamPaths) == Derive(3, streamPhases) || Derive(3, streamPaths) == Derive(3, streamGaps) {
		t.Fatal("the path stream shares its seed with another stream")
	}
}

func fullMirrors(nodes int) [][]bool {
	mirrors := make([][]bool, nodes)
	for entry := range mirrors {
		mirrors[entry] = make([]bool, nodes)
		for node := range mirrors[entry] {
			mirrors[entry][node] = true
		}
	}
	return mirrors
}

func TestSampleMirrorPathsOfFullMirrorsIsSamplePaths(t *testing.T) {
	want, err := SamplePaths(5, 3, 2000, 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []int{0, 1, 5} {
		paths, refused, err := SampleMirrorPaths(fullMirrors(5), 3, missing, 2000, 7)
		if err != nil || refused != 0 || len(paths) != len(want) {
			t.Fatalf("missing %d: %d paths, %d refused, %v; want %d paths and none refused", missing, len(paths), refused, err, len(want))
		}
		for i, path := range paths {
			if !slices.Equal(path, want[i]) {
				t.Fatalf("missing %d: path %d is %v, SamplePaths gives %v", missing, i, path, want[i])
			}
		}
	}
}

// five nodes, chains of three, the client lets an entry leave out one node;
// entries 3 and 4 leave out node 1, which stands before them in the list, so
// neither they nor the nodes after node 1 are numbered in their mirrors as
// they are listed. The client can build 2*3*2 + 3*4*3 = 48 chains: one of the
// 6 of entry 3 or 4 with 1/5 * 1/6 = 1/30, one of the 12 of entry 0, 1 or 2
// with 1/5 * 1/12 = 1/60. Of 60000 attempts a chain of the first kind is
// expected 2000 times with the deviation
// sqrt(60000 * (1/30)(29/30)) = 44, one of the second kind 1000 times with
// sqrt(60000 * (1/60)(59/60)) = 31; each count must fall within five
// deviations, 220 and 157. The seed fixes the sample
func TestSampleMirrorPathsDrawsAmongTheNodesTheEntryServes(t *testing.T) {
	const samples = 60000
	mirrors := fullMirrors(5)
	mirrors[3][1], mirrors[4][1] = false, false
	paths, refused, err := SampleMirrorPaths(mirrors, 3, 1, samples, 1)
	if err != nil || refused != 0 || len(paths) != samples {
		t.Fatalf("%d paths, %d refused, %v; want %d paths and none refused", len(paths), refused, err, samples)
	}
	counts := map[[3]int]int{}
	for i, path := range paths {
		if len(path) != 3 || path[0] == path[1] || path[0] == path[2] || path[1] == path[2] {
			t.Fatalf("path %d is %v: want three distinct nodes", i, path)
		}
		for _, node := range path {
			if node < 0 || node >= 5 || !mirrors[path[0]][node] {
				t.Fatalf("path %d is %v: entry %d does not serve node %d", i, path, path[0], node)
			}
		}
		counts[[3]int(path)]++
	}
	if len(counts) != 48 {
		t.Fatalf("%d different chains, want 48", len(counts))
	}
	for chain, count := range counts {
		want, bound := 1000, 157
		if chain[0] > 2 {
			want, bound = 2000, 220
		}
		if count < want-bound || count > want+bound {
			t.Errorf("chain %v drawn %d times, want %d within %d", chain, count, want, bound)
		}
	}
}

// nodes 0 and 1 keep their descriptors from the others, so the mirrors of 2, 3
// and 4 lack two nodes and a client that allows one refuses them: 3/5 of the
// attempts, 36000 of 60000 with the deviation sqrt(60000 * 0.6 * 0.4) = 120,
// within five of them, 600. Every path enters through 0 or 1. With two
// allowed nothing is refused and an entry among 2, 3, 4 gives a path of
// exactly those three
func TestSampleMirrorPathsRefusesAMirrorThatLacksTooMuch(t *testing.T) {
	const samples = 60000
	mirrors := fullMirrors(5)
	for entry := 2; entry < 5; entry++ {
		mirrors[entry][0], mirrors[entry][1] = false, false
	}
	paths, refused, err := SampleMirrorPaths(mirrors, 3, 1, samples, 1)
	if err != nil || len(paths)+refused != samples {
		t.Fatalf("%d paths and %d refused of %d attempts (%v)", len(paths), refused, samples, err)
	}
	if refused < 36000-600 || refused > 36000+600 {
		t.Fatalf("%d attempts refused, want 36000 within 600", refused)
	}
	for i, path := range paths {
		if path[0] > 1 {
			t.Fatalf("path %d is %v: its entry serves a mirror the client refuses", i, path)
		}
	}

	paths, refused, err = SampleMirrorPaths(mirrors, 3, 2, samples, 1)
	if err != nil || refused != 0 || len(paths) != samples {
		t.Fatalf("missing 2: %d paths, %d refused, %v; want none refused", len(paths), refused, err)
	}
	for i, path := range paths {
		if path[0] > 1 && (slices.Contains(path, 0) || slices.Contains(path, 1)) {
			t.Fatalf("path %d is %v: entry %d does not serve nodes 0 and 1", i, path, path[0])
		}
	}

	// the bound never exceeds the nodes beyond the hops: a mirror of two nodes
	// holds no chain of three, whatever missing says
	short := fullMirrors(5)
	short[0][2], short[0][3], short[0][4] = false, false, false
	paths, _, err = SampleMirrorPaths(short, 3, 5, 2000, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range paths {
		if path[0] == 0 {
			t.Fatalf("path %d is %v: entry 0 serves two nodes", i, path)
		}
	}

	// an entry that does not serve its own bundle is refused, however few it lacks
	selfless := fullMirrors(5)
	selfless[3][3] = false
	paths, refused, err = SampleMirrorPaths(selfless, 3, 1, 2000, 1)
	if err != nil || refused == 0 {
		t.Fatalf("%d refused, %v; want the attempts through node 3 refused", refused, err)
	}
	for i, path := range paths {
		if path[0] == 3 {
			t.Fatalf("path %d is %v: entry 3 does not serve itself", i, path)
		}
	}
}

// the sample is the client's own choice read from the path stream of the
// seed: the entry among all the nodes, then, unless the attempt is refused,
// the rest among the nodes the entry serves, numbered in the listed order
func TestSampleMirrorPathsIsTheChoiceOfTheClient(t *testing.T) {
	mirrors := fullMirrors(6)
	mirrors[0][2], mirrors[0][5] = false, false
	mirrors[1][0], mirrors[1][2], mirrors[1][3] = false, false, false
	mirrors[4][1] = false
	served := [][]int{{0, 1, 3, 4}, nil, {0, 1, 2, 3, 4, 5}, {0, 1, 2, 3, 4, 5}, {0, 2, 3, 4, 5}, {0, 1, 2, 3, 4, 5}}
	paths, refused, err := SampleMirrorPaths(mirrors, 3, 2, 600, 3)
	if err != nil {
		t.Fatal(err)
	}
	stream := rand.New(rand.NewSource(Derive(3, streamPaths)))
	built, turned := 0, 0
	for attempt := 0; attempt < 600; attempt++ {
		entry, err := client.ChooseEntry(6, stream)
		if err != nil {
			t.Fatal(err)
		}
		if served[entry] == nil {
			turned++
			continue
		}
		rest, err := client.ChooseRest(slices.Index(served[entry], entry), len(served[entry]), 3, stream)
		if err != nil {
			t.Fatal(err)
		}
		want := []int{served[entry][rest[0]], served[entry][rest[1]], served[entry][rest[2]]}
		if built >= len(paths) || !slices.Equal(paths[built], want) {
			t.Fatalf("attempt %d: the client draws %v on that stream, the sample holds %v", attempt, want, paths[min(built, len(paths)-1)])
		}
		built++
	}
	if built != len(paths) || turned != refused || turned == 0 {
		t.Fatalf("%d paths and %d refused, the stream gives %d and %d", len(paths), refused, built, turned)
	}
}

func TestSampleMirrorPathsRefusesWhatCannotBeDrawn(t *testing.T) {
	if paths, _, err := SampleMirrorPaths(fullMirrors(3), 4, 1, 10, 1); !errors.Is(err, client.ErrChoice) || paths != nil {
		t.Fatalf("4 hops among 3 nodes = %v, %v, want ErrChoice", paths, err)
	}
	if _, _, err := SampleMirrorPaths(fullMirrors(3), 0, 1, 10, 1); !errors.Is(err, client.ErrChoice) {
		t.Fatalf("no hops: %v, want ErrChoice", err)
	}
	// the refusal does not wait for an attempt to reach the draw of the chain
	if _, _, err := SampleMirrorPaths(fullMirrors(3), 0, 1, 0, 1); !errors.Is(err, client.ErrChoice) {
		t.Fatalf("no hops and no samples: %v, want ErrChoice", err)
	}
	none := fullMirrors(3)
	for entry := range none {
		none[entry][entry] = false
	}
	if _, _, err := SampleMirrorPaths(none, 0, 1, 10, 1); !errors.Is(err, client.ErrChoice) {
		t.Fatalf("no hops and every attempt refused: %v, want ErrChoice", err)
	}
	if _, _, err := SampleMirrorPaths(fullMirrors(5), 3, -1, 10, 1); err == nil {
		t.Fatal("a negative bound was accepted")
	}
	if _, _, err := SampleMirrorPaths(fullMirrors(5), 3, 1, -1, 1); err == nil {
		t.Fatal("a negative number of samples was accepted")
	}
	ragged := fullMirrors(5)
	ragged[2] = ragged[2][:4]
	if _, _, err := SampleMirrorPaths(ragged, 3, 1, 10, 1); err == nil {
		t.Fatal("a mirror that does not cover every node was accepted")
	}
	if paths, refused, err := SampleMirrorPaths(fullMirrors(5), 3, 1, 0, 1); err != nil || len(paths) != 0 || refused != 0 {
		t.Fatalf("no samples = %v, %d, %v", paths, refused, err)
	}
}

// five nodes; 0 and 1 extend to every node, 2, 3 and 4 to every node but 0,
// whose descriptor they do not hold. Checked pair by pair:
//
//	1 2 0: 2 does not extend to 0, fails
//	0 2 1: 0 to 2 and 2 to 1, comes up
//	2 0 3: 2 does not extend to 0, fails
//	0 1 4: comes up
//	3 4 2: comes up
//	1 0 2: 1 to 0 and 0 to 2, comes up: only an honest node before node 0 fails
//	4: a chain of one node extends nowhere, comes up
//	3 0: fails
//
// five come up, in the order given, and three fail
func TestSurvivingPathsKnownAnswer(t *testing.T) {
	extends := fullMirrors(5)
	for node := 2; node < 5; node++ {
		extends[node][0] = false
	}
	paths := [][]int{{1, 2, 0}, {0, 2, 1}, {2, 0, 3}, {0, 1, 4}, {3, 4, 2}, {1, 0, 2}, {4}, {3, 0}}
	up, failed, err := SurvivingPaths(paths, extends)
	want := [][]int{{0, 2, 1}, {0, 1, 4}, {3, 4, 2}, {1, 0, 2}, {4}}
	if err != nil || failed != 3 || !slices.EqualFunc(up, want, slices.Equal[[]int]) {
		t.Fatalf("SurvivingPaths = %v, %d failed, %v; want %v and 3", up, failed, err, want)
	}

	// when every node extends to every other no path fails
	up, failed, err = SurvivingPaths(paths, fullMirrors(5))
	if err != nil || failed != 0 || !slices.EqualFunc(up, paths, slices.Equal[[]int]) {
		t.Fatalf("every node extends to every other: %v, %d failed, %v", up, failed, err)
	}
	up, failed, err = SurvivingPaths(nil, extends)
	if err != nil || failed != 0 || len(up) != 0 {
		t.Fatalf("no paths = %v, %d, %v", up, failed, err)
	}

	for _, path := range [][]int{{0, 5, 1}, {-1, 2}, {2, 0, 7}} {
		if up, failed, err := SurvivingPaths([][]int{{0, 1}, path}, extends); err == nil || up != nil || failed != 0 {
			t.Errorf("a path %v among five nodes = %v, %d, %v; want an error", path, up, failed, err)
		}
	}
	ragged := fullMirrors(5)
	ragged[3] = ragged[3][:4]
	if _, _, err := SurvivingPaths(paths, ragged); err == nil {
		t.Error("a node that does not say what it extends to was accepted")
	}
}

func TestSamplePathsRefusesAnImpossibleChoice(t *testing.T) {
	if paths, err := SamplePaths(3, 4, 10, 1); !errors.Is(err, client.ErrChoice) || paths != nil {
		t.Fatalf("SamplePaths(3 nodes, 4 hops) = %v, %v, want ErrChoice", paths, err)
	}
	if paths, err := SamplePaths(5, 3, 0, 1); err != nil || len(paths) != 0 {
		t.Fatalf("SamplePaths of no samples = %v, %v", paths, err)
	}
}
