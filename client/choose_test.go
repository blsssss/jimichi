package client_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/client"
)

// a stream of the given 64-bit values, which is what Choose reads per draw
func words(values ...uint64) *bytes.Reader {
	b := make([]byte, 0, 8*len(values))
	for _, v := range values {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return bytes.NewReader(b)
}

func TestChooseGivesDistinctNodesInRange(t *testing.T) {
	stream := rand.New(rand.NewSource(16))
	for n := 1; n <= 8; n++ {
		for hops := 1; hops <= n; hops++ {
			for range 200 {
				path, err := client.Choose(n, hops, stream)
				if err != nil {
					t.Fatalf("Choose(%d, %d): %v", n, hops, err)
				}
				if len(path) != hops {
					t.Fatalf("Choose(%d, %d) gave %d hops", n, hops, len(path))
				}
				seen := make(map[int]bool, hops)
				for _, node := range path {
					if node < 0 || node >= n || seen[node] {
						t.Fatalf("Choose(%d, %d) = %v: a node out of range or taken twice", n, hops, path)
					}
					seen[node] = true
				}
			}
		}
	}
}

func TestChooseRefusesAnImpossibleChoice(t *testing.T) {
	stream := rand.New(rand.NewSource(16))
	for _, c := range []struct{ n, hops int }{{3, 4}, {3, 0}, {3, -1}, {0, 0}, {0, 1}, {-1, 1}} {
		if path, err := client.Choose(c.n, c.hops, stream); !errors.Is(err, client.ErrChoice) || path != nil {
			t.Errorf("Choose(%d, %d) = %v, %v, want ErrChoice", c.n, c.hops, path, err)
		}
	}
	for _, n := range []int{0, -1} {
		if _, err := client.ChooseEntry(n, stream); !errors.Is(err, client.ErrChoice) {
			t.Errorf("ChooseEntry(%d) = %v, want ErrChoice", n, err)
		}
	}
	for _, c := range []struct{ entry, n, hops int }{{3, 3, 2}, {-1, 3, 2}, {0, 3, 4}, {0, 3, 0}} {
		if path, err := client.ChooseRest(c.entry, c.n, c.hops, stream); !errors.Is(err, client.ErrChoice) || path != nil {
			t.Errorf("ChooseRest(%d, %d, %d) = %v, %v, want ErrChoice", c.entry, c.n, c.hops, path, err)
		}
	}
}

// a stream that runs out gives no path: two draws are there, the third is cut
func TestChooseFailsWhenTheStreamEnds(t *testing.T) {
	short := io.MultiReader(words(7, 6), bytes.NewReader([]byte{0, 0, 0}))
	if path, err := client.Choose(5, 3, short); !errors.Is(err, io.ErrUnexpectedEOF) || path != nil {
		t.Fatalf("Choose on a short stream = %v, %v, want io.ErrUnexpectedEOF", path, err)
	}
	if path, err := client.Choose(5, 3, words()); !errors.Is(err, io.EOF) || path != nil {
		t.Fatalf("Choose on an empty stream = %v, %v, want io.EOF", path, err)
	}
}

// worked by hand for 5 nodes and 3 hops on the values 7, 6, 5:
//
//	entry: 7 mod 5 = 2, the others are 0 1 3 4
//	second hop: 6 mod 4 = 2, the third of the others, node 3; they become 3 1 0 4
//	third hop: 5 mod 3 = 2, the third of the remaining 1 0 4, node 4
func TestChooseKnownAnswer(t *testing.T) {
	path, err := client.Choose(5, 3, words(7, 6, 5))
	if err != nil || !slices.Equal(path, []int{2, 3, 4}) {
		t.Fatalf("Choose(5, 3) = %v, %v, want [2 3 4]", path, err)
	}
	// one hop takes one draw, and the path is the entry alone
	stream := words(9, 1)
	path, err = client.Choose(4, 1, stream)
	if err != nil || !slices.Equal(path, []int{1}) || stream.Len() != 8 {
		t.Fatalf("Choose(4, 1) = %v, %v with %d bytes left, want [1] and 8", path, err, stream.Len())
	}
}

// 2^64 mod 6 = 4, since 2^64 is even and leaves 1 modulo 3. Reduced modulo 6
// the 2^64 values would give the remainders 0 to 3 once more often than 4 and
// 5, so the four values 0 to 3 are thrown away and the next one is read.
// 2^64 mod 5 = 1 (16 mod 5 = 1 and 2^64 = 16^16), so only 0 is thrown away;
// 2^64 mod 4 = 0, nothing is
func TestChooseThrowsAwayTheValuesThatWouldBias(t *testing.T) {
	for _, c := range []struct {
		name   string
		n      int
		stream []uint64
		want   int
		left   int
	}{
		{"6 nodes, two values thrown away", 6, []uint64{3, 0, 4, 1}, 4, 8},
		{"6 nodes, the first value kept", 6, []uint64{4, 5}, 4, 8},
		{"6 nodes, a large value", 6, []uint64{math.MaxUint64}, 3, 0},
		{"5 nodes, zero thrown away", 5, []uint64{0, 5}, 0, 0},
		{"5 nodes, one kept", 5, []uint64{1, 5}, 1, 8},
		{"4 nodes, zero kept", 4, []uint64{0, 3}, 0, 8},
	} {
		stream := words(c.stream...)
		path, err := client.Choose(c.n, 1, stream)
		if err != nil || len(path) != 1 || path[0] != c.want || stream.Len() != c.left {
			t.Errorf("%s: Choose = %v, %v with %d bytes left, want [%d] and %d", c.name, path, err, stream.Len(), c.want, c.left)
		}
	}
}

func TestChooseIsTheEntryAndThenTheRest(t *testing.T) {
	whole := rand.New(rand.NewSource(3))
	parts := rand.New(rand.NewSource(3))
	for range 500 {
		want, err := client.Choose(7, 4, whole)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := client.ChooseEntry(7, parts)
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.ChooseRest(entry, 7, 4, parts)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("entry %d and the rest gave %v, %v; Choose on the same stream gave %v", entry, got, err, want)
		}
	}
}

// the 0.999 quantile of chi-square with df degrees of freedom by the
// Wilson-Hilferty approximation, df * (1 - 2/(9 df) + z * sqrt(2/(9 df)))^3
// with z = 3.0902, the same quantile of the normal distribution. For df = 59
// it gives 98.4 against the tabulated 98.3
func chiSquareBound(df int) float64 {
	const z = 3.0902
	a := 2 / (9 * float64(df))
	return float64(df) * math.Pow(1-a+z*math.Sqrt(a), 3)
}

func chiSquare(counts []int, expected float64) float64 {
	var sum float64
	for _, c := range counts {
		d := float64(c) - expected
		sum += d * d / expected
	}
	return sum
}

// n!/(n-hops)! ordered paths, each drawn 1000 times on average: the counts of
// the paths and the counts of the nodes in each position must stay under the
// chi-square bound a uniform choice exceeds once in a thousand streams. The
// stream is seeded, so the test gives the same counts every run
func TestChooseIsUniform(t *testing.T) {
	for _, c := range []struct{ n, hops, paths int }{
		{5, 3, 60},
		{4, 4, 24},
		{7, 2, 42},
		{5, 1, 5},
	} {
		stream := rand.New(rand.NewSource(1))
		const perPath = 1000
		draws := c.paths * perPath
		byPath := make(map[int]int, c.paths)
		byPosition := make([][]int, c.hops)
		for i := range byPosition {
			byPosition[i] = make([]int, c.n)
		}
		for range draws {
			path, err := client.Choose(c.n, c.hops, stream)
			if err != nil {
				t.Fatal(err)
			}
			code := 0
			for position, node := range path {
				code = code*c.n + node
				byPosition[position][node]++
			}
			byPath[code]++
		}
		if len(byPath) != c.paths {
			t.Fatalf("%d nodes, %d hops: %d different paths in %d draws, want all %d", c.n, c.hops, len(byPath), draws, c.paths)
		}
		counts := make([]int, 0, c.paths)
		for _, count := range byPath {
			counts = append(counts, count)
		}
		if got, bound := chiSquare(counts, perPath), chiSquareBound(c.paths-1); got > bound {
			t.Errorf("%d nodes, %d hops: chi-square of the paths %.1f over the bound %.1f", c.n, c.hops, got, bound)
		}
		for position, nodes := range byPosition {
			if slices.Contains(nodes, 0) {
				t.Errorf("%d nodes, %d hops: position %d never held some node: %v", c.n, c.hops, position, nodes)
			}
			if got, bound := chiSquare(nodes, float64(draws)/float64(c.n)), chiSquareBound(c.n-1); got > bound {
				t.Errorf("%d nodes, %d hops: chi-square of position %d is %.1f over the bound %.1f: %v", c.n, c.hops, position, got, bound, nodes)
			}
		}
	}
}

// the same statistic catches a choice that is not uniform: reducing a 3-bit
// value modulo 5 gives 0, 1 and 2 twice as often as 3 and 4
func TestChiSquareBoundCatchesModuloBias(t *testing.T) {
	stream := rand.New(rand.NewSource(1))
	counts := make([]int, 5)
	const draws = 5000
	for range draws {
		counts[stream.Intn(8)%5]++
	}
	if got, bound := chiSquare(counts, draws/5), chiSquareBound(4); got <= bound {
		t.Fatalf("chi-square %.1f of a biased choice is under the bound %.1f", got, bound)
	}
	if bound := chiSquareBound(59); math.Abs(bound-98.4) > 0.1 {
		t.Fatalf("bound for 59 degrees of freedom is %.2f, want 98.4", bound)
	}
}

// a source stuck on a rejected value must not hold the choice forever: among
// three nodes the value 0 is the one thrown away
func TestChoiceGivesUpOnAStuckSource(t *testing.T) {
	if _, err := client.ChooseEntry(3, zeros{}); !errors.Is(err, client.ErrChoice) {
		t.Fatalf("ChooseEntry on a stuck source = %v, want %v", err, client.ErrChoice)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
