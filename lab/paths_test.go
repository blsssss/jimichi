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

func TestSamplePathsRefusesAnImpossibleChoice(t *testing.T) {
	if paths, err := SamplePaths(3, 4, 10, 1); !errors.Is(err, client.ErrChoice) || paths != nil {
		t.Fatalf("SamplePaths(3 nodes, 4 hops) = %v, %v, want ErrChoice", paths, err)
	}
	if paths, err := SamplePaths(5, 3, 0, 1); err != nil || len(paths) != 0 {
		t.Fatalf("SamplePaths of no samples = %v, %v", paths, err)
	}
}
