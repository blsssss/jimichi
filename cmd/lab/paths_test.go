package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// five nodes, two of them rogue, chains of three: a uniform choice puts rogue
// nodes at both ends of 2*1/(5*4) = 0.1 of the chains and somewhere in
// 1 - (3/5)(2/4)(1/3) = 0.9 of them. A share of 60000 draws with p = 0.1 or
// 0.9 has the standard error sqrt(0.1*0.9/60000) = 0.00122, and the sample
// must fall within four of them, 0.0049. The seed fixes the sample, so the
// test gives the same shares every run
func TestPathsSetAgreesWithAUniformChoice(t *testing.T) {
	const samples = 60000
	res, err := samplePaths(5, 3, 2, samples, 1)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.EndsExpected-0.1) > 1e-12 || math.Abs(res.TouchedExpected-0.9) > 1e-12 {
		t.Fatalf("expected shares %v and %v, want 0.1 and 0.9", res.EndsExpected, res.TouchedExpected)
	}
	bound := 4 * math.Sqrt(0.1*0.9/samples)
	if math.Abs(bound-0.0049) > 0.0001 {
		t.Fatalf("bound %v, want 0.0049", bound)
	}
	if math.Abs(res.Ends-0.1) > bound || math.Abs(res.Touched-0.9) > bound {
		t.Fatalf("sampled shares %v and %v are further than %v from 0.1 and 0.9", res.Ends, res.Touched, bound)
	}
	if res.Nodes != 5 || res.Hops != 3 || res.Rogue != 2 || res.Samples != samples || res.Seed != 1 {
		t.Fatalf("the row lost its configuration: %+v", res)
	}

	// the shares are the metric of the very paths the lab samples for that seed
	paths, err := lab.SamplePaths(5, 3, samples, 1)
	if err != nil {
		t.Fatal(err)
	}
	ends, touched := metrics.CompromiseFraction(paths, map[int]bool{0: true, 1: true})
	if res.Ends != ends || res.Touched != touched {
		t.Fatalf("row %v and %v, the sampled paths give %v and %v", res.Ends, res.Touched, ends, touched)
	}

	again, err := samplePaths(5, 3, 2, samples, 1)
	if err != nil || again != res {
		t.Fatalf("the same seed gave %+v and then %+v (%v)", res, again, err)
	}
	other, err := samplePaths(5, 3, 2, samples, 2)
	if err != nil || other.Ends == res.Ends && other.Touched == res.Touched {
		t.Fatalf("another seed gave the same sample: %+v (%v)", other, err)
	}
}

// with every node rogue each chain is held, with none no chain is; a chain as
// long as the list holds every node, so one rogue node is in all of them
func TestPathsSetAtTheEdges(t *testing.T) {
	for _, c := range []struct {
		nodes, hops, rogue int
		ends, touched      float64
	}{
		{5, 3, 5, 1, 1},
		{5, 3, 0, 0, 0},
		{3, 3, 1, 0, 1},
		{4, 1, 4, 1, 1},
	} {
		res, err := samplePaths(c.nodes, c.hops, c.rogue, 500, 1)
		if err != nil || res.Ends != c.ends || res.Touched != c.touched || res.EndsExpected != c.ends || res.TouchedExpected != c.touched {
			t.Errorf("%d nodes, %d hops, %d rogue: %+v, %v; want %v and %v sampled and expected", c.nodes, c.hops, c.rogue, res, err, c.ends, c.touched)
		}
	}
}

func TestPathsSetRefusesWhatCannotBeDrawn(t *testing.T) {
	if _, err := samplePaths(3, 4, 1, 10, 1); !errors.Is(err, client.ErrChoice) {
		t.Errorf("more hops than nodes: %v, want ErrChoice", err)
	}
	for _, c := range []struct{ nodes, hops, rogue, samples int }{
		{5, 3, 6, 10}, {5, 3, -1, 10}, {5, 3, 2, 0}, {5, 0, 2, 10},
	} {
		if _, err := samplePaths(c.nodes, c.hops, c.rogue, c.samples, 1); err == nil {
			t.Errorf("samplePaths(%d, %d, %d, %d) succeeded", c.nodes, c.hops, c.rogue, c.samples)
		}
	}
}

func TestPathsRowIsPrintedAndEncodedWithItsConfiguration(t *testing.T) {
	res := pathsResult{Nodes: 5, Hops: 3, Rogue: 2, Samples: 1000, Seed: 9, Rev: "abc", Ends: 0.104, EndsExpected: 0.1, Touched: 0.897, TouchedExpected: 0.9}
	var out bytes.Buffer
	printPaths(&out, res)
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 2 || strings.Join(strings.Fields(lines[1]), " ") != "5 3 2 1000 0.1040 [0.1000] 0.8970 [0.9000]" {
		t.Fatalf("printed row:\n%s", out.String())
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodes":5,"hops":3,"rogue_nodes":2,"samples":1000,"seed":9,"rev":"abc",` +
		`"rogue_entry_and_exit":0.104,"rogue_entry_and_exit_expected":0.1,"any_rogue_node":0.897,"any_rogue_node_expected":0.9}`
	if string(raw) != want {
		t.Fatalf("row encodes as %s, want %s", raw, want)
	}
}
