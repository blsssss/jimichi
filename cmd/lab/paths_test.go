package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// five nodes, two of them rogue, chains of three, full mirrors: a uniform
// choice puts rogue nodes at both ends of 2*1/(5*4) = 0.1 of the chains and
// somewhere in 1 - (3/5)(2/4)(1/3) = 0.9 of them. A share of 60000 draws with
// p = 0.1 or 0.9 has the standard error sqrt(0.1*0.9/60000) = 0.00122, and the
// sample must fall within four of them, 0.0049. The seed fixes the sample, so
// the test gives the same shares every run
func TestPathsSetAgreesWithAUniformChoice(t *testing.T) {
	const samples = 60000
	cfg := pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, samples: samples, seed: 1}
	res, err := samplePaths(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.EndsExpected-0.1) > 1e-12 || math.Abs(res.TouchedExpected-0.9) > 1e-12 {
		t.Fatalf("expected shares %v and %v, want 0.1 and 0.9", res.EndsExpected, res.TouchedExpected)
	}
	if math.Abs(res.EndsUniform-0.1) > 1e-12 || math.Abs(res.TouchedUniform-0.9) > 1e-12 {
		t.Fatalf("shares of full mirrors %v and %v, want 0.1 and 0.9", res.EndsUniform, res.TouchedUniform)
	}
	if math.Abs(res.EndsStdErr-0.00122) > 0.00001 || math.Abs(res.TouchedStdErr-0.00122) > 0.00001 {
		t.Fatalf("standard errors %v and %v, want 0.00122", res.EndsStdErr, res.TouchedStdErr)
	}
	bound := 4 * res.EndsStdErr
	if math.Abs(bound-0.0049) > 0.0001 {
		t.Fatalf("bound %v, want 0.0049", bound)
	}
	if math.Abs(res.Ends-0.1) > bound || math.Abs(res.Touched-0.9) > bound {
		t.Fatalf("sampled shares %v and %v are further than %v from 0.1 and 0.9", res.Ends, res.Touched, bound)
	}
	if res.Nodes != 5 || res.Hops != 3 || res.Rogue != 2 || res.Missing != 1 || res.LeftOut != 0 || res.Withheld != 0 || res.Samples != samples || res.Seed != 1 {
		t.Fatalf("the row lost its configuration: %+v", res)
	}
	// no mirror lacks a node, so no attempt is refused, whatever the draw
	if res.Chains != samples || res.Refused != 0 || res.RefusedExpected != 0 || res.RefusedStdErr != 0 {
		t.Fatalf("%d chains of %d attempts, refused %v [%v +- %v]; want every attempt to build a chain", res.Chains, samples, res.Refused, res.RefusedExpected, res.RefusedStdErr)
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

	again, err := samplePaths(cfg)
	if err != nil || again != res {
		t.Fatalf("the same seed gave %+v and then %+v (%v)", res, again, err)
	}
	cfg.seed = 2
	other, err := samplePaths(cfg)
	if err != nil || other.Ends == res.Ends && other.Touched == res.Touched {
		t.Fatalf("another seed gave the same sample: %+v (%v)", other, err)
	}
}

// the reference case: five nodes, two rogue, chains of three, the client lets
// an entry leave out one node and a rogue entry leaves out one honest node.
// The entry is rogue with 2/5 and then draws its exit among the three other
// nodes it serves, one of them rogue: 2/5 * 1/3 = 2/15 = 0.1333 against 0.1
// for full mirrors. A rogue node: 2/5 for a rogue entry, and an honest one
// serves all five and misses the rogue nodes with (2/4)(1/3) = 1/6, so
// 2/5 + 3/5 * 5/6 = 0.9. Standard errors over 60000 chains:
// sqrt((2/15)(13/15)/60000) = 0.00139 and sqrt(0.9*0.1/60000) = 0.00122; the
// sample must fall within four of each
func TestPathsSetWhenARogueEntryLeavesOutAnHonestNode(t *testing.T) {
	const samples = 60000
	res, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.EndsExpected-2.0/15) > 1e-12 || math.Abs(res.TouchedExpected-0.9) > 1e-12 || res.RefusedExpected != 0 {
		t.Fatalf("expected %v, %v and %v refused, want 2/15, 0.9 and 0", res.EndsExpected, res.TouchedExpected, res.RefusedExpected)
	}
	if math.Abs(res.EndsStdErr-0.00139) > 0.00001 || math.Abs(res.TouchedStdErr-0.00122) > 0.00001 {
		t.Fatalf("standard errors %v and %v, want 0.00139 and 0.00122", res.EndsStdErr, res.TouchedStdErr)
	}
	if math.Abs(res.Ends-2.0/15) > 4*res.EndsStdErr || math.Abs(res.Touched-0.9) > 4*res.TouchedStdErr {
		t.Fatalf("sampled shares %v and %v are further than four standard errors from 2/15 and 0.9", res.Ends, res.Touched)
	}
	// the sample tells the narrowed choice from the uniform one: 0.0333 apart,
	// 24 standard errors
	if math.Abs(res.EndsUniform-0.1) > 1e-12 || res.Ends-res.EndsUniform < 20*res.EndsStdErr {
		t.Fatalf("sampled %v against %v for full mirrors: want them 0.0333 apart", res.Ends, res.EndsUniform)
	}
	if res.Chains != samples || res.Refused != 0 || res.Missing != 1 || res.LeftOut != 1 || res.Withheld != 0 {
		t.Fatalf("the row: %+v", res)
	}

	// the row is the metric of the paths the lab samples over these mirrors
	paths, refused, err := lab.SampleMirrorPaths([][]bool{
		{true, true, true, true, false},
		{true, true, true, true, false},
		{true, true, true, true, true},
		{true, true, true, true, true},
		{true, true, true, true, true},
	}, 3, 1, samples, 1)
	if err != nil || refused != 0 {
		t.Fatal(refused, err)
	}
	ends, touched := metrics.CompromiseFraction(paths, map[int]bool{0: true, 1: true})
	if res.Ends != ends || res.Touched != touched {
		t.Fatalf("row %v and %v, the sampled paths give %v and %v", res.Ends, res.Touched, ends, touched)
	}

	// a client that allows no node to be left out refuses the rogue entries, 2/5
	// of its attempts, standard error sqrt(0.4*0.6/60000) = 0.002, and no chain
	// it builds has a rogue entry
	strict, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 0, leftOut: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(strict.RefusedExpected-0.4) > 1e-12 || math.Abs(strict.RefusedStdErr-0.002) > 0.00001 || math.Abs(strict.Refused-0.4) > 4*strict.RefusedStdErr {
		t.Fatalf("refused %v [%v +- %v], want 0.4 within four standard errors of 0.002", strict.Refused, strict.RefusedExpected, strict.RefusedStdErr)
	}
	if strict.Chains != samples-int(math.Round(strict.Refused*samples)) || strict.Ends != 0 || strict.EndsExpected != 0 || strict.EndsStdErr != 0 {
		t.Fatalf("%d chains, rogue ends %v [%v +- %v]; want the attempts not refused and exactly 0", strict.Chains, strict.Ends, strict.EndsExpected, strict.EndsStdErr)
	}
}

// both rogue nodes of five keep their descriptors from the honest three, whose
// mirrors then lack two nodes; a client that allows one refuses them, 3/5 of
// its attempts with the standard error sqrt(0.6*0.4/60000) = 0.002. Every
// chain enters through a rogue node, which serves all five: a rogue node in
// every chain, exactly, and the exit rogue with 1/4. The chains are about
// 24000, so the standard error of that share is about
// sqrt(0.25*0.75/24000) = 0.0028
func TestPathsSetWhenRogueNodesWithholdTheirDescriptors(t *testing.T) {
	const samples = 60000
	res, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 2, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.RefusedExpected-0.6) > 1e-12 || math.Abs(res.RefusedStdErr-0.002) > 0.00001 || math.Abs(res.Refused-0.6) > 4*res.RefusedStdErr {
		t.Fatalf("refused %v [%v +- %v], want 0.6 within four standard errors of 0.002", res.Refused, res.RefusedExpected, res.RefusedStdErr)
	}
	if res.Chains+int(math.Round(res.Refused*samples)) != samples || res.Chains < 23000 || res.Chains > 25000 {
		t.Fatalf("%d chains and %v refused of %d attempts", res.Chains, res.Refused, samples)
	}
	if res.EndsExpected != 0.25 || math.Abs(res.EndsStdErr-0.0028) > 0.0001 || math.Abs(res.Ends-0.25) > 4*res.EndsStdErr {
		t.Fatalf("rogue ends %v [%v +- %v], want 0.25 within four standard errors of 0.0028", res.Ends, res.EndsExpected, res.EndsStdErr)
	}
	if res.Touched != 1 || res.TouchedExpected != 1 || res.TouchedStdErr != 0 {
		t.Fatalf("a rogue node in %v [%v +- %v] of the chains, want exactly 1", res.Touched, res.TouchedExpected, res.TouchedStdErr)
	}
	if res.Withheld != 2 || res.LeftOut != 0 || res.Missing != 1 {
		t.Fatalf("the row: %+v", res)
	}

	// one withholding node stays within the bound: nothing is refused, the
	// honest entries draw among four nodes with one rogue one, missing it with
	// (2/3)(1/2) = 1/3: (2 + 3 * 2/3)/5 = 0.8; both ends stay (2 * 1/4)/5 = 0.1
	one, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if one.Chains != samples || one.Refused != 0 || math.Abs(one.EndsExpected-0.1) > 1e-12 || math.Abs(one.TouchedExpected-0.8) > 1e-12 {
		t.Fatalf("one withholding node: %+v, want no refusal, 0.1 and 0.8", one)
	}
	if math.Abs(one.Ends-0.1) > 4*one.EndsStdErr || math.Abs(one.Touched-0.8) > 4*one.TouchedStdErr {
		t.Fatalf("sampled shares %v and %v are further than four standard errors from 0.1 and 0.8", one.Ends, one.Touched)
	}
}

// rogue nodes 0 and 1 of five, node 0 withholding, a rogue entry leaving out
// one honest node: the rogue entries serve all but the last node, the honest
// ones all but node 0
func TestMirrorsOfTheModel(t *testing.T) {
	got := mirrorsOf(pathsConfig{nodes: 5, rogue: 2, leftOut: 1, withheld: 1})
	want := [][]bool{
		{true, true, true, true, false},
		{true, true, true, true, false},
		{false, true, true, true, true},
		{false, true, true, true, true},
		{false, true, true, true, true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirrors %v, want %v", got, want)
	}
	for entry, mirror := range mirrorsOf(pathsConfig{nodes: 4, rogue: 1}) {
		for node, served := range mirror {
			if !served {
				t.Fatalf("nothing left out and nothing withheld: entry %d does not serve node %d", entry, node)
			}
		}
	}
}

// a share that the choice makes 0 or 1 is the same for every draw: the row
// repeats it with a standard error of 0. With every node rogue each chain is
// held, with none no chain is; a chain as long as the list holds every node,
// so one rogue node is in all of them and cannot be both ends; one rogue node
// among five is never both ends of a longer chain, whatever it leaves out
func TestPathsSetAtTheEdges(t *testing.T) {
	for _, c := range []struct {
		nodes, hops, rogue, leftOut int
		ends, touched               float64
		sampledTouched              bool
	}{
		{5, 3, 5, 0, 1, 1, false},
		{5, 3, 0, 0, 0, 0, false},
		{3, 3, 1, 0, 0, 1, false},
		{4, 1, 4, 0, 1, 1, false},
		{5, 3, 1, 1, 0, 0.6, true},
	} {
		res, err := samplePaths(pathsConfig{nodes: c.nodes, hops: c.hops, rogue: c.rogue, missing: 1, leftOut: c.leftOut, samples: 500, seed: 1})
		if err != nil || res.Ends != c.ends || res.EndsExpected != c.ends || res.EndsStdErr != 0 {
			t.Errorf("%d nodes, %d hops, %d rogue: %+v, %v; want both ends %v sampled and expected, standard error 0", c.nodes, c.hops, c.rogue, res, err, c.ends)
		}
		if c.sampledTouched {
			if math.Abs(res.TouchedExpected-c.touched) > 1e-12 || res.TouchedStdErr == 0 {
				t.Errorf("%d nodes, %d hops, %d rogue: a rogue node expected in %v +- %v, want %v and a standard error above 0", c.nodes, c.hops, c.rogue, res.TouchedExpected, res.TouchedStdErr, c.touched)
			}
			continue
		}
		if res.Touched != c.touched || res.TouchedExpected != c.touched || res.TouchedStdErr != 0 {
			t.Errorf("%d nodes, %d hops, %d rogue: %+v; want a rogue node in %v sampled and expected, standard error 0", c.nodes, c.hops, c.rogue, res, c.touched)
		}
	}
}

func TestPathsSetRefusesWhatCannotBeDrawn(t *testing.T) {
	if _, err := samplePaths(pathsConfig{nodes: 3, hops: 4, rogue: 1, missing: 1, samples: 10, seed: 1}); !errors.Is(err, client.ErrChoice) {
		t.Errorf("more hops than nodes: %v, want ErrChoice", err)
	}
	for _, c := range []pathsConfig{
		{nodes: 5, hops: 3, rogue: 6, missing: 1, samples: 10},
		{nodes: 5, hops: 3, rogue: -1, missing: 1, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, samples: 0},
		{nodes: 5, hops: 0, rogue: 2, missing: 1, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: -1, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: -1, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: 4, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: -1, samples: 10},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 3, samples: 10},
		{nodes: -1, hops: 3, rogue: 0, missing: 1, samples: 10},
		// every entry lacks more than the client allows: no chain is built
		{nodes: 5, hops: 3, rogue: 2, missing: 0, leftOut: 1, withheld: 2, samples: 10},
	} {
		c.seed = 1
		if _, err := samplePaths(c); err == nil {
			t.Errorf("samplePaths(%+v) succeeded", c)
		}
	}
}

// runs that differ in any part of the configuration write different files even
// within one second; the same configuration draws the same sample
func TestPathsReportNameCarriesTheConfiguration(t *testing.T) {
	at := time.Date(2026, 10, 2, 15, 4, 5, 0, time.FixedZone("", 3*3600))
	base := pathsResult{Nodes: 5, Hops: 3, Rogue: 2, Missing: 1, LeftOut: 1, Withheld: 0, Samples: 100000, Seed: 7}
	name := pathsReportName(base, at)
	if want := "paths-nodes5-hops3-rogue2-missing1-leftout1-withhold0-samples100000-seed7-20261002-120405"; name != want {
		t.Fatalf("report name %s, want %s", name, want)
	}
	seen := map[string]bool{name: true}
	for i, change := range []func(*pathsResult){
		func(r *pathsResult) { r.Nodes = 6 },
		func(r *pathsResult) { r.Hops = 2 },
		func(r *pathsResult) { r.Rogue = 1 },
		func(r *pathsResult) { r.Missing = 2 },
		func(r *pathsResult) { r.LeftOut = 0 },
		func(r *pathsResult) { r.Withheld = 1 },
		func(r *pathsResult) { r.Samples = 10000 },
		func(r *pathsResult) { r.Seed = -7 },
	} {
		other := base
		change(&other)
		if n := pathsReportName(other, at); seen[n] {
			t.Errorf("change %d: the report name %s is taken by another configuration", i, n)
		} else {
			seen[n] = true
		}
	}
	if pathsReportName(base, at.Add(time.Second)) == name {
		t.Error("a later run takes the name of an earlier one")
	}
}

func TestPathsRowIsPrintedAndEncodedWithItsConfiguration(t *testing.T) {
	res := pathsResult{
		Nodes: 5, Hops: 3, Rogue: 2, Missing: 1, LeftOut: 1, Withheld: 0, Samples: 1000, Seed: 9, Rev: "abc",
		Chains: 990, Refused: 0.01, RefusedExpected: 0.02, RefusedStdErr: 0.0044,
		Ends: 0.136, EndsExpected: 0.1333, EndsStdErr: 0.0108,
		Touched: 0.897, TouchedExpected: 0.9, TouchedStdErr: 0.0095,
		EndsUniform: 0.1, TouchedUniform: 0.9,
	}
	var out bytes.Buffer
	printPaths(&out, res)
	lines := strings.Split(out.String(), "\n")
	want := "5 3 2 1 1 0 1000 990 0.0100 [0.0200 +- 0.0044] 0.1360 [0.1333 +- 0.0108] 0.8970 [0.9000 +- 0.0095]"
	if len(lines) < 2 || strings.Join(strings.Fields(lines[1]), " ") != want {
		t.Fatalf("printed row:\n%s", out.String())
	}
	if len(lines[0]) != len(lines[1]) {
		t.Fatalf("the header and the row are not aligned:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "full mirrors, a uniform choice: 0.1000 and 0.9000") {
		t.Fatalf("no line for full mirrors:\n%s", out.String())
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	wantRow := `{"nodes":5,"hops":3,"rogue_nodes":2,"missing":1,"left_out":1,"withheld":0,"samples":1000,"seed":9,"rev":"abc",` +
		`"chains":990,"refused":0.01,"refused_expected":0.02,"refused_stderr":0.0044,` +
		`"rogue_entry_and_exit":0.136,"rogue_entry_and_exit_expected":0.1333,"rogue_entry_and_exit_stderr":0.0108,` +
		`"any_rogue_node":0.897,"any_rogue_node_expected":0.9,"any_rogue_node_stderr":0.0095,` +
		`"rogue_entry_and_exit_full_mirrors":0.1,"any_rogue_node_full_mirrors":0.9}`
	if string(raw) != wantRow {
		t.Fatalf("row encodes as %s, want %s", raw, wantRow)
	}

	// every row the set can produce encodes: no share of it is undefined
	for _, c := range []pathsConfig{
		{nodes: 5, hops: 3, rogue: 2, missing: 1, samples: 200, seed: 1},
		{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 2, samples: 200, seed: 1},
		{nodes: 5, hops: 3, rogue: 0, missing: 0, samples: 200, seed: 1},
		{nodes: 5, hops: 3, rogue: 5, missing: 2, samples: 200, seed: 1},
	} {
		row, err := samplePaths(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(row); err != nil {
			t.Errorf("the row of %+v does not encode: %v", c, err)
		}
	}
}
