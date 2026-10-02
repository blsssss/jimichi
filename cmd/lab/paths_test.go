package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
	// no mirror lacks a node, so no attempt is refused and every node extends
	// to every other, whatever the draw
	if res.Chains != samples || res.Refused != 0 || res.RefusedExpected != 0 || res.RefusedStdErr != 0 {
		t.Fatalf("%d chains of %d attempts, refused %v [%v +- %v]; want every attempt to give a chain", res.Chains, samples, res.Refused, res.RefusedExpected, res.RefusedStdErr)
	}
	if res.Failed != 0 || res.FailedExpected != 0 || res.FailedStdErr != 0 {
		t.Fatalf("failed at setup %v [%v +- %v], want exactly 0", res.Failed, res.FailedExpected, res.FailedStdErr)
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
// 2/5 + 3/5 * 5/6 = 0.9. No node withholds its descriptor, so no chain fails
// at setup. Standard errors over 60000 chains:
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
	if res.Failed != 0 || res.FailedExpected != 0 || res.FailedStdErr != 0 {
		t.Fatalf("failed at setup %v [%v +- %v], want exactly 0", res.Failed, res.FailedExpected, res.FailedStdErr)
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

	// the row of full mirrors at the same seed is not an independent sample: it
	// reads the same stream, so the entries are the same and so are the chains
	// through the honest ones, and a rogue entry puts a rogue node on its chain
	// either way. The share with a rogue node is the same number in both rows
	full, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, samples: samples, seed: 1})
	if err != nil || full.Touched != res.Touched || full.Ends == res.Ends {
		t.Fatalf("full mirrors at the same seed: %v and %v (%v) against %v and %v; want the same share with a rogue node and another share of rogue ends",
			full.Ends, full.Touched, err, res.Ends, res.Touched)
	}

	// a client that allows no node to be left out refuses the rogue entries, 2/5
	// of its attempts, standard error sqrt(0.4*0.6/60000) = 0.002, and no chain
	// that comes up has a rogue entry. The honest entries serve all five and
	// miss the rogue nodes with (2/4)(1/3) = 1/6: a rogue node in 5/6 of the
	// chains, which are about 36000 of the 60000 attempts, so its standard
	// error is sqrt((5/6)(1/6)/36000) = 0.00196, not the 0.00152 of 60000 draws
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
	if strict.Chains < 35400 || strict.Chains > 36600 {
		t.Fatalf("%d chains, want about 36000", strict.Chains)
	}
	if math.Abs(strict.TouchedExpected-5.0/6) > 1e-12 || math.Abs(strict.TouchedStdErr-0.00196) > 0.00002 || math.Abs(strict.Touched-5.0/6) > 4*strict.TouchedStdErr {
		t.Fatalf("a rogue node in %v [%v +- %v] of the chains, want 5/6 within four standard errors of 0.00196", strict.Touched, strict.TouchedExpected, strict.TouchedStdErr)
	}
	if want := math.Sqrt((5.0 / 6) * (1.0 / 6) / float64(strict.Chains)); math.Abs(strict.TouchedStdErr-want) > 1e-12 {
		t.Fatalf("standard error %v of a share of %d chains at 5/6, want %v", strict.TouchedStdErr, strict.Chains, want)
	}
}

// both rogue nodes of five keep their descriptors from the honest three, whose
// mirrors then lack two nodes; a client that allows one refuses them, 3/5 of
// its attempts with the standard error sqrt(0.6*0.4/60000) = 0.002. Every
// chain it chooses enters through a rogue node, which serves all five. Of the
// 12 chains of such an entry the three with an honest node before the other
// rogue node fail at setup, since that honest node does not hold its
// descriptor: 2/5 * 3/12 = 0.1 of the attempts, standard error
// sqrt(0.1*0.9/60000) = 0.00122. About 0.3 * 60000 = 18000 chains come up: a
// rogue node in every one, and the other rogue node the exit of none, both
// exactly, where the choice alone would give 1/4
func TestPathsSetWhenRogueNodesWithholdTheirDescriptors(t *testing.T) {
	const samples = 60000
	cfg := pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 2, samples: samples, seed: 1}
	res, err := samplePaths(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(res.RefusedExpected-0.6) > 1e-12 || math.Abs(res.RefusedStdErr-0.002) > 0.00001 || math.Abs(res.Refused-0.6) > 4*res.RefusedStdErr {
		t.Fatalf("refused %v [%v +- %v], want 0.6 within four standard errors of 0.002", res.Refused, res.RefusedExpected, res.RefusedStdErr)
	}
	if math.Abs(res.FailedExpected-0.1) > 1e-12 || math.Abs(res.FailedStdErr-0.00122) > 0.00001 || math.Abs(res.Failed-0.1) > 4*res.FailedStdErr {
		t.Fatalf("failed at setup %v [%v +- %v], want 0.1 within four standard errors of 0.00122", res.Failed, res.FailedExpected, res.FailedStdErr)
	}
	if res.Chains+int(math.Round(res.Refused*samples))+int(math.Round(res.Failed*samples)) != samples || res.Chains < 17400 || res.Chains > 18600 {
		t.Fatalf("%d chains, %v refused and %v failed of %d attempts; want about 18000 chains and the three to add up", res.Chains, res.Refused, res.Failed, samples)
	}
	if res.Ends != 0 || res.EndsExpected != 0 || res.EndsStdErr != 0 {
		t.Fatalf("rogue ends %v [%v +- %v], want exactly 0", res.Ends, res.EndsExpected, res.EndsStdErr)
	}
	if res.Touched != 1 || res.TouchedExpected != 1 || res.TouchedStdErr != 0 {
		t.Fatalf("a rogue node in %v [%v +- %v] of the chains, want exactly 1", res.Touched, res.TouchedExpected, res.TouchedStdErr)
	}
	if res.Withheld != 2 || res.LeftOut != 0 || res.Missing != 1 {
		t.Fatalf("the row: %+v", res)
	}

	// the row is the metric of the chains the lab samples over these mirrors
	// and keeps when every node on them extends to the next
	chosen, refused, err := lab.SampleMirrorPaths(mirrorsOf(cfg), 3, 1, samples, 1)
	if err != nil {
		t.Fatal(err)
	}
	up, failed, err := lab.SurvivingPaths(chosen, [][]bool{
		{true, true, true, true, true},
		{true, true, true, true, true},
		{false, false, true, true, true},
		{false, false, true, true, true},
		{false, false, true, true, true},
	})
	if err != nil || len(up) != res.Chains || float64(refused)/samples != res.Refused || float64(failed)/samples != res.Failed {
		t.Fatalf("the lab gives %d chains, %d refused and %d failed (%v), the row %d, %v and %v", len(up), refused, failed, err, res.Chains, res.Refused, res.Failed)
	}
	// of the chains chosen, before setup, a quarter have both ends rogue
	if ends, _ := metrics.CompromiseFraction(chosen, map[int]bool{0: true, 1: true}); math.Abs(ends-0.25) > 0.012 {
		t.Fatalf("both ends rogue in %v of the chains chosen, want 0.25 within 0.012", ends)
	}

	// one withholding node stays within the bound: nothing is refused. Entry 0,
	// the withholding one, gives 12 chains that all come up, three with the
	// exit 1; entry 1 gives 12, of which the three with an honest node before 0
	// fail; an honest entry draws among itself, two honest nodes and node 1,
	// and misses node 1 with (2/3)(1/2) = 1/3. Failed (1/5)(3/12) = 0.05,
	// standard error sqrt(0.05*0.95/60000) = 0.00089. Of the 0.95 that come up,
	// about 57000 chains, both ends are rogue in (1/5)(3/12)/0.95 = 1/19 =
	// 0.0526, standard error sqrt((1/19)(18/19)/57000) = 0.00094, and a rogue
	// node is in (1/5 + (1/5)(9/12) + (3/5)(2/3))/0.95 = 15/19 = 0.7895,
	// standard error sqrt((15/19)(4/19)/57000) = 0.00171
	one, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if one.Refused != 0 || one.RefusedExpected != 0 || one.Chains < 56700 || one.Chains > 57300 {
		t.Fatalf("one withholding node: %+v, want no refusal and about 57000 chains", one)
	}
	if math.Abs(one.FailedExpected-0.05) > 1e-12 || math.Abs(one.FailedStdErr-0.00089) > 0.00001 || math.Abs(one.Failed-0.05) > 4*one.FailedStdErr {
		t.Fatalf("failed at setup %v [%v +- %v], want 0.05 within four standard errors of 0.00089", one.Failed, one.FailedExpected, one.FailedStdErr)
	}
	if math.Abs(one.EndsExpected-1.0/19) > 1e-12 || math.Abs(one.EndsStdErr-0.00094) > 0.00001 || math.Abs(one.Ends-1.0/19) > 4*one.EndsStdErr {
		t.Fatalf("rogue ends %v [%v +- %v], want 1/19 within four standard errors of 0.00094", one.Ends, one.EndsExpected, one.EndsStdErr)
	}
	if math.Abs(one.TouchedExpected-15.0/19) > 1e-12 || math.Abs(one.TouchedStdErr-0.00171) > 0.00001 || math.Abs(one.Touched-15.0/19) > 4*one.TouchedStdErr {
		t.Fatalf("a rogue node in %v [%v +- %v], want 15/19 within four standard errors of 0.00171", one.Touched, one.TouchedExpected, one.TouchedStdErr)
	}
}

// a standard error is that of a share at the value the model gives, not at the
// sampled one, over the draws the share is taken of: the chains that came up
// for the two shares of chains, the attempts for the refused and the failed
// ones. 500 attempts leave the sampled shares visibly off their values, so the
// two readings differ.
//
// One withholding node, one honest node left out, nothing refused: failed
// 1/15, both ends 1/14, a rogue node 11/14 (the metric test works them out).
// With this seed 470 chains come up: sqrt((1/15)(14/15)/500) = 0.01116,
// sqrt((1/14)(13/14)/470) = 0.01188, sqrt((11/14)(3/14)/470) = 0.01893.
//
// A client that allows no node left out: refused 2/5, a rogue node 5/6 over
// the 316 chains of this seed: sqrt(0.4*0.6/500) = 0.02191,
// sqrt((5/6)(1/6)/316) = 0.02097
func TestPathsStandardErrorsAreTakenAtTheModelValues(t *testing.T) {
	const samples = 500
	stderr := func(p float64, n int) float64 { return math.Sqrt(p * (1 - p) / float64(n)) }
	same := func(got, want float64) bool { return math.Abs(got-want) < 1e-12 }

	res, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: 1, withheld: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Chains != 470 || res.Chains != samples-int(math.Round(res.Failed*samples)) {
		t.Fatalf("%d chains of %d attempts with %v failed: want 470, the attempts that did not fail", res.Chains, samples, res.Failed)
	}
	for _, share := range []struct {
		name                      string
		sampled, expected, stderr float64
		value                     float64
		draws                     int
	}{
		{"failed at setup", res.Failed, res.FailedExpected, res.FailedStdErr, 1.0 / 15, samples},
		{"rogue entry and exit", res.Ends, res.EndsExpected, res.EndsStdErr, 1.0 / 14, res.Chains},
		{"any rogue node", res.Touched, res.TouchedExpected, res.TouchedStdErr, 11.0 / 14, res.Chains},
	} {
		if !same(share.expected, share.value) || !same(share.stderr, stderr(share.value, share.draws)) {
			t.Errorf("%s: [%v +- %v], want %v +- %v", share.name, share.expected, share.stderr, share.value, stderr(share.value, share.draws))
		}
		if math.Abs(share.sampled-share.value) < 0.002 {
			t.Errorf("%s: sampled %v is too near %v to tell the two standard errors apart", share.name, share.sampled, share.value)
		}
	}
	if math.Abs(res.FailedStdErr-0.01116) > 0.00001 || math.Abs(res.EndsStdErr-0.01188) > 0.00001 || math.Abs(res.TouchedStdErr-0.01893) > 0.00001 {
		t.Errorf("standard errors %v, %v and %v, want 0.01116, 0.01188 and 0.01893", res.FailedStdErr, res.EndsStdErr, res.TouchedStdErr)
	}

	strict, err := samplePaths(pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 0, leftOut: 1, samples: samples, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strict.Chains != 316 || strict.Chains != samples-int(math.Round(strict.Refused*samples)) {
		t.Fatalf("%d chains of %d attempts with %v refused: want 316, the attempts not refused", strict.Chains, samples, strict.Refused)
	}
	if !same(strict.RefusedExpected, 0.4) || !same(strict.RefusedStdErr, stderr(0.4, samples)) || math.Abs(strict.RefusedStdErr-0.02191) > 0.00001 {
		t.Errorf("refused [%v +- %v], want 0.4 +- 0.02191", strict.RefusedExpected, strict.RefusedStdErr)
	}
	if !same(strict.TouchedExpected, 5.0/6) || !same(strict.TouchedStdErr, stderr(5.0/6, strict.Chains)) {
		t.Errorf("a rogue node [%v +- %v], want 5/6 +- %v", strict.TouchedExpected, strict.TouchedStdErr, stderr(5.0/6, strict.Chains))
	}
	if math.Abs(strict.Refused-0.4) < 0.002 || math.Abs(strict.Touched-5.0/6) < 0.002 {
		t.Errorf("sampled %v and %v are too near 0.4 and 5/6 to tell the two standard errors apart", strict.Refused, strict.Touched)
	}
	if math.Abs(strict.TouchedStdErr-0.02097) > 0.00001 {
		t.Errorf("standard error %v over 316 chains, want 0.02097", strict.TouchedStdErr)
	}
}

// rogue nodes 0 and 1 of five, node 0 withholding, a rogue entry leaving out
// one honest node: the rogue entries serve all but the last node, the honest
// ones all but node 0. A rogue node extends a circuit to every node, the last
// one included, an honest one to the nodes it serves
func TestMirrorsOfTheModel(t *testing.T) {
	cfg := pathsConfig{nodes: 5, rogue: 2, leftOut: 1, withheld: 1}
	got := mirrorsOf(cfg)
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
	wantExtends := [][]bool{
		{true, true, true, true, true},
		{true, true, true, true, true},
		{false, true, true, true, true},
		{false, true, true, true, true},
		{false, true, true, true, true},
	}
	if extends := extendsOf(cfg); !reflect.DeepEqual(extends, wantExtends) {
		t.Fatalf("extends %v, want %v", extends, wantExtends)
	}
	if !reflect.DeepEqual(mirrorsOf(cfg), want) {
		t.Fatal("working out what the nodes extend to changed the mirrors")
	}
	plain := pathsConfig{nodes: 4, rogue: 1}
	for _, served := range [][][]bool{mirrorsOf(plain), extendsOf(plain)} {
		for entry, row := range served {
			for node, yes := range row {
				if !yes {
					t.Fatalf("nothing left out and nothing withheld: node %d does not serve or extend to node %d", entry, node)
				}
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
		if res.Failed != 0 || res.FailedExpected != 0 || res.FailedStdErr != 0 {
			t.Errorf("%d nodes, %d hops, %d rogue: failed at setup %v [%v +- %v], want exactly 0", c.nodes, c.hops, c.rogue, res.Failed, res.FailedExpected, res.FailedStdErr)
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

// each refusal names the flag at fault, and the checks come in an order in
// which no message is worked out from a value another check turns away
func TestPathsSetRefusesWhatCannotBeDrawn(t *testing.T) {
	if _, err := samplePaths(pathsConfig{nodes: 3, hops: 4, rogue: 1, missing: 1, samples: 10, seed: 1}); !errors.Is(err, client.ErrChoice) {
		t.Errorf("more hops than nodes: %v, want ErrChoice", err)
	}
	if _, err := samplePaths(pathsConfig{nodes: 5, hops: 0, rogue: 2, missing: 1, samples: 10, seed: 1}); !errors.Is(err, client.ErrChoice) {
		t.Errorf("no hops: %v, want ErrChoice", err)
	}
	for _, c := range []struct {
		cfg  pathsConfig
		want string
	}{
		{pathsConfig{nodes: 5, hops: 3, rogue: 6, missing: 1, samples: 10}, "-rogue 6: want between 0 and -nodes 5"},
		{pathsConfig{nodes: 5, hops: 3, rogue: -1, missing: 1, samples: 10}, "-rogue -1: want between 0 and -nodes 5"},
		{pathsConfig{nodes: -1, hops: 3, rogue: 0, missing: 1, samples: 10}, "-rogue 0: want between 0 and -nodes -1"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, samples: 0}, "-samples 0: want at least 1"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 6, missing: -1, leftOut: 9, withheld: 9, samples: 0}, "-samples 0: want at least 1"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: -1, samples: 10}, "-missing -1: must not be negative"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: -1, samples: 10}, "-leftout -1: want between 0 and the 3 honest nodes"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, leftOut: 4, samples: 10}, "-leftout 4: want between 0 and the 3 honest nodes"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: -1, samples: 10}, "-withhold -1: want between 0 and -rogue 2"},
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 1, withheld: 3, samples: 10}, "-withhold 3: want between 0 and -rogue 2"},
		// every entry lacks more than the client allows: no chain comes up
		{pathsConfig{nodes: 5, hops: 3, rogue: 2, missing: 0, leftOut: 1, withheld: 2, samples: 10}, "none of the 10 attempts gave a chain that came up"},
	} {
		c.cfg.seed = 1
		if _, err := samplePaths(c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("samplePaths(%+v) = %v, want a refusal saying %q", c.cfg, err, c.want)
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
		Chains: 940, Refused: 0.01, RefusedExpected: 0.02, RefusedStdErr: 0.0044,
		Failed: 0.05, FailedExpected: 0.06, FailedStdErr: 0.0075,
		Ends: 0.136, EndsExpected: 0.1333, EndsStdErr: 0.0108,
		Touched: 0.897, TouchedExpected: 0.9, TouchedStdErr: 0.0095,
		EndsUniform: 0.1, TouchedUniform: 0.9,
	}
	var out bytes.Buffer
	printPaths(&out, res)
	lines := strings.Split(out.String(), "\n")
	want := "5 3 2 1 1 0 1000 940 0.0100 [0.0200 +- 0.0044] 0.0500 [0.0600 +- 0.0075] 0.1360 [0.1333 +- 0.0108] 0.8970 [0.9000 +- 0.0095]"
	if len(lines) < 2 || strings.Join(strings.Fields(lines[1]), " ") != want {
		t.Fatalf("printed row:\n%s", out.String())
	}
	wantHeader := "nodes hops rogue missing leftout withhold samples chains refused failed at setup rogue entry and exit any rogue node"
	if strings.Join(strings.Fields(lines[0]), " ") != wantHeader {
		t.Fatalf("printed header:\n%s", lines[0])
	}
	if len(lines[0]) != len(lines[1]) {
		t.Fatalf("the header and the row are not aligned:\n%s", out.String())
	}
	// each share of the row sits under the end of its own column title
	for _, column := range []struct{ title, share string }{
		{"refused", "0.0100 [0.0200 +- 0.0044]"},
		{"failed at setup", "0.0500 [0.0600 +- 0.0075]"},
		{"rogue entry and exit", "0.1360 [0.1333 +- 0.0108]"},
		{"any rogue node", "0.8970 [0.9000 +- 0.0095]"},
	} {
		if strings.Index(lines[0], column.title)+len(column.title) != strings.Index(lines[1], column.share)+len(column.share) {
			t.Errorf("the share %s is not under the column %q:\n%s", column.share, column.title, out.String())
		}
	}
	for _, said := range []string{
		"refused: share of the attempts whose entry served a mirror the client refuses",
		"failed at setup: share of the attempts whose chosen chain has an honest node before a node whose descriptor it does not hold",
		"chains: the attempts whose chain came up; the last two columns are shares of those chains",
		"in brackets what the model gives and the standard error of a share of that many draws at that value",
		"where that value is 0 or 1 every draw gives the same answer: the share is exact by construction, not sampled",
		"full mirrors, a uniform choice: 0.1000 and 0.9000, k(k-1)/(N(N-1)) and 1 - C(N-k,h)/C(N,h)",
	} {
		if !strings.Contains(out.String(), said+"\n") {
			t.Errorf("the printed report does not say %q:\n%s", said, out.String())
		}
	}
	// a chain of one node has both ends rogue when that node is: two of five,
	// k/N = 0.4, where k(k-1)/(N(N-1)) = 2*1/(5*4) is 0.1. A rogue node is in
	// 1 - C(3,1)/C(5,1) = 1 - 3/5 = 0.4 of them, the same chains
	single, err := samplePaths(pathsConfig{nodes: 5, hops: 1, rogue: 2, missing: 1, samples: 200, seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	var one bytes.Buffer
	printPaths(&one, single)
	if want := "full mirrors, a uniform choice: 0.4000 and 0.4000, k/N and 1 - C(N-k,h)/C(N,h)\n"; !strings.HasSuffix(one.String(), want) || strings.Contains(one.String(), "k(k-1)") {
		t.Errorf("chains of one node are printed with:\n%swant the last line %q", one.String(), want)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	wantRow := `{"nodes":5,"hops":3,"rogue_nodes":2,"missing":1,"left_out":1,"withheld":0,"samples":1000,"seed":9,"rev":"abc",` +
		`"chains":940,"refused":0.01,"refused_expected":0.02,"refused_stderr":0.0044,` +
		`"failed_at_setup":0.05,"failed_at_setup_expected":0.06,"failed_at_setup_stderr":0.0075,` +
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

func reports(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// the command reads every flag of the paths set into the part of the
// configuration it names, prints the row and writes it, with the revision,
// to a report named after the configuration. No two flags carry the same
// value, and none its default, so a flag read into another's place, or not
// read, gives another row and another name
func TestPathsSetFromTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := command([]string{"-set", "paths", "-nodes", "6", "-hops", "3", "-rogue", "3", "-missing", "2",
		"-leftout", "1", "-withhold", "2", "-samples", "300", "-seed", "7", "-rev", "abc", "-out", dir}, &out, &errOut)
	if status != 0 || errOut.Len() != 0 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}
	want, err := samplePaths(pathsConfig{nodes: 6, hops: 3, rogue: 3, missing: 2, leftOut: 1, withheld: 2, samples: 300, seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	want.Rev = "abc"

	names := reports(t, dir)
	named := regexp.MustCompile(`^paths-nodes6-hops3-rogue3-missing2-leftout1-withhold2-samples300-seed7-\d{8}-\d{6}\.json$`)
	if len(names) != 1 || !named.MatchString(names[0]) {
		t.Fatalf("reports %v, want one named after the configuration", names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	var rows []pathsResult
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) != 1 || rows[0] != want {
		t.Fatalf("the report holds %+v (%v), want one row %+v", rows, err, want)
	}
	var printed bytes.Buffer
	printPaths(&printed, want)
	if !strings.HasPrefix(out.String(), printed.String()) || !strings.Contains(out.String(), "report: "+filepath.Join(dir, names[0])) {
		t.Fatalf("printed:\n%s\nwant the row of the report and its path", out.String())
	}

	// the defaults are the client's -missing 1 and full mirrors; without -rev
	// the row is written with a warning
	dir = t.TempDir()
	out.Reset()
	status = command([]string{"-set", "paths", "-samples", "200", "-out", dir}, &out, &errOut)
	names = reports(t, dir)
	named = regexp.MustCompile(`^paths-nodes5-hops3-rogue2-missing1-leftout0-withhold0-samples200-seed1-\d{8}-\d{6}\.json$`)
	if status != 0 || len(names) != 1 || !named.MatchString(names[0]) || !strings.Contains(errOut.String(), "no -rev given") {
		t.Fatalf("status %d, reports %v, stderr %q; want the default configuration and a warning", status, names, errOut.String())
	}

	// a configuration that cannot be drawn writes no report
	for _, args := range [][]string{
		{"-set", "paths", "-samples", "200", "-rev", "abc", "-withhold", "3"},
		{"-set", "paths", "-samples", "200", "-rev", "abc", "-missing", "0", "-leftout", "1", "-withhold", "2"},
		{"-set", "paths", "-samples", "200", "-rev", "abc", "-leftout"},
		{"-set", "paths", "-samples", "200", "-rev", "abc", "-no-such-flag"},
	} {
		dir = t.TempDir()
		errOut.Reset()
		status := command(append(args[:len(args):len(args)], "-out", dir), &out, &errOut)
		if names := reports(t, dir); status != 2 || len(names) != 0 || errOut.Len() == 0 {
			t.Errorf("%v: status %d, reports %v, stderr %q; want 2, no report and a message", args, status, names, errOut.String())
		}
	}
}
