package main

import (
	"fmt"
	"io"
	"time"

	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// what the paths set draws: the client's choice and bound, and what the rogue
// nodes do with the mirrors
type pathsConfig struct {
	nodes, hops, rogue int
	// listed nodes the client lets an entry leave out, as -missing of the client
	missing int
	// honest nodes a rogue entry leaves out of its mirror
	leftOut int
	// rogue nodes that keep their descriptors from the honest nodes
	withheld int
	samples  int
	seed     int64
}

// the paths set: the shares of the sampled chains the adversary holds, each
// next to the value the choice gives and the standard error of a share of
// that many chains at that value, with everything needed to draw the same
// sample again. An attempt whose entry serves a mirror the client refuses
// builds no chain; the shares of chains are over the attempts that built one
type pathsResult struct {
	Nodes    int    `json:"nodes"`
	Hops     int    `json:"hops"`
	Rogue    int    `json:"rogue_nodes"`
	Missing  int    `json:"missing"`
	LeftOut  int    `json:"left_out"`
	Withheld int    `json:"withheld"`
	Samples  int    `json:"samples"`
	Seed     int64  `json:"seed"`
	Rev      string `json:"rev"`

	Chains          int     `json:"chains"`
	Refused         float64 `json:"refused"`
	RefusedExpected float64 `json:"refused_expected"`
	RefusedStdErr   float64 `json:"refused_stderr"`

	Ends            float64 `json:"rogue_entry_and_exit"`
	EndsExpected    float64 `json:"rogue_entry_and_exit_expected"`
	EndsStdErr      float64 `json:"rogue_entry_and_exit_stderr"`
	Touched         float64 `json:"any_rogue_node"`
	TouchedExpected float64 `json:"any_rogue_node_expected"`
	TouchedStdErr   float64 `json:"any_rogue_node_stderr"`

	// what a uniform choice among all the nodes gives, the case of full mirrors
	EndsUniform    float64 `json:"rogue_entry_and_exit_full_mirrors"`
	TouchedUniform float64 `json:"any_rogue_node_full_mirrors"`
}

// every honest node is as likely as any other in every position, and so is
// every rogue one, so which nodes are rogue, withhold or are left out does not
// change the shares: the first nodes are rogue, the first of those withhold,
// and a rogue entry leaves out the last nodes
func mirrorsOf(c pathsConfig) [][]bool {
	mirrors := make([][]bool, c.nodes)
	for entry := range mirrors {
		mirrors[entry] = make([]bool, c.nodes)
		for node := range mirrors[entry] {
			if entry < c.rogue {
				mirrors[entry][node] = node < c.nodes-c.leftOut
			} else {
				mirrors[entry][node] = node >= c.withheld
			}
		}
	}
	return mirrors
}

func samplePaths(c pathsConfig) (pathsResult, error) {
	switch {
	case c.samples < 1:
		return pathsResult{}, fmt.Errorf("-samples %d: want at least 1", c.samples)
	case c.rogue < 0 || c.rogue > c.nodes:
		return pathsResult{}, fmt.Errorf("-rogue %d: want between 0 and -nodes %d", c.rogue, c.nodes)
	case c.missing < 0:
		return pathsResult{}, fmt.Errorf("-missing %d: must not be negative", c.missing)
	case c.leftOut < 0 || c.leftOut > c.nodes-c.rogue:
		return pathsResult{}, fmt.Errorf("-leftout %d: want between 0 and the %d honest nodes", c.leftOut, c.nodes-c.rogue)
	case c.withheld < 0 || c.withheld > c.rogue:
		return pathsResult{}, fmt.Errorf("-withhold %d: want between 0 and -rogue %d", c.withheld, c.rogue)
	}
	paths, refused, err := lab.SampleMirrorPaths(mirrorsOf(c), c.hops, c.missing, c.samples, c.seed)
	if err != nil {
		return pathsResult{}, err
	}
	if len(paths) == 0 {
		return pathsResult{}, fmt.Errorf("every one of the %d attempts was refused: there is no chain to take a share of", c.samples)
	}
	held := make(map[int]bool, c.rogue)
	for node := 0; node < c.rogue; node++ {
		held[node] = true
	}
	res := pathsResult{
		Nodes: c.nodes, Hops: c.hops, Rogue: c.rogue,
		Missing: c.missing, LeftOut: c.leftOut, Withheld: c.withheld,
		Samples: c.samples, Seed: c.seed,
		Chains:  len(paths),
		Refused: float64(refused) / float64(c.samples),
	}
	res.Ends, res.Touched = metrics.CompromiseFraction(paths, held)
	res.EndsExpected, res.TouchedExpected, res.RefusedExpected = metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
	res.EndsStdErr = metrics.BinomialStdErr(res.EndsExpected, res.Chains)
	res.TouchedStdErr = metrics.BinomialStdErr(res.TouchedExpected, res.Chains)
	res.RefusedStdErr = metrics.BinomialStdErr(res.RefusedExpected, c.samples)
	res.EndsUniform, res.TouchedUniform = metrics.CompromiseProbability(c.nodes, c.hops, c.rogue)
	return res, nil
}

// the configuration is in the name, so two runs within one second overwrite
// each other only when they draw the same sample
func pathsReportName(r pathsResult, at time.Time) string {
	return fmt.Sprintf("paths-nodes%d-hops%d-rogue%d-missing%d-leftout%d-withhold%d-samples%d-seed%d-%s",
		r.Nodes, r.Hops, r.Rogue, r.Missing, r.LeftOut, r.Withheld, r.Samples, r.Seed, at.UTC().Format("20060102-150405"))
}

func printPaths(w io.Writer, r pathsResult) {
	fmt.Fprintf(w, "%5s %4s %5s %7s %7s %8s %8s %8s %25s %25s %25s\n",
		"nodes", "hops", "rogue", "missing", "leftout", "withhold", "samples", "chains", "refused", "rogue entry and exit", "any rogue node")
	fmt.Fprintf(w, "%5d %4d %5d %7d %7d %8d %8d %8d %s %s %s\n",
		r.Nodes, r.Hops, r.Rogue, r.Missing, r.LeftOut, r.Withheld, r.Samples, r.Chains,
		share(r.Refused, r.RefusedExpected, r.RefusedStdErr), share(r.Ends, r.EndsExpected, r.EndsStdErr), share(r.Touched, r.TouchedExpected, r.TouchedStdErr))
	fmt.Fprintln(w, "refused: share of the attempts whose entry served a mirror the client refuses; the other two: shares of the chains built")
	fmt.Fprintln(w, "in brackets what the choice gives and the standard error of a share of that many draws at that value")
	fmt.Fprintln(w, "where that value is 0 or 1 every draw gives the same answer: the share is exact by construction, not sampled")
	fmt.Fprintf(w, "full mirrors, a uniform choice: %.4f and %.4f, k(k-1)/(N(N-1)) and 1 - C(N-k,h)/C(N,h)\n", r.EndsUniform, r.TouchedUniform)
}

func share(sampled, expected, stderr float64) string {
	return fmt.Sprintf("%6.4f [%.4f +- %.4f]", sampled, expected, stderr)
}
