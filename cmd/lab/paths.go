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

// the paths set: the shares of the chains the adversary holds, each next to
// the value the model gives and the standard error of a share of that many
// draws at that value, with everything needed to draw the same sample again.
// An attempt ends in one of three ways: the client refuses the mirror of the
// entry it drew; it chooses a chain that fails at setup, because an honest
// node on it does not hold the descriptor of the next node; or the chain comes
// up. Refused and Failed are shares of the attempts, Chains counts the chains
// that came up and the two shares of chains are over those
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
	Failed          float64 `json:"failed_at_setup"`
	FailedExpected  float64 `json:"failed_at_setup_expected"`
	FailedStdErr    float64 `json:"failed_at_setup_stderr"`

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

// which node extends a circuit to which: an honest node only to the nodes
// whose descriptors it holds, which are the ones its mirror serves; a rogue
// node to every node, whatever it leaves out of the mirror it serves
func extendsOf(c pathsConfig) [][]bool {
	extends := mirrorsOf(c)
	for node := 0; node < c.rogue; node++ {
		for next := range extends[node] {
			extends[node][next] = true
		}
	}
	return extends
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
	chosen, refused, err := lab.SampleMirrorPaths(mirrorsOf(c), c.hops, c.missing, c.samples, c.seed)
	if err != nil {
		return pathsResult{}, err
	}
	paths, failed, err := lab.SurvivingPaths(chosen, extendsOf(c))
	if err != nil {
		return pathsResult{}, err
	}
	if len(paths) == 0 {
		return pathsResult{}, fmt.Errorf("none of the %d attempts gave a chain that came up: there is no chain to take a share of", c.samples)
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
		Failed:  float64(failed) / float64(c.samples),
	}
	res.Ends, res.Touched = metrics.CompromiseFraction(paths, held)
	res.EndsExpected, res.TouchedExpected, res.RefusedExpected, res.FailedExpected = metrics.MirrorCompromiseProbability(c.nodes, c.hops, c.rogue, c.missing, c.leftOut, c.withheld)
	res.EndsStdErr = metrics.BinomialStdErr(res.EndsExpected, res.Chains)
	res.TouchedStdErr = metrics.BinomialStdErr(res.TouchedExpected, res.Chains)
	res.RefusedStdErr = metrics.BinomialStdErr(res.RefusedExpected, c.samples)
	res.FailedStdErr = metrics.BinomialStdErr(res.FailedExpected, c.samples)
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
	fmt.Fprintf(w, "%5s %4s %5s %7s %7s %8s %8s %8s %25s %25s %25s %25s\n",
		"nodes", "hops", "rogue", "missing", "leftout", "withhold", "samples", "chains", "refused", "failed at setup", "rogue entry and exit", "any rogue node")
	fmt.Fprintf(w, "%5d %4d %5d %7d %7d %8d %8d %8d %s %s %s %s\n",
		r.Nodes, r.Hops, r.Rogue, r.Missing, r.LeftOut, r.Withheld, r.Samples, r.Chains,
		share(r.Refused, r.RefusedExpected, r.RefusedStdErr), share(r.Failed, r.FailedExpected, r.FailedStdErr),
		share(r.Ends, r.EndsExpected, r.EndsStdErr), share(r.Touched, r.TouchedExpected, r.TouchedStdErr))
	for _, line := range pathsLegend {
		fmt.Fprintln(w, line)
	}
	// a chain of one node has that node at both ends
	ends := "k(k-1)/(N(N-1))"
	if r.Hops == 1 {
		ends = "k/N"
	}
	fmt.Fprintf(w, "full mirrors, a uniform choice: %.4f and %.4f, %s and 1 - C(N-k,h)/C(N,h)\n", r.EndsUniform, r.TouchedUniform, ends)
}

var pathsLegend = []string{
	"refused: share of the attempts whose entry served a mirror the client refuses",
	"failed at setup: share of the attempts whose chosen chain has an honest node before a node whose descriptor it does not hold",
	"chains: the attempts whose chain came up; the last two columns are shares of those chains",
	"in brackets what the model gives and the standard error of a share of that many draws at that value",
	"where that value is 0 or 1 every draw gives the same answer: the share is exact by construction, not sampled",
}

func share(sampled, expected, stderr float64) string {
	return fmt.Sprintf("%6.4f [%.4f +- %.4f]", sampled, expected, stderr)
}
