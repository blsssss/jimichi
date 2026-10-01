package main

import (
	"fmt"
	"io"

	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

// the paths set: the shares of sampled paths the adversary holds, each next to
// the value a uniform choice gives, with everything needed to draw the same
// sample again
type pathsResult struct {
	Nodes   int    `json:"nodes"`
	Hops    int    `json:"hops"`
	Rogue   int    `json:"rogue_nodes"`
	Samples int    `json:"samples"`
	Seed    int64  `json:"seed"`
	Rev     string `json:"rev"`

	Ends            float64 `json:"rogue_entry_and_exit"`
	EndsExpected    float64 `json:"rogue_entry_and_exit_expected"`
	Touched         float64 `json:"any_rogue_node"`
	TouchedExpected float64 `json:"any_rogue_node_expected"`
}

func samplePaths(nodes, hops, rogue, samples int, seed int64) (pathsResult, error) {
	if samples < 1 {
		return pathsResult{}, fmt.Errorf("-samples %d: want at least 1", samples)
	}
	if rogue < 0 || rogue > nodes {
		return pathsResult{}, fmt.Errorf("-rogue %d: want between 0 and -nodes %d", rogue, nodes)
	}
	paths, err := lab.SamplePaths(nodes, hops, samples, seed)
	if err != nil {
		return pathsResult{}, err
	}
	// every node is as likely as any other in every position, so which of them
	// are rogue does not change the shares: the first ones are
	held := make(map[int]bool, rogue)
	for node := 0; node < rogue; node++ {
		held[node] = true
	}
	res := pathsResult{Nodes: nodes, Hops: hops, Rogue: rogue, Samples: samples, Seed: seed}
	res.Ends, res.Touched = metrics.CompromiseFraction(paths, held)
	res.EndsExpected, res.TouchedExpected = metrics.CompromiseProbability(nodes, hops, rogue)
	return res, nil
}

func printPaths(w io.Writer, r pathsResult) {
	fmt.Fprintf(w, "%5s %4s %5s %8s %22s %22s\n", "nodes", "hops", "rogue", "samples", "rogue entry and exit", "any rogue node")
	fmt.Fprintf(w, "%5d %4d %5d %8d %10.4f [%.4f] %13.4f [%.4f]\n",
		r.Nodes, r.Hops, r.Rogue, r.Samples, r.Ends, r.EndsExpected, r.Touched, r.TouchedExpected)
	fmt.Fprintln(w, "shares of the sampled paths; in brackets what a uniform choice gives, k(k-1)/(N(N-1)) and 1 - C(N-k,h)/C(N,h)")
}
