package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/blsssss/jimichi/client"
	"github.com/blsssss/jimichi/lab"
	"github.com/blsssss/jimichi/lab/metrics"
)

type result struct {
	Traffic    string  `json:"traffic"`
	Flows      int     `json:"flows"`
	Hops       int     `json:"hops"`
	Cells      int     `json:"cells"`
	Messages   int     `json:"messages"`
	Multiplier float64 `json:"bandwidth_multiplier"`
	// the same ratio in the other direction of the entry link and in both
	// directions of the observed link between relays, where pacing adds padding
	EntryBackMultiplier float64 `json:"entry_back_multiplier"`
	RelayMultiplier     float64 `json:"relay_link_multiplier"`
	RelayBackMultiplier float64 `json:"relay_link_back_multiplier"`
	AUC                 float64 `json:"auc"`
	AUCLow              float64 `json:"auc_ci_low"`
	AUCHigh             float64 `json:"auc_ci_high"`
	CIMethod            string  `json:"auc_ci_method"`
	TPR                 float64 `json:"tpr_at_fpr_0.01"`
	TopOne              float64 `json:"top1_accuracy"`
	DropRate            float64 `json:"drop_rate"`
	RelayDropRate       float64 `json:"relay_drop_rate"`
	P50                 string  `json:"latency_p50"`
	P95                 string  `json:"latency_p95"`
}

type variant struct {
	label string
	cfg   lab.Config
}

// the raw material of the figures: what the observer counted on each link and
// how every entry flow scored against every exit flow
type detail struct {
	Traffic string      `json:"traffic"`
	Bin     string      `json:"bin"`
	Entry   [][]float64 `json:"entry"`
	Exit    [][]float64 `json:"exit"`
	Scores  [][]float64 `json:"scores"`
}

func variantSet(name string) []variant {
	if name == "paced" {
		// 70 and 35 ms are the client rates that leaked their phase to the exit
		// when relays forwarded at once
		out := []variant{{"none", lab.Config{}}}
		for _, ms := range []int{70, 35} {
			d := time.Duration(ms) * time.Millisecond
			// nodes tick 5% faster than the client, so a missed tick is caught up
			node := d * 95 / 100
			out = append(out,
				variant{fmt.Sprintf("fixed-%dms", ms), lab.Config{Mode: client.ConstantRate, Rate: d}},
				variant{fmt.Sprintf("relay-%dms", ms), lab.Config{RelayPeriod: node}},
				variant{fmt.Sprintf("both-%dms", ms), lab.Config{Mode: client.ConstantRate, Rate: d, RelayPeriod: node}},
			)
		}
		return out
	}
	if name == "rates" {
		out := []variant{{"none", lab.Config{}}}
		for _, ms := range []int{200, 140, 100, 70, 50, 35, 25} {
			out = append(out, variant{
				fmt.Sprintf("fixed-%dms", ms),
				lab.Config{Mode: client.ConstantRate, Rate: time.Duration(ms) * time.Millisecond},
			})
		}
		return out
	}
	return []variant{
		{"none", lab.Config{}},
		{"add-0.5x", lab.Config{CoverEvery: 400 * time.Millisecond}},
		{"add-1x", lab.Config{CoverEvery: 200 * time.Millisecond}},
		{"add-2x", lab.Config{CoverEvery: 100 * time.Millisecond}},
		{"fixed-1x", lab.Config{Mode: client.ConstantRate, Rate: 200 * time.Millisecond}},
		{"fixed-2x", lab.Config{Mode: client.ConstantRate, Rate: 100 * time.Millisecond}},
		{"fixed-4x", lab.Config{Mode: client.ConstantRate, Rate: 50 * time.Millisecond}},
	}
}

func main() {
	flows := flag.Int("flows", 6, "concurrent flows")
	hops := flag.Int("hops", 3, "relays in the chain")
	duration := flag.Duration("duration", 20*time.Second, "length of one run")
	send := flag.Duration("send", 200*time.Millisecond, "mean gap between messages of one flow")
	bin := flag.Duration("bin", 100*time.Millisecond, "observation window for the attack")
	repeats := flag.Int("repeats", 1, "runs per configuration")
	out := flag.String("out", "artifacts", "directory for the json report")
	set := flag.String("set", "main", "main: cover strategies, rates: constant rate at several speeds, paced: relays on their own clocks")
	flag.Parse()

	stamp := time.Now().UTC().Format("20060102-150405")
	details := make([]detail, 0)

	variants := variantSet(*set)

	results := make([]result, 0, len(variants)*(*repeats))
	fmt.Printf("%-11s %6s %11s %8s %24s %7s %6s %7s %9s %9s\n",
		"traffic", "cells", "multiplier", "relay-x", "auc [95% ci]", "tpr@1%", "top1", "drops", "p50", "p95")

	for _, v := range variants {
		for r := 0; r < *repeats; r++ {
			cfg := v.cfg
			cfg.Hops = *hops
			cfg.Flows = *flows
			cfg.Duration = *duration
			cfg.SendEvery = *send
			cfg.Seed = int64(1000 + r)

			run, err := lab.Execute(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
				os.Exit(1)
			}
			res, d := analyse(run, v.label, *bin)
			results = append(results, res)
			if r == 0 {
				details = append(details, d)
			}
			fmt.Printf("%-11s %6d %11.2f %8.2f     %.3f [%.3f, %.3f] %7.3f %6.3f %7.3f %9s %9s\n",
				res.Traffic, res.Cells, res.Multiplier, res.RelayMultiplier,
				res.AUC, res.AUCLow, res.AUCHigh, res.TPR, res.TopOne,
				res.DropRate, res.P50, res.P95)
		}
	}

	if err := write(*out, "detail-"+*set+"-"+stamp, details); err != nil {
		fmt.Fprintf(os.Stderr, "detail: %v\n", err)
		os.Exit(1)
	}
	if err := write(*out, "correlation-"+*set+"-"+stamp, results); err != nil {
		fmt.Fprintf(os.Stderr, "report: %v\n", err)
		os.Exit(1)
	}
}

func analyse(run *lab.Run, traffic string, bin time.Duration) (result, detail) {
	entry := make([][]float64, len(run.Entry))
	for i, t := range run.Entry {
		entry[i] = metrics.Bin(t.Events(), run.Config.Duration, bin)
	}
	exit := make([][]float64, len(run.Exit))
	for i, t := range run.Exit {
		exit[i] = metrics.Bin(t.Events(), run.Config.Duration, bin)
	}

	// the observer never sees the pairing; it only scores the attack
	truth := make(map[int]int, len(entry))
	for i := range entry {
		truth[i] = i
	}

	scores := metrics.ScorePairs(entry, exit, truth)
	ci := metrics.BootstrapAUC(scores, len(entry), 10000, 7)

	matrix := make([][]float64, len(entry))
	for i := range matrix {
		matrix[i] = make([]float64, len(exit))
	}
	for _, sc := range scores {
		matrix[sc.Entry][sc.Exit] = sc.Value
	}

	window := run.Config.Duration
	cost := func(traces []*lab.Trace) float64 {
		return metrics.Multiplier(metrics.CellsWithin(events(traces), window), run.Sent)
	}
	cells := metrics.CellsWithin(events(run.Entry), window)

	p50, p95 := percentiles(run.Latency)
	drops, relayDrops := 0.0, 0.0
	if total := run.Sent; total > 0 {
		drops = float64(run.Dropped) / float64(total)
		relayDrops = float64(run.RelayDropped) / float64(total)
	}

	res := result{
		Traffic:    traffic,
		Flows:      run.Config.Flows,
		Hops:       run.Config.Hops,
		Cells:      cells,
		Messages:   run.Sent,
		Multiplier: metrics.Multiplier(cells, run.Sent),

		EntryBackMultiplier: cost(run.EntryBack),
		RelayMultiplier:     cost(run.Exit),
		RelayBackMultiplier: cost(run.ExitBack),
		AUC:                 ci.Point,
		AUCLow:              ci.Low,
		AUCHigh:             ci.High,
		CIMethod:            ci.Method + "-10000",
		TPR:                 metrics.TPRAtFPR(scores, 0.01),
		TopOne:              metrics.TopOneAccuracy(scores, len(entry)),
		DropRate:            drops,
		RelayDropRate:       relayDrops,
		P50:                 p50.Round(time.Microsecond).String(),
		P95:                 p95.Round(time.Microsecond).String(),
	}
	return res, detail{Traffic: traffic, Bin: bin.String(), Entry: entry, Exit: exit, Scores: matrix}
}

func events(traces []*lab.Trace) [][]time.Duration {
	out := make([][]time.Duration, len(traces))
	for i, t := range traces {
		out[i] = t.Events()
	}
	return out
}

func percentiles(samples []time.Duration) (p50, p95 time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// linear interpolation between order statistics, the usual type 7 estimator
	idx := func(q float64) time.Duration {
		pos := q * float64(len(sorted)-1)
		lo := int(pos)
		if lo+1 >= len(sorted) {
			return sorted[lo]
		}
		frac := pos - float64(lo)
		return sorted[lo] + time.Duration(frac*float64(sorted[lo+1]-sorted[lo]))
	}
	return idx(0.5), idx(0.95)
}

func write(dir, base string, v any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := filepath.Join(dir, base+".json")
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	fmt.Printf("\nreport: %s\n", name)
	return nil
}
