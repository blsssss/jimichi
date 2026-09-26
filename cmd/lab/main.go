package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/blsssss/jimichi/client"
	"github.com/blsssss/jimichi/crypto/suite"
	"github.com/blsssss/jimichi/lab"
	"github.com/blsssss/jimichi/lab/metrics"
)

// one row per run and observation window; the configuration travels with the
// numbers so any row can be reproduced from the report alone
type result struct {
	Traffic     string `json:"traffic"`
	Bin         string `json:"bin"`
	Repeat      int    `json:"repeat"`
	BaseSeed    int64  `json:"base_seed"`
	Seed        int64  `json:"seed"`
	Suite       string `json:"suite"`
	Mode        string `json:"mode"`
	Rate        string `json:"rate"`
	CoverEvery  string `json:"cover_every"`
	RelayPeriod string `json:"relay_period"`
	Jitter      string `json:"jitter"`
	Send        string `json:"send_mean_gap"`
	Payload     int    `json:"payload_bytes"`
	Duration    string `json:"duration"`
	Flows       int    `json:"flows"`
	Hops        int    `json:"hops"`
	Rev         string `json:"rev"`
	GOOS        string `json:"goos"`
	// a busy host delays ticks and lowers the scores, so every row says how
	// loaded the machine was around its run
	NumCPU     int    `json:"num_cpu"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	LoadBefore string `json:"loadavg_before,omitempty"`
	LoadAfter  string `json:"loadavg_after,omitempty"`

	Cells      int     `json:"cells"`
	Messages   int     `json:"messages"`
	Multiplier float64 `json:"bandwidth_multiplier"`
	// the same ratio in the other direction of the entry link and in both
	// directions of the observed link between relays, where pacing adds padding
	EntryBackMultiplier float64 `json:"entry_back_multiplier"`
	RelayMultiplier     float64 `json:"relay_link_multiplier"`
	RelayBackMultiplier float64 `json:"relay_link_back_multiplier"`

	AUC      float64 `json:"auc"`
	AUCLow   float64 `json:"auc_ci_low"`
	AUCHigh  float64 `json:"auc_ci_high"`
	CIMethod string  `json:"auc_ci_method"`
	TPR      float64 `json:"tpr_at_fpr_0.01"`
	TopOne   float64 `json:"top1_accuracy"`
	// how many pairs had no defined correlation, and whether the bootstrap
	// collapsed to a single value; together they tell a 0.5 that means
	// "nothing to rank" from one that means "ranked at chance"
	UndefinedPairs int  `json:"undefined_pairs"`
	CIDegenerate   bool `json:"ci_degenerate"`

	DropRate          float64 `json:"drop_rate"`
	RelayDroppedCells uint64  `json:"relay_dropped_cells"`
	LatencySamples    int     `json:"latency_samples"`
	Unanswered        int     `json:"unanswered"`
	P50               string  `json:"latency_p50,omitempty"`
	P95               string  `json:"latency_p95,omitempty"`
	P99               string  `json:"latency_p99,omitempty"`
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
	binList := flag.String("bins", "100ms", "comma-separated observation windows, each scored on the same runs")
	repeats := flag.Int("repeats", 1, "runs per configuration")
	out := flag.String("out", "artifacts", "directory for the json report")
	set := flag.String("set", "main", "main: cover strategies, rates: constant rate at several speeds, paced: relays on their own clocks")
	rev := flag.String("rev", "unknown", "code revision recorded in every row")
	seed := flag.Int64("seed", 1, "base seed; every repeat derives its own from it")
	suiteName := flag.String("suite", "c25519", "primitive suite for every node and client: gost or c25519")
	flag.Parse()

	if *flows < 2 || *hops < 2 {
		fmt.Fprintln(os.Stderr, "need at least 2 flows and 2 hops: the attack pairs flows seen before and after a relay")
		os.Exit(2)
	}
	if *rev == "unknown" {
		fmt.Fprintln(os.Stderr, "warning: no -rev given, rows cannot be traced to a revision")
	}

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	bins, err := parseBins(*binList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bins: %v\n", err)
		os.Exit(2)
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	details := make([]detail, 0)
	variants := variantSet(*set)
	results := make([]result, 0, len(variants)*(*repeats)*len(bins))
	fmt.Printf("%-11s %6s %6s %11s %8s %24s %7s %6s %7s %9s %9s\n",
		"traffic", "bin", "cells", "multiplier", "relay-x", "auc [95% ci]", "tpr@1%", "top1", "drops", "p50", "p95")

	for _, v := range variants {
		for r := 0; r < *repeats; r++ {
			cfg := v.cfg
			cfg.Hops = *hops
			cfg.Flows = *flows
			cfg.Duration = *duration
			cfg.SendEvery = *send
			cfg.Seed = lab.Derive(*seed, uint64(r))
			cfg.Suite = chosen

			before := loadavg()
			run, err := lab.Execute(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
				os.Exit(1)
			}
			if run.Sent == 0 {
				fmt.Fprintf(os.Stderr, "%s: no message was sent, nothing to score\n", v.label)
				os.Exit(1)
			}
			after := loadavg()
			for _, bin := range bins {
				res, d := analyse(run, v.label, bin)
				res.Repeat, res.BaseSeed, res.Rev = r, *seed, *rev
				res.GOOS, res.NumCPU, res.GOMAXPROCS = runtime.GOOS, runtime.NumCPU(), runtime.GOMAXPROCS(0)
				res.LoadBefore, res.LoadAfter = before, after
				results = append(results, res)
				if r == 0 {
					details = append(details, d)
				}
				fmt.Printf("%-11s %6s %6d %11.2f %8.2f     %.3f [%.3f, %.3f] %7.3f %6.3f %7.3f %9s %9s\n",
					res.Traffic, res.Bin, res.Cells, res.Multiplier, res.RelayMultiplier,
					res.AUC, res.AUCLow, res.AUCHigh, res.TPR, res.TopOne,
					res.DropRate, res.P50, res.P95)
			}
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
	sum := summarise(results)
	printSummary(sum)
	if err := write(*out, "summary-"+*set+"-"+stamp, sum); err != nil {
		fmt.Fprintf(os.Stderr, "summary: %v\n", err)
		os.Exit(1)
	}
}

// runs of one configuration at one window, reduced to the median and the range
// across repeats; the rows stay in the report for anything finer
type summary struct {
	Suite          string  `json:"suite"`
	Traffic        string  `json:"traffic"`
	Bin            string  `json:"bin"`
	Runs           int     `json:"runs"`
	AUC            float64 `json:"auc_median"`
	AUCMin         float64 `json:"auc_min"`
	AUCMax         float64 `json:"auc_max"`
	TopOne         float64 `json:"top1_median"`
	Multiplier     float64 `json:"bandwidth_multiplier_median"`
	RelayMult      float64 `json:"relay_link_multiplier_median"`
	LatencyP50Ms   float64 `json:"latency_p50_ms_median"`
	DegenerateRuns int     `json:"ci_degenerate_runs"`
}

func summarise(rows []result) []summary {
	type key struct{ traffic, bin string }
	order := []key{}
	groups := map[key][]result{}
	for _, r := range rows {
		k := key{r.Traffic, r.Bin}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	out := make([]summary, 0, len(order))
	for _, k := range order {
		g := groups[k]
		var auc, top, mult, relay, p50 []float64
		degenerate := 0
		for _, r := range g {
			auc = append(auc, r.AUC)
			top = append(top, r.TopOne)
			mult = append(mult, r.Multiplier)
			relay = append(relay, r.RelayMultiplier)
			if d, err := time.ParseDuration(r.P50); err == nil {
				p50 = append(p50, float64(d)/float64(time.Millisecond))
			}
			if r.CIDegenerate {
				degenerate++
			}
		}
		out = append(out, summary{
			Suite: g[0].Suite, Traffic: k.traffic, Bin: k.bin, Runs: len(g),
			AUC: metrics.Median(auc), AUCMin: slices.Min(auc), AUCMax: slices.Max(auc),
			TopOne: metrics.Median(top), Multiplier: metrics.Median(mult), RelayMult: metrics.Median(relay),
			LatencyP50Ms: metrics.Median(p50), DegenerateRuns: degenerate,
		})
	}
	return out
}

func printSummary(sum []summary) {
	if len(sum) > 0 {
		fmt.Printf("\nsuite %s", sum[0].Suite)
	}
	fmt.Printf("\n%-11s %6s %4s %20s %6s %8s %8s %10s %4s\n",
		"traffic", "bin", "runs", "auc median [min,max]", "top1", "mult", "relay-x", "p50 ms", "deg")
	for _, s := range sum {
		fmt.Printf("%-11s %6s %4d %6.3f [%.3f, %.3f] %6.3f %8.2f %8.2f %10.2f %4d\n",
			s.Traffic, s.Bin, s.Runs, s.AUC, s.AUCMin, s.AUCMax, s.TopOne, s.Multiplier, s.RelayMult, s.LatencyP50Ms, s.DegenerateRuns)
	}
}

// the first three fields of /proc/loadavg; empty where there is no such file
func loadavg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return ""
	}
	return strings.Join(f[:3], " ")
}

func parseBins(list string) ([]time.Duration, error) {
	var bins []time.Duration
	for _, f := range strings.Split(list, ",") {
		d, err := time.ParseDuration(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		if d <= 0 {
			return nil, fmt.Errorf("window %v must be positive", d)
		}
		bins = append(bins, d)
	}
	return bins, nil
}

func analyse(run *lab.Run, traffic string, bin time.Duration) (result, detail) {
	cfg := run.Config
	window := cfg.Duration
	entryEvents := sinceOrigin(run.Entry, run.Origin)
	exitEvents := sinceOrigin(run.Exit, run.Origin)

	entry := make([][]float64, len(entryEvents))
	for i, e := range entryEvents {
		entry[i] = metrics.Bin(e, window, bin)
	}
	exit := make([][]float64, len(exitEvents))
	for i, e := range exitEvents {
		exit[i] = metrics.Bin(e, window, bin)
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

	cells := metrics.CellsWithin(entryEvents, window)
	cost := func(traces []*lab.Trace) float64 {
		return metrics.Multiplier(metrics.CellsWithin(sinceOrigin(traces, run.Origin), window), run.Sent)
	}

	res := result{
		Traffic:     traffic,
		Bin:         bin.String(),
		Seed:        cfg.Seed,
		Suite:       cfg.Suite.String(),
		Mode:        modeName(cfg.Mode),
		Rate:        cfg.Rate.String(),
		CoverEvery:  cfg.CoverEvery.String(),
		RelayPeriod: cfg.RelayPeriod.String(),
		Jitter:      cfg.Jitter.String(),
		Send:        cfg.SendEvery.String(),
		Payload:     cfg.Payload,
		Duration:    cfg.Duration.String(),
		Flows:       cfg.Flows,
		Hops:        cfg.Hops,

		Cells:               cells,
		Messages:            run.Sent,
		Multiplier:          metrics.Multiplier(cells, run.Sent),
		EntryBackMultiplier: cost(run.EntryBack),
		RelayMultiplier:     cost(run.Exit),
		RelayBackMultiplier: cost(run.ExitBack),

		AUC:      ci.Point,
		AUCLow:   ci.Low,
		AUCHigh:  ci.High,
		CIMethod: ci.Method + "-10000",
		TPR:      metrics.TPRAtFPR(scores, 0.01),
		TopOne:   metrics.TopOneAccuracy(scores, len(entry)),

		UndefinedPairs: metrics.UndefinedPairs(scores),
		CIDegenerate:   ci.Low == ci.High,

		DropRate:          float64(run.Dropped) / float64(run.Sent),
		RelayDroppedCells: run.RelayDropped,
		LatencySamples:    len(run.Latency),
		Unanswered:        run.Unanswered,
		P50:               percentile(run.Latency, 0.5),
		P95:               percentile(run.Latency, 0.95),
		P99:               percentile(run.Latency, 0.99),
	}
	return res, detail{Traffic: traffic, Bin: bin.String(), Entry: entry, Exit: exit, Scores: matrix}
}

// the window opens when the flows start sending: circuit setup and the cover
// sent while the other circuits were still being built fall before it
func sinceOrigin(traces []*lab.Trace, origin time.Duration) [][]time.Duration {
	out := make([][]time.Duration, len(traces))
	for i, t := range traces {
		for _, e := range t.Events() {
			if e >= origin {
				out[i] = append(out[i], e-origin)
			}
		}
	}
	return out
}

func percentile(samples []time.Duration, q float64) string {
	v, ok := metrics.Percentile(samples, q)
	if !ok {
		return ""
	}
	return v.Round(time.Microsecond).String()
}

func modeName(m client.Mode) string {
	if m == client.ConstantRate {
		return "constant-rate"
	}
	return "immediate"
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
