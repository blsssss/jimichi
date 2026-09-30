package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab"
)

// two flows with a few frames each, enough for analyse to score them
func syntheticRun(broken uint64, brokenFlows int) *lab.Run {
	start := time.Now()
	trace := func(offsets ...time.Duration) *lab.Trace {
		t := lab.NewTrace(start)
		for _, o := range offsets {
			t.Mark(start.Add(o))
		}
		return t
	}
	ms := time.Millisecond
	return &lab.Run{
		Config:       lab.Config{Hops: 3, Flows: 2, Duration: time.Second, Suite: jcrypto.SuiteC25519, Payload: 128},
		Entry:        []*lab.Trace{trace(10*ms, 300*ms, 310*ms), trace(500*ms, 900*ms)},
		Exit:         []*lab.Trace{trace(20*ms, 320*ms, 330*ms), trace(520*ms, 910*ms)},
		EntryBack:    []*lab.Trace{trace(30 * ms), trace(530 * ms)},
		ExitBack:     []*lab.Trace{trace(25 * ms), trace(525 * ms)},
		Sent:         5,
		RelayBroken:  broken,
		BrokenFlows:  brokenFlows,
		RelayDropped: 4,
	}
}

func TestBreakCountsReachTheReport(t *testing.T) {
	res, _ := analyse(syntheticRun(2, 1), "x", 100*time.Millisecond)
	if res.RelayBrokenCircuits != 2 || res.BrokenFlows != 1 || res.RelayDroppedCells != 4 {
		t.Fatalf("row carries %d closed circuits, %d broken flows, %d dropped cells; want 2, 1 and 4",
			res.RelayBrokenCircuits, res.BrokenFlows, res.RelayDroppedCells)
	}
}

// three runs of one configuration, the third with a closed circuit. Worked by
// hand from the two clean runs only:
//
//	auc 0.6 and 0.8: median (0.6 + 0.8) / 2 = 0.7, min 0.6, max 0.8
//	top1 0.5 and 1.0: median 0.75
//	multiplier 2 and 4: median 3; relay multiplier 1 and 3: median 2
//	p50 10ms and 30ms: median 20 ms
//	deg: the one degenerate run is the broken one, so 0
//
// with the broken run counted the auc median would be 0.6 and the range [0.1, 0.8]
func TestBrokenRunsStayOutOfTheMedians(t *testing.T) {
	rows := []result{
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.6, TopOne: 0.5, Multiplier: 2, RelayMultiplier: 1, P50: "10ms"},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.8, TopOne: 1.0, Multiplier: 4, RelayMultiplier: 3, P50: "30ms"},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.1, TopOne: 0, Multiplier: 9, RelayMultiplier: 9, P50: "900ms",
			CIDegenerate: true, RelayBrokenCircuits: 1},
	}
	sum := summarise(rows)
	if len(sum) != 1 {
		t.Fatalf("%d summary lines, want 1", len(sum))
	}
	s := sum[0]
	if s.Runs != 3 || s.BrokenRuns != 1 {
		t.Fatalf("runs %d, broken %d; want 3 and 1", s.Runs, s.BrokenRuns)
	}
	near := func(a *float64, b float64) bool { return a != nil && *a-b < 1e-9 && b-*a < 1e-9 }
	if !near(s.AUC, 0.7) || !near(s.AUCMin, 0.6) || !near(s.AUCMax, 0.8) || !near(s.TopOne, 0.75) ||
		!near(s.Multiplier, 3) || !near(s.RelayMult, 2) || !near(s.LatencyP50Ms, 20) ||
		s.DegenerateRuns == nil || *s.DegenerateRuns != 0 {
		t.Fatalf("summary does not match the two clean runs: %s", encode(t, s))
	}
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("summary does not encode: %v", err)
	}
	return string(b)
}

var medianFields = []string{
	"auc_median", "auc_min", "auc_max", "top1_median", "bandwidth_multiplier_median",
	"relay_link_multiplier_median", "ci_degenerate_runs", "latency_p50_ms_median",
}

func fields(t *testing.T, s summary) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(encode(t, s)), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// a configuration whose every run closed a circuit keeps its line, and every
// field that would hold a result is null rather than a zero that reads as one
func TestEveryRunBrokenLeavesNothingToSummarise(t *testing.T) {
	rows := []result{
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.9, P50: "10ms", BrokenFlows: 1},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.4, P50: "20ms", RelayBrokenCircuits: 3},
	}
	sum := summarise(rows)
	if len(sum) != 1 || sum[0].Runs != 2 || sum[0].BrokenRuns != 2 {
		t.Fatalf("summary %s, want two runs, both broken", encode(t, sum))
	}
	m := fields(t, sum[0])
	for _, f := range medianFields {
		v, present := m[f]
		if !present || v != nil {
			t.Fatalf("%s is %v, want null: %s", f, v, encode(t, sum[0]))
		}
	}
}

// clean runs without a single latency sample leave the latency median null:
// Median of nothing is NaN, which JSON cannot hold
func TestNoLatencySampleLeavesTheLatencyMedianNull(t *testing.T) {
	sum := summarise([]result{{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.6}})
	m := fields(t, sum[0])
	if v, present := m["latency_p50_ms_median"]; !present || v != nil {
		t.Fatalf("latency median %v, want null", v)
	}
	if m["auc_median"] != 0.6 || m["ci_degenerate_runs"] != 0.0 {
		t.Fatalf("clean fields lost: %s", encode(t, sum[0]))
	}
}

// one clean run gives values, not a median, and the printed line says so; a
// line with no clean run prints no numbers at all
func TestSummaryMarksLinesWithOneOrNoCleanRun(t *testing.T) {
	sum := summarise([]result{
		{Suite: "c25519", Traffic: "one", Bin: "100ms", AUC: 0.6, P50: "10ms"},
		{Suite: "c25519", Traffic: "one", Bin: "100ms", AUC: 0.9, RelayBrokenCircuits: 1},
		{Suite: "c25519", Traffic: "none", Bin: "100ms", AUC: 0.9, BrokenFlows: 2},
		{Suite: "c25519", Traffic: "two", Bin: "100ms", AUC: 0.6},
		{Suite: "c25519", Traffic: "two", Bin: "100ms", AUC: 0.8},
	})
	var out bytes.Buffer
	printSummary(&out, sum)
	lines := map[string]string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines[f[0]] = l
		}
	}
	if !strings.Contains(lines["one"], "one clean run") {
		t.Fatalf("a single clean run is printed as a median: %q", lines["one"])
	}
	if !strings.Contains(lines["none"], "nothing to summarise") || strings.Contains(lines["none"], "0.900") {
		t.Fatalf("a line without clean runs prints numbers: %q", lines["none"])
	}
	if strings.Contains(lines["two"], "one clean run") || !strings.Contains(lines["two"], "0.700") {
		t.Fatalf("a line of two clean runs lost its median: %q", lines["two"])
	}
}
