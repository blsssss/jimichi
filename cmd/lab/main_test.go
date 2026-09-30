package main

import (
	"encoding/json"
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
	near := func(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }
	if !near(s.AUC, 0.7) || !near(s.AUCMin, 0.6) || !near(s.AUCMax, 0.8) || !near(s.TopOne, 0.75) ||
		!near(s.Multiplier, 3) || !near(s.RelayMult, 2) || !near(s.LatencyP50Ms, 20) || s.DegenerateRuns != 0 {
		t.Fatalf("summary %+v does not match the two clean runs", s)
	}
}

// a configuration whose every run closed a circuit keeps its line, with zero
// medians the report can still encode
func TestEveryRunBrokenLeavesNothingToSummarise(t *testing.T) {
	rows := []result{
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.9, BrokenFlows: 1},
		{Suite: "c25519", Traffic: "x", Bin: "100ms", AUC: 0.4, RelayBrokenCircuits: 3},
	}
	sum := summarise(rows)
	if len(sum) != 1 || sum[0].Runs != 2 || sum[0].BrokenRuns != 2 || sum[0].AUC != 0 {
		t.Fatalf("summary %+v, want two runs, both broken, no median", sum)
	}
	if _, err := json.Marshal(sum); err != nil {
		t.Fatalf("summary does not encode: %v", err)
	}
}
