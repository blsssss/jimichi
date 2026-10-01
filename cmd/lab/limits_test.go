package main

import (
	"testing"
	"time"
)

// a run that a node limit touched keeps its counts in the row and stays out of
// the medians like a broken one: of the three runs only the clean one, with
// AUC 0.7, is summarised
func TestLimitedRunsStayOutOfTheMedians(t *testing.T) {
	touched := syntheticRun(0, 0)
	touched.RelayTimedOut, touched.RelayExpired, touched.RelayRefused = 1, 2, 3
	limitedRow, _ := analyse(touched, "x", 100*time.Millisecond)
	if limitedRow.RelayTimedOut != 1 || limitedRow.RelayExpired != 2 || limitedRow.RelayRefused != 3 {
		t.Fatalf("row carries timed out %d, expired %d, refused %d; want 1, 2, 3",
			limitedRow.RelayTimedOut, limitedRow.RelayExpired, limitedRow.RelayRefused)
	}
	limitedRow.AUC = 0.1
	cleanRow, _ := analyse(syntheticRun(0, 0), "x", 100*time.Millisecond)
	cleanRow.AUC = 0.7
	// a write deadline that ran out closes the circuit, so such a run is both
	both := limitedRow
	both.RelayBrokenCircuits = 1

	sum := summarise([]result{limitedRow, cleanRow, both})
	if len(sum) != 1 {
		t.Fatalf("%d summary lines, want 1", len(sum))
	}
	s := sum[0]
	if s.Runs != 3 || s.BrokenRuns != 1 || s.LimitedRuns != 2 || s.CleanRuns != 1 {
		t.Fatalf("runs %d, broken %d, limited %d, clean %d; want 3, 1, 2, 1", s.Runs, s.BrokenRuns, s.LimitedRuns, s.CleanRuns)
	}
	if s.AUC == nil || *s.AUC != 0.7 {
		t.Fatalf("median %s, want the clean run's 0.7", encode(t, s))
	}

	only := summarise([]result{limitedRow})
	if only[0].AUC != nil || only[0].CleanRuns != 0 || only[0].LimitedRuns != 1 || only[0].BrokenRuns != 0 {
		t.Fatalf("a line of limited runs alone was summarised: %s", encode(t, only[0]))
	}
}
