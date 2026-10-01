package main

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/relay"
)

// readiness follows the cell listener: a node that stopped accepting must not
// keep its place behind the service
func TestHealthReflectsServing(t *testing.T) {
	var serving atomic.Bool
	n := &node{ttl: time.Hour, now: time.Now, logger: log.New(&logBuffer{}, "", 0), serving: serving.Load}
	info := httptest.NewServer(n.infoMux())
	defer info.Close()

	if code, _ := call(t, http.MethodGet, info.URL+"/healthz", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz = %d before the node serves, want 503", code)
	}
	serving.Store(true)
	if code, _ := call(t, http.MethodGet, info.URL+"/healthz", nil); code != http.StatusOK {
		t.Fatalf("/healthz = %d while the node serves, want 200", code)
	}
	serving.Store(false)
	if code, _ := call(t, http.MethodGet, info.URL+"/healthz", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz = %d after the node stopped serving, want 503", code)
	}
}

// a node whose Serve returned, with or without an error, ends with one, so the
// process exits non-zero; a signal ends it cleanly
func TestStoppedServeEndsTheNode(t *testing.T) {
	logger := log.New(&logBuffer{}, "", 0)
	for _, stopped := range []error{errors.New("accept: listener gone"), nil} {
		served := make(chan error, 1)
		served <- stopped
		err := untilStopped(make(chan os.Signal), served, logger)
		if err == nil || !strings.Contains(err.Error(), "serve stopped") {
			t.Fatalf("untilStopped after Serve returned %v = %v, want an error", stopped, err)
		}
	}
	stop := make(chan os.Signal, 1)
	stop <- os.Interrupt
	if err := untilStopped(stop, make(chan error), logger); err != nil {
		t.Fatalf("untilStopped on a signal = %v, want nil", err)
	}
}

func TestStatsCarryEveryCounter(t *testing.T) {
	n := &node{ttl: time.Hour, now: time.Now, logger: log.New(&logBuffer{}, "", 0)}
	admin := httptest.NewServer(n.adminMux(func() relay.Counters {
		return relay.Counters{Accepted: 1, Forwarded: 2, Delivered: 3, Dropped: 4, Padding: 5, Broken: 6,
			AcceptRetries: 7, RefusedLinks: 8, RefusedBusy: 9, RefusedSource: 10, RefusedRate: 11,
			RefusedSetups: 12, TimedOut: 13, Expired: 14, RefusedExtend: 15}
	}))
	defer admin.Close()
	_, body := call(t, http.MethodGet, admin.URL+"/stats", nil)
	for _, want := range []string{
		`"accepted":1`, `"forwarded":2`, `"delivered":3`, `"dropped":4`, `"padding":5`, `"broken":6`,
		`"accept_retries":7`, `"refused_links":8`, `"refused_busy":9`, `"refused_source":10`, `"refused_rate":11`,
		`"refused_setups":12`, `"timed_out":13`, `"expired":14`, `"refused_extend":15`, `"cert":"none"`,
		`"roster":0`, `"peers":0`, `"descriptor_requests":0`, `"mirror_requests":0`,
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("/stats %s lacks %s", body, want)
		}
	}
}
