package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

func main() {
	listen := flag.String("listen", ":9000", "address for cells")
	info := flag.String("info", ":9100", "address for the node descriptor and health check")
	statsAddr := flag.String("stats", "127.0.0.1:9101", "loopback address for counters and enrollment")
	logEvery := flag.Duration("log-every", time.Minute, "print aggregated counters to stdout this often; 0 disables")
	harden := flag.Bool("harden", true, "disable core dumps and ptrace access for the process")
	suiteName := flag.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	keymem := flag.String("keymem", "all", "key memory measures: all, none, or a list of offheap, lock, dontdump, zero")
	echo := flag.Bool("echo", true, "as an exit, send the payload back along the circuit")
	period := flag.Duration("period", 0, "send one frame per circuit and direction every period, padding when idle; 0 forwards at once")
	queue := flag.Int("queue", 64, "cells a circuit may queue per direction when -period is set")
	setupCache := flag.Int("setup-cache", wire.DefaultSetupCache, fmt.Sprintf("setups remembered to refuse a replay, 0 for the default, at most %d; when full the node refuses new circuits until restart", relay.MaxSetupCache))
	auth := flag.Bool("auth", true, "serve a descriptor signed under a certificate from jimichi enroll; false serves it unsigned")
	name := flag.String("name", "", "node name for its certificate, required with -auth")
	advertise := flag.String("advertise", "", fmt.Sprintf("host:port clients dial, bound into the certificate, at most %d bytes, required with -auth", wire.AddrSize))
	descriptorTTL := flag.Duration("descriptor-ttl", time.Hour, "lifetime of a signed descriptor, re-signed every half of it")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if *auth {
		if err := checkAuthFlags(*statsAddr, *name, *advertise, *descriptorTTL); err != nil {
			logger.Fatal(err)
		}
	}

	policy, err := secmem.ParsePolicy(*keymem)
	if err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if err := secmem.SetPolicy(policy); err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if *harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Fatalf("harden: %v", err)
		}
	}
	if policy.Lock {
		if err := checkMemlock(); err != nil {
			logger.Fatal(err)
		}
	}

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		logger.Fatal(err)
	}
	provider, err := suite.New(chosen)
	if err != nil {
		logger.Fatal(err)
	}
	staticPriv, staticPub, err := provider.GenerateEphemeral()
	if err != nil {
		logger.Fatalf("static key: %v", err)
	}
	defer staticPriv.Release()

	if policy.Lock && !staticPriv.Locked() {
		logger.Fatal("key memory is not locked, refusing to start")
	}

	n := &node{ttl: *descriptorTTL, now: time.Now, logger: logger}
	if *auth {
		id, err := pki.NewIdentity(provider, *name, *advertise)
		if err != nil {
			logger.Fatalf("identity: %v", err)
		}
		defer id.Close()
		if policy.Lock && !id.Locked() {
			logger.Fatal("identity key memory is not locked, refusing to start")
		}
		id.SetKeys(staticPub, staticPub, 0)
		n.id = id
	} else if n.unsigned, err = pki.Unsigned(provider, staticPub, staticPub); err != nil {
		logger.Fatalf("descriptor: %v", err)
	}

	r, err := relay.New(relay.Config{
		Provider:   provider,
		StaticPriv: staticPriv,
		// the payload is never logged: that would hand out exactly the metadata
		// the node exists to withhold
		Deliver: func(_ uint64, payload []byte) []byte {
			if *echo {
				return payload
			}
			return nil
		},
		Period:     *period,
		QueueCells: *queue,
		SetupCache: *setupCache,
	})
	if err != nil {
		logger.Fatalf("relay: %v", err)
	}
	defer r.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go serve(*info, n.infoMux(), logger)
	go serve(*statsAddr, n.adminMux(r.Stats().Snapshot), logger)
	if n.id != nil {
		go n.keepFresh()
	}
	if *logEvery > 0 {
		go logCounters(r, n, *logEvery, logger)
	}

	logger.Printf("relay listening on %s, info on %s, suite=%s, keymem=%s, locked=%v, harden=%v, period=%v, auth=%v",
		*listen, *info, chosen, policy, staticPriv.Locked(), *harden, *period, *auth)
	if n.id != nil {
		logger.Printf("identity=%s name=%s awaiting enrollment", n.id.Fingerprint(), *name)
	}
	go func() {
		if err := r.Serve(ln); err != nil {
			logger.Printf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Print("shutting down")
}

// a setup holds a handful of key pages at once, the static and identity keys
// one more each; below this the node would start and then fail its first
// circuits
const minMemlock = 64 << 10

func checkMemlock() error {
	budget, err := secmem.MemlockBudget()
	if err != nil {
		return err
	}
	if budget < minMemlock {
		return fmt.Errorf("RLIMIT_MEMLOCK is %d bytes, need at least %d to lock key pages", budget, minMemlock)
	}
	return nil
}

func serve(addr string, h http.Handler, logger *log.Logger) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Printf("http %s: %v", addr, err)
	}
}

func logCounters(r *relay.Relay, n *node, every time.Duration, logger *log.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		s := r.Stats().Snapshot()
		logger.Printf("counters accepted=%d forwarded=%d delivered=%d dropped=%d padding=%d cert=%s",
			s.Accepted, s.Forwarded, s.Delivered, s.Dropped, s.Padding, n.certState())
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
