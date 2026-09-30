package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

type config struct {
	listen, info, stats string
	logEvery            time.Duration
	echo                bool
	period              time.Duration
	queue, setupCache   int
	auth                bool
	name, advertise     string
	descriptorTTL       time.Duration
	// refuse to run with keys in memory that could not be locked
	lock bool
	// for the startup line only
	keymem string
	harden bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":9000", "address for cells")
	flag.StringVar(&cfg.info, "info", ":9100", "address for the node descriptor and health check")
	flag.StringVar(&cfg.stats, "stats", "127.0.0.1:9101", "loopback address for counters and enrollment")
	flag.DurationVar(&cfg.logEvery, "log-every", time.Minute, "print aggregated counters to stdout this often; 0 disables")
	flag.BoolVar(&cfg.harden, "harden", true, "disable core dumps and ptrace access for the process")
	suiteName := flag.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	flag.StringVar(&cfg.keymem, "keymem", "all", "key memory measures: all, none, or a list of offheap, lock, dontdump, zero")
	flag.BoolVar(&cfg.echo, "echo", true, "as an exit, send the payload back along the circuit")
	flag.DurationVar(&cfg.period, "period", 0, "send one frame per circuit and direction every period, padding when idle; 0 forwards at once")
	flag.IntVar(&cfg.queue, "queue", 64, "cells a circuit may queue per direction when -period is set")
	flag.IntVar(&cfg.setupCache, "setup-cache", wire.DefaultSetupCache, fmt.Sprintf("setups remembered to refuse a replay, 0 for the default, at most %d; when full the node refuses new circuits until restart", relay.MaxSetupCache))
	flag.BoolVar(&cfg.auth, "auth", true, "serve a descriptor signed under a certificate from jimichi enroll; false serves it unsigned")
	flag.StringVar(&cfg.name, "name", "", "node name for its certificate, required with -auth")
	flag.StringVar(&cfg.advertise, "advertise", "", fmt.Sprintf("host:port clients dial, bound into the certificate, at most %d bytes, required with -auth", wire.AddrSize))
	flag.DurationVar(&cfg.descriptorTTL, "descriptor-ttl", time.Hour, "lifetime of a signed descriptor, re-signed once half of it has passed")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if cfg.auth {
		if err := checkAuthFlags(cfg.stats, cfg.name, cfg.advertise, cfg.descriptorTTL); err != nil {
			logger.Fatal(err)
		}
	}

	policy, err := secmem.ParsePolicy(cfg.keymem)
	if err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if err := secmem.SetPolicy(policy); err != nil {
		logger.Fatalf("keymem: %v", err)
	}
	if cfg.harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Fatalf("harden: %v", err)
		}
	}
	if policy.Lock {
		if err := checkMemlock(); err != nil {
			logger.Fatal(err)
		}
	}
	cfg.lock = policy.Lock
	cfg.keymem = policy.String()

	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		logger.Fatal(err)
	}
	provider, err := suite.New(chosen)
	if err != nil {
		logger.Fatal(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	// logger.Fatal would skip deferred calls; serveNode has released every key
	// by the time it returns
	if err := serveNode(provider, cfg, logger, stop); err != nil {
		logger.Print(err)
		os.Exit(1)
	}
}

func serveNode(provider jcrypto.CryptoProvider, cfg config, logger *log.Logger, stop <-chan os.Signal) error {
	staticPriv, staticPub, err := provider.GenerateEphemeral()
	if err != nil {
		return fmt.Errorf("static key: %w", err)
	}
	defer staticPriv.Release()
	if cfg.lock && !staticPriv.Locked() {
		return errors.New("key memory is not locked, refusing to start")
	}

	n := &node{ttl: cfg.descriptorTTL, now: time.Now, logger: logger}
	if cfg.auth {
		id, err := pki.NewIdentity(provider, cfg.name, cfg.advertise)
		if err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		defer id.Close()
		if cfg.lock && !id.Locked() {
			return errors.New("identity key memory is not locked, refusing to start")
		}
		id.SetKeys(staticPub, staticPub, 0)
		n.id = id
		// printed before any listener serves, so whoever reads the pin from this
		// log finds it once the pod is ready; the full hash is the pin, the
		// fingerprint is for people
		logger.Printf("identity=%s identity_hash=%s name=%s awaiting enrollment", id.Fingerprint(), id.KeyHash(), cfg.name)
	} else if n.unsigned, err = pki.Unsigned(provider, staticPub, staticPub); err != nil {
		return fmt.Errorf("descriptor: %w", err)
	}

	r, err := relay.New(relay.Config{
		Provider:   provider,
		StaticPriv: staticPriv,
		// the payload is never logged: that would hand out exactly the metadata
		// the node exists to withhold
		Deliver: func(_ uint64, payload []byte) []byte {
			if cfg.echo {
				return payload
			}
			return nil
		},
		Period:     cfg.period,
		QueueCells: cfg.queue,
		SetupCache: cfg.setupCache,
	})
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	defer r.Close()

	// bound here rather than inside the serving goroutines: a node whose
	// enrollment port is taken would otherwise run on and never get a certificate
	var lns [3]net.Listener
	for i, addr := range []string{cfg.listen, cfg.info, cfg.stats} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		defer ln.Close()
		lns[i] = ln
	}
	cells, infoLn, adminLn := lns[0], lns[1], lns[2]

	go serve(infoLn, n.infoMux(), logger)
	go serve(adminLn, n.adminMux(r.Stats().Snapshot), logger)
	if n.id != nil {
		go n.keepFresh()
	}
	if cfg.logEvery > 0 {
		go logCounters(r, n, cfg.logEvery, logger)
	}

	logger.Printf("relay listening on %s, info on %s, suite=%s, keymem=%s, locked=%v, harden=%v, period=%v, auth=%v",
		cells.Addr(), infoLn.Addr(), provider.Suite(), cfg.keymem, staticPriv.Locked(), cfg.harden, cfg.period, cfg.auth)
	go func() {
		if err := r.Serve(cells); err != nil {
			logger.Printf("serve: %v", err)
		}
	}()

	<-stop
	logger.Print("shutting down")
	return nil
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

func serve(ln net.Listener, h http.Handler, logger *log.Logger) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Printf("http %s: %v", ln.Addr(), err)
	}
}

func logCounters(r *relay.Relay, n *node, every time.Duration, logger *log.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		s := r.Stats().Snapshot()
		logger.Printf("counters accepted=%d forwarded=%d delivered=%d dropped=%d padding=%d broken=%d cert=%s",
			s.Accepted, s.Forwarded, s.Delivered, s.Dropped, s.Padding, s.Broken, n.certState())
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
