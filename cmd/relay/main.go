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
	"strings"
	"syscall"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
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
	onionRotate         time.Duration
	peerInfoPort        string
	peers               []string
	// refuse to run with keys in memory that could not be locked
	lock bool
	// for the startup line only
	keymem string
	harden bool
	// only the limit fields are set, straight from the flags
	limits relay.Config
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
	flag.BoolVar(&cfg.auth, "auth", true, "serve a descriptor signed under a certificate from jimichi enroll and extend only to the roster nodes it names, over authenticated links; false serves it unsigned and extends to any address over anonymous links")
	flag.StringVar(&cfg.name, "name", "", "node name for its certificate, required with -auth")
	flag.StringVar(&cfg.advertise, "advertise", "", fmt.Sprintf("host:port clients dial, bound into the certificate, at most %d bytes, required with -auth; without -auth the address this node lists itself under in /descriptors", wire.AddrSize))
	flag.DurationVar(&cfg.descriptorTTL, "descriptor-ttl", time.Hour, "lifetime of a signed descriptor, re-signed once half of it has passed")
	flag.DurationVar(&cfg.onionRotate, "onion-rotate", 0, fmt.Sprintf("replace the onion key this often and release the replaced one -descriptor-ttl plus %v later, once no valid descriptor names it; a setup cell recorded before that no longer opens with what the node holds; the next rotation waits for that release; not shorter than -descriptor-ttl; 0 keeps the link key as the onion key for the life of the process", pki.Skew))
	flag.StringVar(&cfg.peerInfoPort, "peer-info-port", "9100", "port where the other nodes publish their descriptors")
	peers := flag.String("peers", "", "without -auth only: comma separated host:port of the other nodes, whose unsigned descriptors this node serves in /descriptors; with -auth they come from the roster")
	flag.DurationVar(&cfg.limits.HandshakeTimeout, "handshake-timeout", relay.DefaultHandshakeTimeout, "close a connection whose link handshake has not finished this long after it was accepted; an initiator sends its hello at once; negative turns it off")
	flag.DurationVar(&cfg.limits.SetupTimeout, "setup-timeout", relay.DefaultSetupTimeout, "close a link that has opened no circuit this long after its handshake; clients and relays send the setup at once; negative turns it off")
	flag.DurationVar(&cfg.limits.WriteTimeout, "write-timeout", 0, "longest one frame may wait to be written before its circuit is torn down, so a peer that stops reading cannot hold a sender; 0 picks 4 periods and at least 1s, or 5s without -period; negative turns it off")
	flag.DurationVar(&cfg.limits.IdleTimeout, "idle-timeout", relay.DefaultIdleTimeout, "tear down a circuit that carried no cell either way this long, so an abandoned paced circuit stops sending padding; the stand client sends every 200ms; negative turns it off")
	flag.DurationVar(&cfg.limits.CircuitLifetime, "circuit-lifetime", relay.DefaultCircuitLifetime, "tear down any circuit this old, which bounds how long one set of circuit keys lives; the client builds a new one; negative turns it off")
	flag.IntVar(&cfg.limits.MaxHandshakes, "max-handshakes", relay.DefaultMaxHandshakes, "link handshakes running at once; more would only queue for the CPU while each holds a socket; negative turns it off")
	flag.IntVar(&cfg.limits.MaxHandshakesPerSource, "max-handshakes-per-source", 0, "link handshakes one address may run at once, so it cannot hold every slot of -max-handshakes; 0 picks an eighth of -max-handshakes and at least 1, also 4 when -max-handshakes is off; negative turns it off")
	flag.IntVar(&cfg.limits.MaxLinks, "max-links", relay.DefaultMaxLinks, "open inbound links; keeps the sockets, goroutines and locked key pages of their circuits inside a 128 MiB pod; negative turns it off")
	flag.IntVar(&cfg.limits.MaxLinksPerSource, "max-links-per-source", relay.DefaultMaxLinksPerSource, "open inbound links from one address, an IPv6 /64 counting as one, so one peer cannot take every slot; a preceding relay is one address for all it forwards, so forwarding nodes turn this off; negative turns it off")
	flag.Float64Var(&cfg.limits.SourceLinkRate, "source-link-rate", relay.DefaultSourceLinkRate, "new links per second one address may open, checked before any key agreement; every connection costs one, refused or not; negative turns it off")
	flag.IntVar(&cfg.limits.SourceLinkBurst, "source-link-burst", relay.DefaultSourceLinkBurst, "links one address may open at once before -source-link-rate applies; covers a client building several circuits; 0 for the default, a negative -source-link-rate turns the limit off")
	flag.Float64Var(&cfg.limits.SourceSetupRate, "source-setup-rate", relay.DefaultSourceSetupRate, "circuit setups per second from one address, checked after the link handshake and before the agreement with the node key, each costing that agreement, a dial onwards and a tag held until restart; at the default one address needs about 91 hours to fill -setup-cache; negative turns it off")
	flag.IntVar(&cfg.limits.SourceSetupBurst, "source-setup-burst", relay.DefaultSourceSetupBurst, "setups one address may send at once before -source-setup-rate applies; 0 for the default, a negative -source-setup-rate turns the limit off")
	flag.Parse()
	cfg.peers = splitList(*peers)

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if cfg.auth {
		if err := checkAuthFlags(cfg.stats, cfg.name, cfg.advertise, cfg.descriptorTTL); err != nil {
			logger.Fatal(err)
		}
	} else if err := checkTTL(cfg.descriptorTTL); err != nil {
		logger.Fatal(err)
	}
	if err := checkPeerFlags(cfg.auth, cfg.advertise, cfg.peerInfoPort, cfg.peers); err != nil {
		logger.Fatal(err)
	}
	if err := checkRotateFlags(cfg.onionRotate, cfg.descriptorTTL); err != nil {
		logger.Fatal(err)
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

	n := &node{
		p: provider, name: cfg.name, addr: cfg.advertise,
		ttl: cfg.descriptorTTL, now: time.Now, logger: logger,
		wake:      make(chan struct{}),
		fetchPeer: peerFetcher(fetch.NewClient(), cfg.peerInfoPort),
	}
	// a rotating node opens setups with a key of its own from the start: the
	// link key lives as long as the process, so an epoch under it would not end
	onionPub := staticPub
	if cfg.onionRotate > 0 {
		onionPriv, pub, err := provider.GenerateEphemeral()
		if err != nil {
			return fmt.Errorf("onion key: %w", err)
		}
		if cfg.lock && !onionPriv.Locked() {
			onionPriv.Release()
			return errors.New("onion key memory is not locked, refusing to start")
		}
		ring, err := relay.NewOnionRing(provider, onionPriv, pub, cfg.setupCache)
		if err != nil {
			onionPriv.Release()
			return fmt.Errorf("onion key: %w", err)
		}
		defer ring.Close()
		onionPub = pub
		n.link = staticPub
		n.onion = newOnionKeys(ring, cfg.onionRotate, cfg.descriptorTTL, cfg.lock, n.now())
	}
	if cfg.auth {
		id, err := pki.NewIdentity(provider, cfg.name, cfg.advertise)
		if err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		defer id.Close()
		if cfg.lock && !id.Locked() {
			return errors.New("identity key memory is not locked, refusing to start")
		}
		id.SetKeys(staticPub, onionPub, 0)
		n.id = id
		// printed before any listener serves, so whoever reads the pin from this
		// log finds it once the pod is ready; the full hash is the pin, the
		// fingerprint is for people
		logger.Printf("identity=%s identity_hash=%s name=%s awaiting enrollment", id.Fingerprint(), id.KeyHash(), cfg.name)
	} else if n.unsigned, err = pki.Unsigned(provider, staticPub, onionPub); err != nil {
		return fmt.Errorf("descriptor: %w", err)
	}

	if !cfg.auth && cfg.advertise != "" {
		n.setPeers(cfg.peers, unverifiedPeer(provider))
	}

	r, err := relay.New(relayConfig(provider, staticPriv, cfg, n))
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

	served := make(chan error, 1)
	go func() { served <- r.Serve(cells) }()
	n.serving = r.Serving
	go serve(infoLn, n.infoMux(), logger)
	go serve(adminLn, n.adminMux(r.Stats().Snapshot), logger)
	if n.id != nil {
		go n.keepFresh()
	}
	if n.onion != nil {
		stopped := make(chan struct{})
		defer close(stopped)
		go n.keepOnion(stopped)
	}
	go n.keepPeers(nil)
	if cfg.logEvery > 0 {
		go logCounters(r, n, cfg.logEvery, logger)
	}

	logger.Printf("relay listening on %s, info on %s, suite=%s, keymem=%s, locked=%v, harden=%v, period=%v, auth=%v, onion_rotate=%v",
		cells.Addr(), infoLn.Addr(), provider.Suite(), cfg.keymem, staticPriv.Locked(), cfg.harden, cfg.period, cfg.auth, cfg.onionRotate)
	return untilStopped(stop, served, logger)
}

// a node that no longer accepts must not stay up looking ready: the error makes
// the process exit, and the orchestrator starts a fresh one
func untilStopped(stop <-chan os.Signal, served <-chan error, logger *log.Logger) error {
	select {
	case <-stop:
		logger.Print("shutting down")
		return nil
	case err := <-served:
		return fmt.Errorf("serve stopped: %v", err)
	}
}

func relayConfig(provider jcrypto.CryptoProvider, staticPriv *secmem.Buffer, cfg config, n *node) relay.Config {
	rc := relay.Config{
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

		HandshakeTimeout:       cfg.limits.HandshakeTimeout,
		SetupTimeout:           cfg.limits.SetupTimeout,
		WriteTimeout:           cfg.limits.WriteTimeout,
		IdleTimeout:            cfg.limits.IdleTimeout,
		CircuitLifetime:        cfg.limits.CircuitLifetime,
		MaxHandshakes:          cfg.limits.MaxHandshakes,
		MaxHandshakesPerSource: cfg.limits.MaxHandshakesPerSource,
		MaxLinks:               cfg.limits.MaxLinks,
		MaxLinksPerSource:      cfg.limits.MaxLinksPerSource,
		SourceLinkRate:         cfg.limits.SourceLinkRate,
		SourceLinkBurst:        cfg.limits.SourceLinkBurst,
		SourceSetupRate:        cfg.limits.SourceSetupRate,
		SourceSetupBurst:       cfg.limits.SourceSetupBurst,
	}
	// set from the start, so until a roster arrives the node extends nowhere
	if cfg.auth {
		rc.Peers = n.peerKey
	}
	if n.onion != nil {
		rc.Onion = n.onion.ring
	}
	return rc
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// a setup holds a handful of key pages at once, the static and identity keys
// one more each, the onion keys of a rotating node up to three while one is
// replaced; below this the node would start and then fail its first circuits
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
		roster, held := n.peerState()
		logger.Printf("counters accepted=%d forwarded=%d delivered=%d dropped=%d padding=%d broken=%d"+
			" accept_retries=%d refused_links=%d refused_busy=%d refused_source=%d refused_rate=%d refused_setups=%d refused_extend=%d failed_extend=%d timed_out=%d expired=%d"+
			" cert=%s roster=%d peers=%d descriptor_requests=%d mirror_requests=%d onion_epoch=%d",
			s.Accepted, s.Forwarded, s.Delivered, s.Dropped, s.Padding, s.Broken,
			s.AcceptRetries, s.RefusedLinks, s.RefusedBusy, s.RefusedSource, s.RefusedRate, s.RefusedSetups, s.RefusedExtend, s.FailedExtend, s.TimedOut, s.Expired,
			n.certState(), roster, held, n.descriptorRequests.Load(), n.mirrorRequests.Load(), n.onionEpoch())
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
