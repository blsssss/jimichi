package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

const maxAdminBody = 4 << 10

const (
	certNone    = "none"
	certValid   = "valid"
	certExpired = "expired"
)

// what the node publishes about itself; without -auth there is no identity and
// the descriptor goes out unsigned
type node struct {
	id       *pki.Identity
	unsigned []byte
	ttl      time.Duration
	now      func() time.Time
	logger   *log.Logger

	// one installation or refresh at a time, so the expiry below always
	// belongs to the certificate the descriptor was signed under
	mu       sync.Mutex
	notAfter atomic.Int64
}

func checkAuthFlags(stats, name, advertise string, ttl time.Duration) error {
	host, _, err := net.SplitHostPort(stats)
	if err != nil {
		return fmt.Errorf("-stats %q: %v", stats, err)
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("-stats %q: enrollment is served there, so it must be a loopback IP address", stats)
	}
	if !pki.ValidName(name) {
		return fmt.Errorf("-name %q: want 1 to 32 characters of a-z, 0-9 and -", name)
	}
	if !pki.ValidAddr(advertise) {
		return fmt.Errorf("-advertise %q: want host:port in printable ASCII, lower case, at most %d bytes", advertise, wire.AddrSize)
	}
	if ttl < time.Minute || ttl > pki.MaxDescriptorLife {
		return fmt.Errorf("-descriptor-ttl %v: want between 1m and %v", ttl, pki.MaxDescriptorLife)
	}
	return nil
}

func (n *node) certState() string {
	until := n.notAfter.Load()
	switch {
	case until == 0:
		return certNone
	case n.now().Unix() >= until:
		return certExpired
	default:
		return certValid
	}
}

func (n *node) descriptor() ([]byte, bool) {
	if n.id == nil {
		return n.unsigned, n.unsigned != nil
	}
	if n.certState() != certValid {
		return nil, false
	}
	return n.id.Bundle()
}

func (n *node) infoMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, ok := n.descriptor()
		if !ok {
			http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	return mux
}

// counters polled every few milliseconds would show which ticks of a paced
// circuit carried a real cell, so they stay off the network the clients use;
// enrollment shares the loopback listener and is reached by port-forward
func (n *node) adminMux(counters func() relay.Counters) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		s := counters()
		writeJSON(w, map[string]uint64{
			"accepted":  s.Accepted,
			"forwarded": s.Forwarded,
			"delivered": s.Delivered,
			"dropped":   s.Dropped,
			"padding":   s.Padding,
		})
	})
	if n.id != nil {
		mux.HandleFunc("POST /csr", n.handleRequest)
		mux.HandleFunc("PUT /cert", n.handleCert)
	}
	return mux
}

func (n *node) handleRequest(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var nonce [pki.NonceSize]byte
	if len(body) != len(nonce) {
		http.Error(w, fmt.Sprintf("want a %d-byte nonce", len(nonce)), http.StatusBadRequest)
		return
	}
	copy(nonce[:], body)
	req, err := n.id.Request(nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(req)
}

func (n *node) handleCert(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	cert, err := pki.ParseCert(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if err := n.id.Install(raw, now); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.notAfter.Store(cert.NotAfter)
	if err := n.id.Refresh(now, n.ttl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n.logger.Printf("certificate installed serial=%x not_after=%s",
		cert.Serial, time.Unix(cert.NotAfter, 0).UTC().Format(time.RFC3339))
	w.WriteHeader(http.StatusNoContent)
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdminBody))
	if err != nil {
		code := http.StatusBadRequest
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			code = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), code)
		return nil, false
	}
	return body, true
}

// a signature on GOST costs math/big work and leaves heap copies of the key,
// so it runs on this timer only and never because someone asked for the
// descriptor
func (n *node) keepFresh() {
	t := time.NewTicker(n.ttl / 2)
	defer t.Stop()
	for range t.C {
		n.refresh()
	}
}

func (n *node) refresh() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.notAfter.Load() == 0 {
		return
	}
	if err := n.id.Refresh(n.now(), n.ttl); err != nil {
		n.logger.Printf("descriptor refresh: %v", err)
	}
}
