package main

import (
	"bytes"
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

const (
	maxAdminBody  = 4 << 10
	maxCheckEvery = time.Minute
)

const (
	certNone    = "none"
	certValid   = "valid"
	certExpired = "expired"
)

var (
	errNoRequest = fmt.Errorf("no open certificate request: install within %v of POST /csr, once per request", pki.InstallWindow)
	errStaleCert = errors.New("certificate issued before the open request")
	// jimichi enroll recognises this text and prints the restart hint
	errInstalled = errors.New("certificate already installed and valid: a new one needs a relay restart, which gives a fresh identity")
)

// the bundle clients get, with the times that end it
type served struct {
	bundle    []byte
	notAfter  int64
	published int64
	expires   int64
}

// what the node publishes about itself; without -auth there is no identity and
// the descriptor goes out unsigned
type node struct {
	id       *pki.Identity
	unsigned []byte
	ttl      time.Duration
	now      func() time.Time
	logger   *log.Logger

	// replaced only by a signing that succeeded, so a refused or failed
	// installation leaves the previous bundle in service
	out atomic.Pointer[served]
	// not_after of the installed certificate, 0 before the first installation
	notAfter atomic.Int64

	mu          sync.Mutex
	requestAt   time.Time
	installed   []byte
	signedState string
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
	s := n.out.Load()
	if s == nil {
		return nil, false
	}
	if now := n.now().Unix(); now >= s.notAfter || now >= s.expires {
		return nil, false
	}
	return s.bundle, true
}

func (n *node) infoMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, ok := n.descriptor()
		if !ok {
			http.Error(w, "no valid descriptor", http.StatusServiceUnavailable)
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
		writeJSON(w, map[string]any{
			"accepted":  s.Accepted,
			"forwarded": s.Forwarded,
			"delivered": s.Delivered,
			"dropped":   s.Dropped,
			"padding":   s.Padding,
			"cert":      n.certState(),
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
	if n.certState() == certValid {
		http.Error(w, errInstalled.Error(), http.StatusConflict)
		return
	}
	req, err := n.id.Request(nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n.mu.Lock()
	n.requestAt = n.now()
	n.mu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(req)
}

// the loopback port is reachable by anyone allowed to port-forward to the pod
// and Install cannot check a CA signature, so a valid certificate is never
// replaced for the life of the process; a new one needs a restart and with it a
// fresh identity. Sending the installed bytes again succeeds, so a retry after a
// lost answer does not fail
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
	switch {
	case bytes.Equal(raw, n.installed) && n.certState() == certValid:
		w.WriteHeader(http.StatusNoContent)
		return
	case n.certState() == certValid:
		http.Error(w, errInstalled.Error(), http.StatusConflict)
		return
	case n.requestAt.IsZero() || now.Sub(n.requestAt) > pki.InstallWindow:
		http.Error(w, errNoRequest.Error(), http.StatusConflict)
		return
	case cert.NotBefore < n.requestAt.Add(-pki.Skew).Unix():
		http.Error(w, errStaleCert.Error(), http.StatusConflict)
		return
	}
	if err := n.id.Install(raw, now); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.requestAt = time.Time{}
	n.installed = raw
	n.notAfter.Store(cert.NotAfter)
	n.logger.Printf("certificate installed serial=%x not_after=%s",
		cert.Serial, time.Unix(cert.NotAfter, 0).UTC().Format(time.RFC3339))
	if err := n.sign(now); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

// callers hold mu
func (n *node) sign(now time.Time) error {
	n.signedState = n.certState()
	if err := n.id.Refresh(now, n.ttl); err != nil {
		return err
	}
	b, ok := n.id.Bundle()
	if !ok {
		return pki.ErrNoCert
	}
	s, err := servedFrom(b)
	if err != nil {
		return err
	}
	n.out.Store(s)
	return nil
}

func servedFrom(b []byte) (*served, error) {
	bundle, err := pki.ParseBundle(b)
	if err != nil {
		return nil, err
	}
	c, err := pki.ParseCert(bundle.Cert)
	if err != nil {
		return nil, err
	}
	d, err := pki.ParseDescriptor(bundle.Descriptor)
	if err != nil {
		return nil, err
	}
	return &served{bundle: b, notAfter: c.NotAfter, published: d.Published, expires: d.Expires}, nil
}

// a signature on GOST costs math/big work and leaves heap copies of the key,
// so it happens on this timer and never because someone asked for the
// descriptor; the timer runs on the monotonic clock, which stops while the
// host sleeps, hence the frequent look at the wall-clock age
func (n *node) keepFresh() {
	t := time.NewTicker(checkEvery(n.ttl))
	defer t.Stop()
	for range t.C {
		n.refreshIfDue()
	}
}

// a quarter of the lifetime keeps a re-signing due at half of it from
// slipping past the expiry, even for the shortest lifetime of a minute
func checkEvery(ttl time.Duration) time.Duration {
	return min(ttl/4, maxCheckEvery)
}

func (n *node) refreshIfDue() {
	n.mu.Lock()
	defer n.mu.Unlock()
	state := n.certState()
	if state == certNone || state == certExpired && n.signedState == certExpired {
		return
	}
	now := n.now()
	s := n.out.Load()
	due := s == nil || now.Unix()-s.published >= int64(n.ttl/2/time.Second)
	if !due && state == n.signedState {
		return
	}
	if err := n.sign(now); err != nil {
		n.logger.Printf("descriptor refresh: %v", err)
	}
}
