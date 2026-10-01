package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	// the roster is the largest body the admin port takes
	maxAdminBody  = pki.MaxRoster
	maxCheckEvery = time.Minute
	minCheckEvery = time.Second
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
	errInstalled = errors.New("certificate already installed: a new one needs a relay restart, which gives a fresh identity")
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
	p        jcrypto.CryptoProvider
	name     string
	addr     string
	id       *pki.Identity
	unsigned []byte
	ttl      time.Duration
	now      func() time.Time
	logger   *log.Logger
	// whether the relay still accepts cells; nil counts as serving
	serving func() bool
	// one GET of another node's /descriptor, strictly parsed
	fetchPeer func(addr string) ([]byte, error)
	// pause before a missing or due peer is asked again; zero picks peerRetry
	peerRetry time.Duration

	// nil until the roster arrives, or from the start without -auth
	peers atomic.Pointer[peerCache]
	// closed once peers is set; nil where nothing waits for it
	wake chan struct{}

	descriptorRequests atomic.Uint64
	mirrorRequests     atomic.Uint64

	// replaced only by a signing that succeeded, so a failed re-signing leaves
	// the last good bundle in service until it expires
	out atomic.Pointer[served]
	// not_after of the installed certificate, 0 before the first installation
	notAfter atomic.Int64

	mu        sync.Mutex
	requestAt time.Time
	// the one certificate this process takes, nil until then
	installed   []byte
	installedAt time.Time
	// the one roster this process takes, nil until then
	roster      []byte
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
	return checkTTL(ttl)
}

func checkTTL(ttl time.Duration) error {
	if ttl < time.Minute || ttl > pki.MaxDescriptorLife {
		return fmt.Errorf("-descriptor-ttl %v: want between 1m and %v", ttl, pki.MaxDescriptorLife)
	}
	return nil
}

// with -auth the peers come from the roster; without it -peers names them and
// -advertise is this node's own entry among the descriptors it serves
func checkPeerFlags(auth bool, advertise, peerInfoPort string, peers []string) error {
	if !pki.ValidAddr("node:" + peerInfoPort) {
		return fmt.Errorf("-peer-info-port %q: want a port number", peerInfoPort)
	}
	if auth {
		if len(peers) > 0 {
			return errors.New("-peers is for -auth=false only: with -auth the peers come from the roster")
		}
		return nil
	}
	if advertise == "" {
		if len(peers) > 0 {
			return errors.New("-peers needs -advertise, the address this node itself is listed under")
		}
		return nil
	}
	seen := map[string]bool{advertise: true}
	for _, addr := range append([]string{advertise}, peers...) {
		if !pki.ValidAddr(addr) {
			return fmt.Errorf("%q: want host:port in printable ASCII, lower case, at most %d bytes", addr, wire.AddrSize)
		}
	}
	for _, addr := range peers {
		if seen[addr] {
			return fmt.Errorf("-peers: %s repeated or equal to -advertise", addr)
		}
		seen[addr] = true
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

// the bundle in service and the unix second it runs out
func (n *node) current() ([]byte, int64, bool) {
	if n.id == nil {
		return n.unsigned, math.MaxInt64, n.unsigned != nil
	}
	s := n.out.Load()
	if s == nil {
		return nil, 0, false
	}
	until := min(s.notAfter, s.expires)
	if n.now().Unix() >= until {
		return nil, 0, false
	}
	return s.bundle, until, true
}

func (n *node) descriptor() ([]byte, bool) {
	b, _, ok := n.current()
	return b, ok
}

func (n *node) infoMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if n.serving != nil && !n.serving() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		n.descriptorRequests.Add(1)
		b, ok := n.descriptor()
		if !ok {
			http.Error(w, "no valid descriptor", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	// this node's bundle and the bundles of its roster peers, so a client asks
	// its entry alone; the bytes are ready before the request comes
	mux.HandleFunc("GET /descriptors", func(w http.ResponseWriter, _ *http.Request) {
		n.mirrorRequests.Add(1)
		c := n.peers.Load()
		if c == nil {
			missing := "no descriptors: the node has no roster"
			if n.id == nil {
				missing = "no descriptors: without -auth the node lists itself only under -advertise, and the other nodes from -peers"
			}
			http.Error(w, missing, http.StatusServiceUnavailable)
			return
		}
		b, ok := c.descriptors()
		if !ok {
			http.Error(w, "no valid descriptor of every roster node", http.StatusServiceUnavailable)
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
		roster, held := n.peerState()
		writeJSON(w, map[string]any{
			"accepted":            s.Accepted,
			"forwarded":           s.Forwarded,
			"delivered":           s.Delivered,
			"dropped":             s.Dropped,
			"padding":             s.Padding,
			"broken":              s.Broken,
			"accept_retries":      s.AcceptRetries,
			"refused_links":       s.RefusedLinks,
			"refused_busy":        s.RefusedBusy,
			"refused_source":      s.RefusedSource,
			"refused_rate":        s.RefusedRate,
			"refused_setups":      s.RefusedSetups,
			"refused_extend":      s.RefusedExtend,
			"failed_extend":       s.FailedExtend,
			"timed_out":           s.TimedOut,
			"expired":             s.Expired,
			"cert":                n.certState(),
			"roster":              roster,
			"peers":               held,
			"descriptor_requests": n.descriptorRequests.Load(),
			"mirror_requests":     n.mirrorRequests.Load(),
		})
	})
	if n.id != nil {
		mux.HandleFunc("POST /csr", n.handleRequest)
		mux.HandleFunc("PUT /cert", n.handleCert)
		mux.HandleFunc("PUT /roster", n.handleRoster)
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
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.installed != nil {
		http.Error(w, errInstalled.Error(), http.StatusConflict)
		return
	}
	req, err := n.id.Request(nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n.requestAt = n.now()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(req)
}

// the loopback port is reachable by anyone allowed to port-forward to the pod
// and Install cannot check a CA signature, so a process takes one certificate
// and keeps it, expired or not; a new one needs a restart and with it a fresh
// identity. Sending the installed bytes again while they are valid succeeds, so
// a retry after a lost answer does not fail
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
	case n.installed != nil && bytes.Equal(raw, n.installed) && n.certState() == certValid:
		w.WriteHeader(http.StatusNoContent)
		return
	case n.installed != nil:
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
	n.installedAt = now
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
	if c := n.peers.Load(); c != nil {
		c.publish()
	}
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
// slipping past the expiry, even for the shortest lifetime of a minute; the
// lower bound keeps a ticker valid whatever lifetime it is given
func checkEvery(ttl time.Duration) time.Duration {
	return max(min(ttl/4, maxCheckEvery), minCheckEvery)
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
