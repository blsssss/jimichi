package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

// a missing peer is asked again this soon, so one that answers late does not
// keep the node from extending for a whole refresh period
const peerRetry = 5 * time.Second

var (
	errRosterEarly = errors.New("no certificate installed: the roster follows the certificate")
	errRosterLate  = fmt.Errorf("roster refused: it is accepted within %v of the certificate", pki.InstallWindow)
	errRosterSet   = errors.New("roster already installed: a new one needs a relay restart")
	errRosterSelf  = errors.New("roster does not list this node under its name and address")
	errNoBundle    = errors.New("no valid descriptor to check the roster's anchor against")
)

type peerEntry struct {
	bundle  []byte
	linkPub []byte
	// unix seconds: when the bundle is fetched again and when it is dropped
	due     int64
	expires int64
}

// what the info port serves as /descriptors, with the moment its first bundle
// runs out
type mirror struct {
	body  []byte
	until int64
}

// the bundles of the other roster nodes, fetched and checked by this node:
// public data, kept in memory only
type peerCache struct {
	self  string
	addrs []string
	// the bundle this node serves itself and when it runs out
	own    func() ([]byte, int64, bool)
	fetch  func(addr string) ([]byte, error)
	read   func(addr string, bundle []byte, now time.Time) (*peerEntry, error)
	now    func() time.Time
	logger *log.Logger

	mu      sync.Mutex
	entries map[string]*peerEntry
	// the last failure logged per peer, so a peer that stays down is one line
	failed map[string]string

	mirror atomic.Pointer[mirror]
}

func newPeerCache(n *node, addrs []string, read func(string, []byte, time.Time) (*peerEntry, error)) *peerCache {
	return &peerCache{
		self:    n.addr,
		addrs:   addrs,
		own:     n.current,
		fetch:   n.fetchPeer,
		read:    read,
		now:     n.now,
		logger:  n.logger,
		entries: make(map[string]*peerEntry, len(addrs)),
		failed:  make(map[string]string),
	}
}

// Verify bounds the descriptor by its certificate, so expires alone ends the entry
func verifiedPeer(p jcrypto.CryptoProvider, anchor pki.Anchor) func(string, []byte, time.Time) (*peerEntry, error) {
	policy := pki.Policy{Anchor: anchor, Skew: pki.Skew}
	return func(addr string, bundle []byte, now time.Time) (*peerEntry, error) {
		v, err := pki.Verify(p, policy, addr, bundle, now)
		if err != nil {
			return nil, err
		}
		s, err := servedFrom(bundle)
		if err != nil {
			return nil, err
		}
		return &peerEntry{bundle: bundle, linkPub: v.LinkPub, due: s.published + (s.expires-s.published)/2, expires: s.expires}, nil
	}
}

// the baseline without node authentication: an unsigned bundle carries no
// times, so it is fetched again on every refresh and never runs out
func unverifiedPeer(p jcrypto.CryptoProvider) func(string, []byte, time.Time) (*peerEntry, error) {
	return func(addr string, bundle []byte, _ time.Time) (*peerEntry, error) {
		nodes, err := pki.Unverified(p, []string{addr}, [][]byte{bundle})
		if err != nil {
			return nil, err
		}
		return &peerEntry{bundle: bundle, linkPub: nodes[0].LinkPub, expires: math.MaxInt64}, nil
	}
}

// reports whether every peer is held afterwards
func (c *peerCache) refresh() bool {
	for _, addr := range c.addrs {
		now := c.now()
		c.mu.Lock()
		e := c.entries[addr]
		c.mu.Unlock()
		// due comes before expires, so an entry that ran out is asked for again
		if e != nil && now.Unix() < e.due {
			continue
		}
		bundle, err := c.fetch(addr)
		var fresh *peerEntry
		if err == nil {
			fresh, err = c.read(addr, bundle, now)
		}
		c.mu.Lock()
		if err != nil {
			if c.failed[addr] != err.Error() {
				c.failed[addr] = err.Error()
				c.logger.Printf("peer %s: descriptor: %v", addr, err)
			}
		} else {
			delete(c.failed, addr)
			c.entries[addr] = fresh
		}
		c.mu.Unlock()
	}
	c.publish()
	return c.held() == len(c.addrs)
}

// encoded here, on a refresh or when this node signs its own descriptor again,
// so a request for the descriptors only copies bytes
func (c *peerCache) publish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	own, until, ok := c.own()
	if !ok {
		c.mirror.Store(nil)
		return
	}
	now := c.now().Unix()
	entries := make([]pki.MirrorEntry, 0, len(c.addrs)+1)
	entries = append(entries, pki.MirrorEntry{Addr: c.self, Bundle: own})
	for _, addr := range c.addrs {
		e := c.entries[addr]
		if e == nil || now >= e.expires {
			c.mirror.Store(nil)
			return
		}
		entries = append(entries, pki.MirrorEntry{Addr: addr, Bundle: e.bundle})
		until = min(until, e.expires)
	}
	body, err := pki.MarshalMirror(entries)
	if err != nil {
		c.logger.Printf("descriptors: %v", err)
		c.mirror.Store(nil)
		return
	}
	c.mirror.Store(&mirror{body: body, until: until})
}

func (c *peerCache) linkKey(addr string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[addr]
	if e == nil || c.now().Unix() >= e.expires {
		return nil, false
	}
	return e.linkPub, true
}

func (c *peerCache) held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	held := 0
	for _, e := range c.entries {
		if now < e.expires {
			held++
		}
	}
	return held
}

func (c *peerCache) descriptors() ([]byte, bool) {
	m := c.mirror.Load()
	if m == nil || c.now().Unix() >= m.until {
		return nil, false
	}
	return m.body, true
}

// what relay.Config.Peers asks: before a roster there is no peer at all
func (n *node) peerKey(addr string) ([]byte, bool) {
	c := n.peers.Load()
	if c == nil {
		return nil, false
	}
	return c.linkKey(addr)
}

// the roster size and how many of the other nodes are held
func (n *node) peerState() (roster, held int) {
	c := n.peers.Load()
	if c == nil {
		return 0, 0
	}
	return len(c.addrs) + 1, c.held()
}

func (n *node) setPeers(addrs []string, read func(string, []byte, time.Time) (*peerEntry, error)) {
	c := newPeerCache(n, addrs, read)
	c.publish()
	n.peers.Store(c)
	if n.wake != nil {
		close(n.wake)
	}
}

// peers are fetched on this timer and never because someone asked for the
// descriptors; ages are read off the wall clock as in keepFresh
func (n *node) keepPeers() {
	<-n.wake
	c := n.peers.Load()
	for {
		wait := checkEvery(n.ttl)
		if !c.refresh() {
			wait = min(wait, peerRetry)
		}
		time.Sleep(wait)
	}
}

// whoever reaches the loopback port within the window could send a roster, so
// a process takes one and it must name an anchor under which this node's own
// certificate verifies: a roster of another CA is refused. Sending the same
// bytes again succeeds, so a retry after a lost answer does not fail
func (n *node) handleRoster(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	roster, err := pki.ParseRoster(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	switch {
	case n.roster != nil && bytes.Equal(raw, n.roster):
		w.WriteHeader(http.StatusNoContent)
		return
	case n.roster != nil:
		http.Error(w, errRosterSet.Error(), http.StatusConflict)
		return
	case n.installed == nil:
		http.Error(w, errRosterEarly.Error(), http.StatusConflict)
		return
	case now.Sub(n.installedAt) > pki.InstallWindow:
		http.Error(w, errRosterLate.Error(), http.StatusConflict)
		return
	}
	bundle, ok := n.descriptor()
	if !ok {
		http.Error(w, errNoBundle.Error(), http.StatusConflict)
		return
	}
	if !roster.Has(n.name, n.addr) {
		http.Error(w, errRosterSelf.Error(), http.StatusBadRequest)
		return
	}
	if _, err := pki.Verify(n.p, pki.Policy{Anchor: roster.Anchor, Skew: pki.Skew}, n.addr, bundle, now); err != nil {
		http.Error(w, fmt.Sprintf("this node's bundle does not verify under the roster's anchor: %v", err), http.StatusBadRequest)
		return
	}
	addrs := make([]string, 0, len(roster.Nodes)-1)
	for _, node := range roster.Nodes {
		if node.Addr != n.addr {
			addrs = append(addrs, node.Addr)
		}
	}
	n.roster = raw
	n.setPeers(addrs, verifiedPeer(n.p, roster.Anchor))
	n.logger.Printf("roster installed nodes=%d ca=%x", len(roster.Nodes), roster.Anchor.ID(n.p))
	w.WriteHeader(http.StatusNoContent)
}
