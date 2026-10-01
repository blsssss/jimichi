package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/pki"
)

// nodes of one enrollment that reach each other's info port by the address in
// their certificates
type cluster struct {
	p     jcrypto.CryptoProvider
	ca    *pki.CA
	clock *clock
	nodes []*fixture
	web   *http.Client

	mu     sync.Mutex
	routes map[string]string
}

func newCluster(t *testing.T, s jcrypto.Suite, names ...string) *cluster {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	c := &cluster{p: p, ca: newCA(t, p), clock: &clock{now: t0}, web: fetch.NewClient(), routes: make(map[string]string)}
	for _, name := range names {
		f := newNode(t, p, c.ca, c.clock, name)
		f.n.fetchPeer = c.fetch
		c.route(f.n.addr, f.info.URL)
		c.nodes = append(c.nodes, f)
	}
	return c
}

func (c *cluster) route(addr, url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if url == "" {
		delete(c.routes, addr)
		return
	}
	c.routes[addr] = url
}

func (c *cluster) fetch(addr string) ([]byte, error) {
	c.mu.Lock()
	url, ok := c.routes[addr]
	c.mu.Unlock()
	if !ok {
		return nil, errors.New("no node at " + addr)
	}
	return fetch.Bundle(c.web, url+"/descriptor", 1, 0)
}

func (c *cluster) enroll(t *testing.T, notAfter time.Time) {
	t.Helper()
	for _, f := range c.nodes {
		f.enroll(t, notAfter)
	}
}

func rosterOf(anchor pki.Anchor, names ...string) []byte {
	r := pki.Roster{Anchor: anchor}
	for _, name := range names {
		r.Nodes = append(r.Nodes, pki.RosterNode{Name: name, Addr: addrOf(name)})
	}
	return r.Marshal()
}

func (c *cluster) roster() []byte {
	names := make([]string, len(c.nodes))
	for i, f := range c.nodes {
		names[i] = f.n.name
	}
	return rosterOf(c.ca.Anchor(), names...)
}

func (f *fixture) putRoster(t *testing.T, raw []byte) (int, string) {
	t.Helper()
	code, body := call(t, http.MethodPut, f.admin.URL+"/roster", raw)
	return code, string(body)
}

func (f *fixture) takeRoster(t *testing.T, raw []byte) *peerCache {
	t.Helper()
	if code, body := f.putRoster(t, raw); code != http.StatusNoContent {
		t.Fatalf("PUT /roster = %d %s", code, body)
	}
	return f.n.peers.Load()
}

func (f *fixture) descriptors(t *testing.T) (int, []byte) {
	t.Helper()
	return call(t, http.MethodGet, f.info.URL+"/descriptors", nil)
}

// the addresses a node's mirror lists; nil when it serves none
func (f *fixture) mirrored(t *testing.T) []string {
	t.Helper()
	code, raw := f.descriptors(t)
	if code != http.StatusOK {
		return nil
	}
	entries, err := pki.ParseMirror(raw)
	if err != nil {
		t.Fatalf("ParseMirror: %v", err)
	}
	addrs := make([]string, len(entries))
	for i, e := range entries {
		addrs[i] = e.Addr
	}
	return addrs
}

func three(t *testing.T, s jcrypto.Suite) *cluster {
	t.Helper()
	c := newCluster(t, s, "relay-1", "relay-2", "relay-3")
	c.enroll(t, t0.Add(72*time.Hour))
	return c
}

func TestRosterEndpointRules(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2", "relay-3")
	f := c.nodes[0]
	good := c.roster()

	if code, body := f.putRoster(t, good); code != http.StatusConflict || !strings.Contains(body, errRosterEarly.Error()) {
		t.Fatalf("PUT /roster before the certificate = %d %s, want 409", code, body)
	}
	c.enroll(t, t0.Add(72*time.Hour))

	gost, err := suite.New(jcrypto.SuiteGOST)
	if err != nil {
		t.Fatal(err)
	}
	other := pki.Roster{Anchor: c.ca.Anchor(), Nodes: []pki.RosterNode{
		{Name: "relay-1", Addr: addrOf("relay-2")}, {Name: "relay-2", Addr: addrOf("relay-1")},
	}}.Marshal()
	for _, tc := range []struct {
		name string
		raw  []byte
		code int
		want string
	}{
		{"not a roster", []byte("relay-1,relay-2"), http.StatusBadRequest, pki.ErrFormat.Error()},
		{"loose spelling", append(bytes.Clone(good), '\n'), http.StatusBadRequest, pki.ErrFormat.Error()},
		{"over the cap", make([]byte, maxAdminBody+1), http.StatusRequestEntityTooLarge, ""},
		{"anchor of another CA", rosterOf(newCA(t, c.p).Anchor(), "relay-1", "relay-2", "relay-3"), http.StatusBadRequest, pki.ErrUnknownCA.Error()},
		{"anchor of another suite", rosterOf(newCA(t, gost).Anchor(), "relay-1", "relay-2", "relay-3"), http.StatusBadRequest, pki.ErrSuite.Error()},
		{"this node missing", rosterOf(c.ca.Anchor(), "relay-2", "relay-3"), http.StatusBadRequest, errRosterSelf.Error()},
		{"this node's name with another address", other, http.StatusBadRequest, errRosterSelf.Error()},
	} {
		if code, body := f.putRoster(t, tc.raw); code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: PUT /roster = %d %q, want %d with %q", tc.name, code, body, tc.code, tc.want)
		}
	}
	if f.n.peers.Load() != nil {
		t.Fatal("a refused roster gave the node peers")
	}
	if code, _ := call(t, http.MethodPut, f.info.URL+"/roster", good); code != http.StatusNotFound {
		t.Errorf("the public listener answered /roster with %d", code)
	}
	if code, _ := call(t, http.MethodPost, f.admin.URL+"/roster", good); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /roster = %d, want 405", code)
	}

	// a refused roster does not use up the one this process takes
	c.clock.advance(pki.InstallWindow)
	if code, body := f.putRoster(t, good); code != http.StatusNoContent {
		t.Fatalf("PUT /roster at the end of the window = %d %s, want 204", code, body)
	}
	if !strings.Contains(f.log.String(), "roster installed nodes=3 ca=") {
		t.Fatalf("no roster line in the log: %q", f.log.String())
	}
	if got := f.stats(t); !strings.Contains(got, `"roster":3`) || !strings.Contains(got, `"peers":0`) {
		t.Fatalf("stats after the roster: %s", got)
	}

	c.clock.advance(time.Hour)
	if code, body := f.putRoster(t, good); code != http.StatusNoContent {
		t.Fatalf("the installed roster sent again = %d %s, want 204 for a retry", code, body)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"the same nodes in another order", rosterOf(c.ca.Anchor(), "relay-3", "relay-2", "relay-1")},
		{"fewer nodes", rosterOf(c.ca.Anchor(), "relay-1", "relay-2")},
		{"another CA", rosterOf(newCA(t, c.p).Anchor(), "relay-1", "relay-2", "relay-3")},
	} {
		if code, body := f.putRoster(t, tc.raw); code != http.StatusConflict || !strings.Contains(body, errRosterSet.Error()) {
			t.Errorf("%s: PUT /roster over the installed one = %d %s, want 409", tc.name, code, body)
		}
	}
	if got := len(f.n.peers.Load().addrs); got != 2 {
		t.Fatalf("the node holds %d peers after refused rosters, want 2", got)
	}
}

func TestRosterComesWithinTheWindowOfTheCertificate(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	f := c.nodes[1]
	c.clock.advance(pki.InstallWindow + time.Second)
	if code, body := f.putRoster(t, c.roster()); code != http.StatusConflict || !strings.Contains(body, errRosterLate.Error()) {
		t.Fatalf("PUT /roster after the window = %d %s, want 409", code, body)
	}
	if f.n.peers.Load() != nil {
		t.Fatal("a late roster gave the node peers")
	}
}

func TestRosterNeedsADescriptorInService(t *testing.T) {
	c := newCluster(t, jcrypto.SuiteC25519, "relay-1", "relay-2")
	f := c.nodes[0]
	cert := f.issue(t, f.request(t), t0, t0.Add(72*time.Hour))
	f.n.mu.Lock()
	f.n.ttl = 0
	f.n.mu.Unlock()
	if code, body := f.put(t, cert); code != http.StatusInternalServerError {
		t.Fatalf("PUT /cert with signing broken = %d %s, want 500", code, body)
	}
	if code, body := f.putRoster(t, c.roster()); code != http.StatusConflict || !strings.Contains(body, errNoBundle.Error()) {
		t.Fatalf("PUT /roster with no descriptor in service = %d %s, want 409", code, body)
	}
}

func TestNodeHasNoPeersBeforeTheRoster(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	f := c.nodes[0]
	if _, ok := f.n.peerKey(addrOf("relay-2")); ok {
		t.Fatal("a node without a roster knows a peer")
	}
	if code, _ := f.descriptors(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptors before the roster = %d, want 503", code)
	}
	if got := f.stats(t); !strings.Contains(got, `"roster":0`) || !strings.Contains(got, `"peers":0`) || !strings.Contains(got, `"mirror_requests":1`) {
		t.Fatalf("stats before the roster: %s", got)
	}

	rc := relayConfig(c.p, nil, config{auth: true}, f.n)
	if rc.Peers == nil {
		t.Fatal("with -auth the relay extends without asking the node for its peers")
	}
	if _, ok := rc.Peers(addrOf("relay-2")); ok {
		t.Fatal("the relay may extend before a roster arrived")
	}
	cache := f.takeRoster(t, c.roster())
	if _, ok := rc.Peers(addrOf("relay-2")); ok {
		t.Fatal("the relay may extend to a peer whose descriptor it has not checked yet")
	}
	cache.refresh()
	if key, ok := rc.Peers(addrOf("relay-2")); !ok || !bytes.Equal(key, c.nodes[1].pub) {
		t.Fatal("the relay does not get the link key from the peer's descriptor")
	}
	if rc := relayConfig(c.p, nil, config{auth: false}, f.n); rc.Peers != nil {
		t.Fatal("without -auth the relay is given peers; the baseline extends to any address")
	}
}

func TestPeerCacheRefreshesAndExpires(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			c := three(t, s)
			n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
			cache := n1.takeRoster(t, c.roster())
			asked := func() [2]uint64 {
				return [2]uint64{n2.n.descriptorRequests.Load(), n3.n.descriptorRequests.Load()}
			}
			key := func(f *fixture) bool {
				k, ok := n1.n.peerKey(f.n.addr)
				return ok && bytes.Equal(k, f.pub)
			}

			if key(n2) || key(n3) || asked() != [2]uint64{0, 0} {
				t.Fatal("the roster alone gave link keys or fetched on the request")
			}
			if !cache.refresh() {
				t.Fatalf("refresh did not get every peer: %s", n1.log.String())
			}
			if !key(n2) || !key(n3) || asked() != [2]uint64{1, 1} {
				t.Fatalf("after the first refresh: keys %v %v, requests %v", key(n2), key(n3), asked())
			}
			if _, ok := n1.n.peerKey(n1.n.addr); ok {
				t.Fatal("the node is its own peer")
			}
			if _, ok := n1.n.peerKey(addrOf("relay-4")); ok {
				t.Fatal("an address outside the roster is a peer")
			}
			if got := n1.stats(t); !strings.Contains(got, `"roster":3`) || !strings.Contains(got, `"peers":2`) {
				t.Fatalf("stats: %s", got)
			}

			c.clock.advance(29 * time.Minute)
			cache.refresh()
			if asked() != [2]uint64{1, 1} {
				t.Fatalf("requests %v before half of the descriptors' life, want none new", asked())
			}

			// relay-2 signs again at half of its life, relay-3 does not
			c.clock.advance(time.Minute)
			n1.n.refreshIfDue()
			n2.n.refreshIfDue()
			cache.refresh()
			if asked() != [2]uint64{2, 2} {
				t.Fatalf("requests %v at half of the descriptors' life, want one more each", asked())
			}

			c.clock.advance(30 * time.Minute)
			if !key(n2) {
				t.Fatal("the refreshed descriptor of relay-2 ran out with the first one")
			}
			if key(n3) {
				t.Fatal("relay-3 is still a peer after its descriptor expired")
			}
			if got := n1.stats(t); !strings.Contains(got, `"peers":1`) {
				t.Fatalf("stats with one descriptor expired: %s", got)
			}
			if listed := n1.mirrored(t); !slices.Contains(listed, n2.n.addr) || slices.Contains(listed, n3.n.addr) {
				t.Fatalf("GET /descriptors with a peer's descriptor expired lists %v, want relay-2 and not relay-3", listed)
			}
			if asked() != [2]uint64{2, 2} {
				t.Fatalf("requests %v, a lookup or a request for the descriptors fetched", asked())
			}

			if cache.refresh() {
				t.Fatal("refresh reports every peer held while relay-3 serves no descriptor")
			}
			cache.refresh()
			if n := strings.Count(n1.log.String(), "peer "+n3.n.addr+": descriptor:"); n != 1 {
				t.Fatalf("the failure of relay-3 was logged %d times, want once: %q", n, n1.log.String())
			}
			if key(n3) {
				t.Fatal("relay-3 is a peer again without a valid descriptor")
			}

			n3.n.refreshIfDue()
			if !cache.refresh() || !key(n3) {
				t.Fatal("relay-3 did not come back with its new descriptor")
			}
			if code, _ := n1.descriptors(t); code != http.StatusOK {
				t.Fatalf("GET /descriptors with every peer back = %d, want 200", code)
			}
		})
	}
}

func TestPeerBundleMustVerifyAtItsAddress(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]

	foreign := newNode(t, c.p, newCA(t, c.p), c.clock, "relay-2")
	foreign.enroll(t, t0.Add(72*time.Hour))
	unsigned, err := pki.Unsigned(c.p, n2.pub, n2.pub)
	if err != nil {
		t.Fatal(err)
	}
	plain := &fixture{p: c.p, n: &node{p: c.p, addr: n2.n.addr, unsigned: unsigned, ttl: time.Hour, now: c.clock.Now, logger: log.New(io.Discard, "", 0)}}
	plain.serve(t)

	cache := n1.takeRoster(t, c.roster())
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{"the bundle of another roster node", n3.info.URL, pki.ErrWrongAddr.Error()},
		{"a bundle under another CA", foreign.info.URL, pki.ErrUnknownCA.Error()},
		{"an unsigned bundle", plain.info.URL, pki.ErrFormat.Error()},
		{"nobody there", "", "no answer"},
	} {
		c.route(n2.n.addr, tc.url)
		if cache.refresh() {
			t.Fatalf("%s: refresh reports every peer held", tc.name)
		}
		if _, ok := n1.n.peerKey(n2.n.addr); ok {
			t.Fatalf("%s: taken as the descriptor of relay-2", tc.name)
		}
		if !strings.Contains(n1.log.String(), "peer "+n2.n.addr+": descriptor: "+tc.want+"\n") {
			t.Fatalf("%s: no line with %q in the log: %q", tc.name, tc.want, n1.log.String())
		}
		if listed := n1.mirrored(t); slices.Contains(listed, n2.n.addr) || !slices.Contains(listed, n3.n.addr) {
			t.Fatalf("%s: GET /descriptors lists %v, want relay-3 and not relay-2", tc.name, listed)
		}
	}
	if _, ok := n1.n.peerKey(n3.n.addr); !ok {
		t.Fatal("a failing peer took relay-3 with it")
	}

	c.route(n2.n.addr, n2.info.URL)
	if !cache.refresh() {
		t.Fatalf("relay-2 was not taken once it served its own bundle: %s", n1.log.String())
	}
}

func TestDescriptorsMirror(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			c := three(t, s)
			n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
			c.route(n3.n.addr, "")
			cache := n1.takeRoster(t, c.roster())
			cache.refresh()
			code, raw := n1.descriptors(t)
			partial, err := pki.ParseMirror(raw)
			if code != http.StatusOK || err != nil || len(partial) != 2 ||
				partial[0].Addr != n1.n.addr || partial[1].Addr != n2.n.addr {
				t.Fatalf("GET /descriptors with a roster node missing = %d, %d entries, %v, want the node and the peer it holds", code, len(partial), err)
			}

			c.route(n3.n.addr, n3.info.URL)
			cache.refresh()
			code, raw = n1.descriptors(t)
			if code != http.StatusOK {
				t.Fatalf("GET /descriptors = %d %s", code, raw)
			}
			entries, err := pki.ParseMirror(raw)
			if err != nil || len(entries) != 3 {
				t.Fatalf("ParseMirror = %d entries, %v", len(entries), err)
			}
			policy := pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}
			for i, f := range c.nodes {
				if entries[i].Addr != f.n.addr {
					t.Fatalf("entry %d is %s, want %s: sorted by address", i, entries[i].Addr, f.n.addr)
				}
				v, err := pki.Verify(c.p, policy, f.n.addr, entries[i].Bundle, c.clock.Now())
				if err != nil || !bytes.Equal(v.LinkPub, f.pub) {
					t.Fatalf("entry %d: Verify = %v", i, err)
				}
				if _, own := f.descriptor(t); !bytes.Equal(entries[i].Bundle, own) {
					t.Fatalf("entry %d differs from what %s serves itself", i, f.n.name)
				}
			}

			asked := n2.n.descriptorRequests.Load() + n3.n.descriptorRequests.Load()
			c.clock.advance(45 * time.Minute)
			if _, again := n1.descriptors(t); !bytes.Equal(again, raw) {
				t.Fatal("a request changed the descriptors; they are built on a refresh only")
			}
			if n2.n.descriptorRequests.Load()+n3.n.descriptorRequests.Load() != asked {
				t.Fatal("a request for the descriptors fetched from a peer")
			}

			// the node's own new descriptor is in the mirror as soon as it is signed
			n1.n.refreshIfDue()
			_, raw = n1.descriptors(t)
			entries, err = pki.ParseMirror(raw)
			if err != nil {
				t.Fatalf("ParseMirror after the re-signing: %v", err)
			}
			if _, own := n1.descriptor(t); !bytes.Equal(entries[0].Bundle, own) {
				t.Fatal("the mirror kept the node's previous descriptor")
			}

			// the peers' descriptors run out, the node's own was signed again: the
			// mirror goes on with what is left, without a gap
			c.clock.advance(15 * time.Minute)
			code, raw = n1.descriptors(t)
			entries, err = pki.ParseMirror(raw)
			if code != http.StatusOK || err != nil || len(entries) != 1 || entries[0].Addr != n1.n.addr {
				t.Fatalf("GET /descriptors once the peers' descriptors expired = %d, %d entries, %v, want the node alone", code, len(entries), err)
			}
			if got := n1.stats(t); !strings.Contains(got, `"mirror_requests":5`) {
				t.Fatalf("stats: %s", got)
			}
			if got := n2.stats(t); !strings.Contains(got, `"mirror_requests":0`) || !strings.Contains(got, `"descriptor_requests":2`) {
				t.Fatalf("stats of a peer: %s, want the one fetch of relay-1 and the test's own", got)
			}
		})
	}
}

func TestMirrorWaitsForTheNodesOwnDescriptor(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	cache := n1.takeRoster(t, c.roster())
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}

	c.clock.advance(time.Hour)
	n2.n.refreshIfDue()
	n3.n.refreshIfDue()
	if !cache.refresh() {
		t.Fatalf("refresh after the peers signed again: %s", n1.log.String())
	}
	if code, _ := n1.descriptors(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptors while the node's own descriptor is expired = %d, want 503", code)
	}
	if strings.Contains(n1.log.String(), "descriptors:") {
		t.Fatalf("a mirror was encoded without the node's own bundle: %q", n1.log.String())
	}
	n1.n.refreshIfDue()
	if code, _ := n1.descriptors(t); code != http.StatusOK {
		t.Fatalf("GET /descriptors after the node signed again = %d, want 200", code)
	}
}

func TestUnsignedNodeMirrorsItsPeersUnverified(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	c := &cluster{p: p, web: fetch.NewClient(), routes: make(map[string]string), clock: &clock{now: t0}}
	for _, name := range []string{"relay-1", "relay-2", "relay-3"} {
		_, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := pki.Unsigned(p, pub, pub)
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{p: p, pub: pub, log: &logBuffer{}}
		f.n = &node{p: p, addr: addrOf(name), unsigned: unsigned, ttl: time.Hour, now: c.clock.Now, fetchPeer: c.fetch}
		f.n.logger = log.New(f.log, "", 0)
		f.serve(t)
		c.route(f.n.addr, f.info.URL)
		c.nodes = append(c.nodes, f)
	}
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]

	if code, _ := n1.descriptors(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptors of a node that lists nothing = %d, want 503", code)
	}
	n3.n.setPeers(nil, unverifiedPeer(p))
	code, raw := n3.descriptors(t)
	if entries, err := pki.ParseMirror(raw); code != http.StatusOK || err != nil || len(entries) != 1 || entries[0].Addr != n3.n.addr {
		t.Fatalf("GET /descriptors of a node without peers = %d, %v, want itself alone", code, err)
	}

	n1.n.setPeers([]string{n2.n.addr, n3.n.addr}, unverifiedPeer(p))
	cache := n1.n.peers.Load()
	if listed := n1.mirrored(t); len(listed) != 1 || listed[0] != n1.n.addr {
		t.Fatalf("GET /descriptors before the first refresh lists %v, want the node alone", listed)
	}
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	code, raw = n1.descriptors(t)
	entries, err := pki.ParseMirror(raw)
	if code != http.StatusOK || err != nil || len(entries) != 3 {
		t.Fatalf("GET /descriptors = %d, %d entries, %v", code, len(entries), err)
	}
	addrs := []string{n1.n.addr, n2.n.addr, n3.n.addr}
	nodes, err := pki.Unverified(p, addrs, [][]byte{entries[0].Bundle, entries[1].Bundle, entries[2].Bundle})
	if err != nil || !bytes.Equal(nodes[1].OnionPub, n2.pub) || !bytes.Equal(nodes[2].LinkPub, n3.pub) {
		t.Fatalf("Unverified = %v, %v", nodes, err)
	}

	// an unsigned bundle carries no times: it is asked for again a minute later
	// and stays until then
	c.clock.advance(59 * time.Second)
	cache.refresh()
	if got := n2.n.descriptorRequests.Load(); got != 1 {
		t.Fatalf("relay-2 was asked %d times within a minute, want 1", got)
	}
	c.clock.advance(1000 * time.Hour)
	if code, _ := n1.descriptors(t); code != http.StatusOK {
		t.Fatalf("GET /descriptors much later = %d, want 200", code)
	}
	cache.refresh()
	if got := n2.n.descriptorRequests.Load(); got != 2 {
		t.Fatalf("relay-2 was asked %d times over two refreshes a minute apart, want 2", got)
	}
}

func TestPeerFlags(t *testing.T) {
	a1, a2, a3 := addrOf("relay-1"), addrOf("relay-2"), addrOf("relay-3")
	for _, c := range []struct {
		name      string
		auth      bool
		advertise string
		port      string
		peers     []string
		ok        bool
	}{
		{"defaults with auth", true, a1, "9100", nil, true},
		{"peers with auth", true, a1, "9100", []string{a2}, false},
		{"port name", true, a1, "info", nil, false},
		{"port zero", true, a1, "0", nil, false},
		{"port out of range", true, a1, "65536", nil, false},
		{"no port", true, a1, "", nil, false},
		{"baseline alone", false, "", "9100", nil, true},
		{"baseline listing itself", false, a1, "9100", nil, true},
		{"baseline with peers", false, a1, "9100", []string{a2, a3}, true},
		{"peers without an address of its own", false, "", "9100", []string{a2}, false},
		{"bad own address", false, "relay-1", "9100", nil, false},
		{"bad peer address", false, a1, "9100", []string{"relay-2"}, false},
		{"peer repeated", false, a1, "9100", []string{a2, a2}, false},
		{"itself among the peers", false, a1, "9100", []string{a2, a1}, false},
	} {
		err := checkPeerFlags(c.auth, c.advertise, c.port, c.peers)
		if (err == nil) != c.ok {
			t.Errorf("%s: checkPeerFlags = %v, want ok %v", c.name, err, c.ok)
		}
	}
	if got := splitList(" a:1, b:2 ,,"); len(got) != 2 || got[0] != "a:1" || got[1] != "b:2" {
		t.Errorf("splitList = %q", got)
	}
}

// a listener that answers every request with the given bytes, whatever was asked
func rawPeer(t *testing.T, answer func(n int) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var asked atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := int(asked.Add(1))
			go func() {
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 4096))
				_, _ = conn.Write(answer(n))
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// what a peer puts on its status line reaches neither the log nor the cache:
// the cause is one of a fixed set, and a peer that fails the same way in other
// words is still one line
func TestPeerFailureIsLoggedAsABoundedClass(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2 := c.nodes[0], c.nodes[1]
	cache := n1.takeRoster(t, c.roster())
	base := len(n1.log.String())
	clean := func(what string) string {
		t.Helper()
		added := n1.log.String()[base:]
		if len(added) > 400 || strings.ContainsAny(added, "\x1b\x07\x00") || strings.Contains(added, "AAAA") {
			t.Fatalf("%s: the log took %d bytes from the peer: %.120q", what, len(added), added)
		}
		for addr, class := range cache.failed {
			if len(class) > 64 {
				t.Fatalf("%s: the cache keeps %d bytes about %s", what, len(class), addr)
			}
		}
		return added
	}

	c.route(n2.n.addr, rawPeer(t, func(n int) []byte {
		line := fmt.Sprintf("HTTP/1.1 404 try %d \x1b[2J\x07 %s\r\nContent-Length: 0\r\n\r\n", n, strings.Repeat("AAAA", 64))
		return []byte(line)
	}))
	for range 3 {
		cache.refresh()
	}
	added := clean("a status line with control bytes that changes every time")
	if want := "peer " + n2.n.addr + ": descriptor: answered status 404\n"; strings.Count(added, want) != 1 || strings.Count(added, "peer "+n2.n.addr) != 1 {
		t.Fatalf("three answers with status 404 gave %q, want once %q", added, want)
	}

	c.route(n2.n.addr, rawPeer(t, func(int) []byte {
		line := append([]byte("HTTP/1.1 404 "), bytes.Repeat([]byte("AAAA\x1b"), 1<<18)...)
		return append(line, "\r\nContent-Length: 0\r\n\r\n"...)
	}))
	for range 2 {
		cache.refresh()
	}
	added = clean("a status line of more than a megabyte")
	if want := "peer " + n2.n.addr + ": descriptor: no answer\n"; strings.Count(added, want) != 1 || strings.Count(added, "peer "+n2.n.addr) != 2 {
		t.Fatalf("an oversized status line gave %q, want one more line %q", added, want)
	}

	c.route(n2.n.addr, rawPeer(t, func(int) []byte {
		return append([]byte("HTTP/1.1 200 OK\r\n\r\n"), bytes.Repeat([]byte("AAAA"), fetch.MaxBundle)...)
	}))
	cache.refresh()
	added = clean("a body over the size limit")
	if !strings.HasSuffix(added, "descriptor: "+fetch.ErrTooLarge.Error()+"\n") {
		t.Fatalf("an oversized body gave %q", added)
	}
	if _, ok := n1.n.peerKey(n2.n.addr); ok {
		t.Fatal("a peer that never served a bundle is held")
	}
}

func TestFailureClass(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("node x: %w", pki.ErrDescSignature), pki.ErrDescSignature.Error()},
		{pki.ErrFormat, pki.ErrFormat.Error()},
		{&fetch.StatusError{Code: 503}, "answered status 503"},
		{fmt.Errorf("%w of 16384 bytes", fetch.ErrTooLarge), fetch.ErrTooLarge.Error()},
		{errors.New("dial tcp 10.0.0.7:51324->10.0.0.9:9100: connection refused"), "elsewhere"},
		{errors.New("malformed HTTP response \"\\x1b[2J\""), "elsewhere"},
	} {
		if got := failureClass(c.err, "elsewhere"); got != c.want {
			t.Errorf("failureClass(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// the fetch a running node makes: one GET of /descriptor on the info port of
// the host in the roster address
func TestPeerFetcherAsksTheInfoPortOfThePeer(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n2 := c.nodes[1]
	var dialled []string
	web := fetch.NewClient()
	web.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		var d net.Dialer
		return d.DialContext(ctx, network, strings.TrimPrefix(n2.info.URL, "http://"))
	}
	get := peerFetcher(web, "9100")

	bundle, err := get(n2.n.addr)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if _, own := n2.descriptor(t); !bytes.Equal(bundle, own) {
		t.Fatal("the fetch returned something else than the peer's bundle")
	}
	if len(dialled) != 1 || dialled[0] != "relay-2.jimichi.svc.cluster.local:9100" {
		t.Fatalf("dialled %v, want the info port of the roster host once", dialled)
	}
	if got := n2.n.descriptorRequests.Load(); got != 2 {
		t.Fatalf("the peer answered %d requests for its descriptor, want this fetch and the test's own", got)
	}
	if got := n2.n.mirrorRequests.Load(); got != 0 {
		t.Fatalf("the fetch asked for the mirror %d times", got)
	}
	for _, addr := range []string{"relay-2", "relay-2/x:9000", "user@relay-2:9000"} {
		if _, err := get(addr); err == nil {
			t.Errorf("fetch from %q succeeded", addr)
		}
	}
	if len(dialled) != 1 {
		t.Fatalf("a refused address was dialled: %v", dialled)
	}
}

// the timer of a running node: nothing before the roster, then every peer, and
// a peer that answers late is taken on a retry without waiting a whole period
func TestKeepPeersStartsWithTheRosterAndRetriesAMissingPeer(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	c.route(n3.n.addr, "")
	n1.n.wake = make(chan struct{})
	n1.n.peerRetry = 5 * time.Millisecond
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		n1.n.keepPeers(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()
	eventually := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %s", what, n1.log.String())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}

	time.Sleep(30 * time.Millisecond)
	if got := n2.n.descriptorRequests.Load(); got != 0 {
		t.Fatalf("a peer was asked %d times before the roster", got)
	}
	n1.takeRoster(t, c.roster())
	eventually("relay-2 was not taken after the roster", func() bool {
		_, ok := n1.n.peerKey(n2.n.addr)
		return ok
	})
	if _, ok := n1.n.peerKey(n3.n.addr); ok {
		t.Fatal("an unreachable peer is held")
	}
	if got := n2.n.descriptorRequests.Load(); got != 1 {
		t.Fatalf("relay-2 was asked %d times while relay-3 was retried, want once: it is held and not due", got)
	}

	c.route(n3.n.addr, n3.info.URL)
	eventually("relay-3 was not taken once it answered", func() bool {
		_, ok := n1.n.peerKey(n3.n.addr)
		return ok
	})
	eventually("no mirror with every peer held", func() bool {
		code, _ := n1.descriptors(t)
		return code == http.StatusOK
	})
	asked := n2.n.descriptorRequests.Load() + n3.n.descriptorRequests.Load()
	time.Sleep(50 * time.Millisecond)
	if got := n2.n.descriptorRequests.Load() + n3.n.descriptorRequests.Load(); got != asked {
		t.Fatalf("held peers were asked %d more times before any was due", got-asked)
	}
}

func TestKeepPeersEndsBeforeTheRoster(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n := c.nodes[0].n
	n.wake = make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		n.keepPeers(stop)
		close(done)
	}()
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("keepPeers did not end")
	}
}

func TestPeerWaitFollowsTheNearestDueTime(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
	c.route(n3.n.addr, "")
	cache := n1.takeRoster(t, c.roster())
	if got := cache.wait(); got != peerRetry {
		t.Fatalf("wait with no peer held = %v, want the retry pause %v", got, peerRetry)
	}
	cache.refresh()
	if got := cache.wait(); got != peerRetry {
		t.Fatalf("wait with a peer missing = %v, want %v", got, peerRetry)
	}
	c.route(n3.n.addr, n3.info.URL)
	cache.refresh()

	// both descriptors are due at half of their hour
	for _, tc := range []struct {
		at   time.Duration
		want time.Duration
	}{
		{0, time.Minute},
		{28 * time.Minute, time.Minute},
		{29*time.Minute + 20*time.Second, 40 * time.Second},
		{29*time.Minute + 58*time.Second, peerRetry},
		{30 * time.Minute, peerRetry},
		{59 * time.Minute, peerRetry},
		{61 * time.Minute, peerRetry},
	} {
		c.clock.mu.Lock()
		c.clock.now = t0.Add(tc.at)
		c.clock.mu.Unlock()
		if got := cache.wait(); got != tc.want {
			t.Errorf("wait %v after the descriptors were signed = %v, want %v", tc.at, got, tc.want)
		}
	}

	// one peer signed again, the other is still due
	c.clock.mu.Lock()
	c.clock.now = t0.Add(30 * time.Minute)
	c.clock.mu.Unlock()
	n2.n.refreshIfDue()
	cache.refresh()
	if got := cache.wait(); got != peerRetry {
		t.Fatalf("wait with one peer still due = %v, want %v", got, peerRetry)
	}
	n3.n.refreshIfDue()
	cache.refresh()
	if got := cache.wait(); got != time.Minute {
		t.Fatalf("wait with both peers fresh = %v, want %v", got, time.Minute)
	}
}

func TestFailedRefetchKeepsTheEntryUntilItExpires(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	n1, n2 := c.nodes[0], c.nodes[1]
	cache := n1.takeRoster(t, c.roster())
	if !cache.refresh() {
		t.Fatalf("refresh: %s", n1.log.String())
	}
	held := func() bool {
		key, ok := n1.n.peerKey(n2.n.addr)
		return ok && bytes.Equal(key, n2.pub)
	}

	c.clock.advance(40 * time.Minute)
	n1.n.refreshIfDue()
	c.nodes[2].n.refreshIfDue()
	c.route(n2.n.addr, "")
	if !cache.refresh() {
		t.Fatal("a failed re-fetch dropped an entry that has not expired")
	}
	if !held() {
		t.Fatal("relay-2 is no peer after a failed re-fetch, 20 minutes before its descriptor expires")
	}
	if code, _ := n1.descriptors(t); code != http.StatusOK {
		t.Fatalf("GET /descriptors after a failed re-fetch = %d, want 200 with the bundle still valid", code)
	}
	if !strings.Contains(n1.log.String(), "peer "+n2.n.addr+": descriptor: no answer") {
		t.Fatalf("the failed re-fetch is not in the log: %q", n1.log.String())
	}

	c.clock.advance(20 * time.Minute)
	if held() {
		t.Fatal("relay-2 is still a peer at the expiry of its descriptor")
	}
	if cache.refresh() {
		t.Fatal("refresh reports every peer held after the entry expired")
	}
	if listed := n1.mirrored(t); len(listed) == 0 || slices.Contains(listed, n2.n.addr) {
		t.Fatalf("GET /descriptors after the entry expired lists %v, want the mirror without relay-2", listed)
	}
}

func TestDescriptorsSayWhatIsMissing(t *testing.T) {
	c := three(t, jcrypto.SuiteC25519)
	if code, body := c.nodes[0].descriptors(t); code != http.StatusServiceUnavailable || !strings.Contains(string(body), "no roster") {
		t.Fatalf("GET /descriptors before the roster = %d %q", code, body)
	}
	p := c.p
	_, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := pki.Unsigned(p, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	plain := &fixture{p: p, n: &node{p: p, unsigned: unsigned, ttl: time.Hour, now: time.Now, logger: log.New(io.Discard, "", 0)}}
	plain.serve(t)
	code, body := plain.descriptors(t)
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "-advertise") || !strings.Contains(string(body), "-peers") {
		t.Fatalf("GET /descriptors of a node without -auth and -advertise = %d %q, want 503 naming both flags", code, body)
	}
}

func TestDescriptorTTLIsCheckedInEveryMode(t *testing.T) {
	for _, c := range []struct {
		ttl time.Duration
		ok  bool
	}{
		{time.Hour, true}, {time.Minute, true}, {24 * time.Hour, true},
		{0, false}, {-time.Second, false}, {59 * time.Second, false}, {25 * time.Hour, false},
	} {
		if err := checkTTL(c.ttl); (err == nil) != c.ok {
			t.Errorf("checkTTL(%v) = %v, want ok %v", c.ttl, err, c.ok)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Hour, time.Nanosecond, 3 * time.Second} {
		if got := checkEvery(ttl); got < minCheckEvery {
			t.Errorf("checkEvery(%v) = %v, a ticker needs at least %v", ttl, got, minCheckEvery)
		}
	}
}
