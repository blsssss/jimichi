package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/pki"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addrOf(name string) string { return name + ".jimichi.svc.cluster.local:9000" }

type relayKeys struct {
	addr  string
	onion []byte
	link  []byte
}

// a node enrolled under ca the way jimichi enroll does it, serving a
// descriptor signed at t0
func enrolled(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name string, notAfter time.Time) (relayKeys, []byte) {
	t.Helper()
	id, err := pki.NewIdentity(p, name, addrOf(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	var nonce [pki.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(req, t0, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), t0); err != nil {
		t.Fatal(err)
	}
	k := relayKeys{addr: addrOf(name), onion: agreementKey(t, p), link: agreementKey(t, p)}
	id.SetKeys(k.link, k.onion, 0)
	if err := id.Refresh(t0, time.Hour); err != nil {
		t.Fatal(err)
	}
	b, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return k, b
}

func agreementKey(t *testing.T, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
}

func newCA(t *testing.T, p jcrypto.CryptoProvider) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	return ca
}

func TestTrustPolicyIsSettledBeforeAnyFetch(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	anchor := newCA(t, p).Anchor().String()
	gostAnchor := newCA(t, provider(t, jcrypto.SuiteGOST)).Anchor().String()

	for _, c := range []struct {
		name string
		auth bool
		ca   string
		skew time.Duration
		ok   bool
	}{
		{"anchor of the suite", true, anchor, pki.Skew, true},
		{"no anchor", true, "", pki.Skew, false},
		{"malformed anchor", true, "c25519:not base64", pki.Skew, false},
		{"unknown suite", true, "rsa:" + strings.SplitN(anchor, ":", 2)[1], pki.Skew, false},
		{"anchor of the other suite", true, gostAnchor, pki.Skew, false},
		{"negative skew", true, anchor, -time.Second, false},
		{"no anchor without auth", false, "", pki.Skew, true},
	} {
		_, err := trustPolicy(c.auth, c.ca, jcrypto.SuiteC25519, c.skew)
		if (err == nil) != c.ok {
			t.Errorf("%s: trustPolicy = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func TestResolveRefusesWhatDoesNotVerify(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			ca := newCA(t, p)
			until := t0.Add(72 * time.Hour)
			trust := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			k1, b1 := enrolled(t, p, ca, "relay-1", until)
			k2, b2 := enrolled(t, p, ca, "relay-2", until)
			k3, b3 := enrolled(t, p, ca, "relay-3", until)
			addrs := []string{k1.addr, k2.addr, k3.addr}
			bundles := [][]byte{b1, b2, b3}

			nodes, err := resolve(p, true, trust, addrs, bundles, t0)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			chain := chainOf(nodes)
			for i, k := range []relayKeys{k1, k2, k3} {
				if chain[i].Addr != k.addr || !bytes.Equal(chain[i].StaticPub, k.onion) || !bytes.Equal(chain[i].LinkPub, k.link) {
					t.Fatalf("hop %d: %+v, want the onion key as StaticPub and the link key as LinkPub", i, chain[i])
				}
			}

			foreign := pki.Policy{Anchor: newCA(t, p).Anchor(), Skew: pki.Skew}
			_, eb := enrolled(t, p, newCA(t, p), "relay-2", until)
			unsigned, err := pki.Unsigned(p, k2.link, k2.onion)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				name    string
				trust   pki.Policy
				bundles [][]byte
				now     time.Time
				want    error
			}{
				{"foreign anchor", foreign, bundles, t0, pki.ErrUnknownCA},
				{"node certified by another CA", trust, [][]byte{b1, eb, b3}, t0, pki.ErrUnknownCA},
				{"bundle of another address", trust, [][]byte{b1, b3, b2}, t0, pki.ErrWrongAddr},
				{"unsigned bundle", trust, [][]byte{b1, unsigned, b3}, t0, pki.ErrFormat},
				{"descriptor expired", trust, bundles, t0.Add(time.Hour), pki.ErrDescTime},
				{"certificate expired", trust, bundles, until, pki.ErrCertTime},
				{"not yet valid", trust, bundles, t0.Add(-pki.Skew - time.Second), pki.ErrCertTime},
			} {
				_, err := resolve(p, true, c.trust, addrs, c.bundles, c.now)
				if !errors.Is(err, c.want) || !strings.HasPrefix(err.Error(), "node ") {
					t.Errorf("%s: resolve = %v, want node ...: %v", c.name, err, c.want)
				}
			}

			twice := []string{k1.addr, k1.addr}
			if _, err := resolve(p, true, trust, twice, [][]byte{b1, b1}, t0); !errors.Is(err, pki.ErrDuplicate) {
				t.Errorf("repeated node: resolve = %v, want %v", err, pki.ErrDuplicate)
			}

			nodes, err = resolve(p, false, pki.Policy{}, addrs, [][]byte{b1, unsigned, b3}, t0.Add(1000*time.Hour))
			if err != nil {
				t.Fatalf("resolve without auth: %v", err)
			}
			if !bytes.Equal(nodes[1].OnionPub, k2.onion) {
				t.Fatal("resolve without auth lost the unsigned onion key")
			}
		})
	}
}

// the info port of one node: its own bundle and whatever mirror the test gives
// it, with every request counted
type infoServer struct {
	requests atomic.Int32
	mirror   atomic.Pointer[[]byte]
	// answers 503 to this many mirror requests first
	unready atomic.Int32
}

func serveInfo(t *testing.T, own []byte) (*infoServer, string) {
	t.Helper()
	s := &infoServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Add(1)
		_, _ = w.Write(own)
	})
	mux.HandleFunc("GET /descriptors", func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Add(1)
		m := s.mirror.Load()
		if m == nil || s.unready.Add(-1) >= 0 {
			http.Error(w, "incomplete", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(*m)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return s, strings.TrimPrefix(srv.URL, "http://")
}

func mirrorOf(t *testing.T, addrs []string, bundles [][]byte) []byte {
	t.Helper()
	entries := make([]pki.MirrorEntry, len(addrs))
	for i := range addrs {
		entries[i] = pki.MirrorEntry{Addr: addrs[i], Bundle: bundles[i]}
	}
	raw, err := pki.MarshalMirror(entries)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type testbed struct {
	p       jcrypto.CryptoProvider
	trust   pki.Policy
	keys    []relayKeys
	addrs   []string
	bundles [][]byte
	info    []*infoServer
	web     *http.Client
}

// three enrolled nodes whose info ports the client reaches by the names in
// their certificates
func newTestbed(t *testing.T, s jcrypto.Suite) *testbed {
	t.Helper()
	p := provider(t, s)
	ca := newCA(t, p)
	tb := &testbed{p: p, trust: pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}}
	routes := make(map[string]string)
	for _, name := range []string{"relay-1", "relay-2", "relay-3"} {
		k, b := enrolled(t, p, ca, name, t0.Add(72*time.Hour))
		srv, at := serveInfo(t, b)
		host, _, err := net.SplitHostPort(k.addr)
		if err != nil {
			t.Fatal(err)
		}
		routes[net.JoinHostPort(host, "9100")] = at
		tb.keys = append(tb.keys, k)
		tb.addrs = append(tb.addrs, k.addr)
		tb.bundles = append(tb.bundles, b)
		tb.info = append(tb.info, srv)
	}
	tb.web = fetch.NewClient()
	tb.web.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		to, ok := routes[addr]
		if !ok {
			return nil, fmt.Errorf("no node at %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
	return tb
}

func (tb *testbed) publish(t *testing.T, bundles [][]byte) {
	t.Helper()
	m := mirrorOf(t, tb.addrs, bundles)
	for _, srv := range tb.info {
		srv.mirror.Store(&m)
	}
}

func (tb *testbed) requests() [3]int32 {
	return [3]int32{tb.info[0].requests.Load(), tb.info[1].requests.Load(), tb.info[2].requests.Load()}
}

func TestBundlesComeFromTheEntryOnly(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			tb := newTestbed(t, s)
			tb.publish(t, tb.bundles)
			tb.info[0].unready.Store(2)

			bundles, err := chainBundles(tb.web, tb.addrs, "9100", 5, time.Millisecond)
			if err != nil {
				t.Fatalf("chainBundles: %v", err)
			}
			nodes, err := resolve(tb.p, true, tb.trust, tb.addrs, bundles, t0)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			for i, k := range tb.keys {
				if nodes[i].Addr != k.addr || !bytes.Equal(nodes[i].OnionPub, k.onion) || !bytes.Equal(nodes[i].LinkPub, k.link) {
					t.Fatalf("hop %d: %+v, want the keys of %s", i, nodes[i], k.addr)
				}
			}
			if got := tb.requests(); got != [3]int32{3, 0, 0} {
				t.Fatalf("requests per node %v, want two retries and the answer at the entry and none elsewhere", got)
			}

			// a shorter chain through the same entry takes its nodes from the same mirror
			two := []string{tb.addrs[0], tb.addrs[2]}
			bundles, err = chainBundles(tb.web, two, "9100", 1, 0)
			if err != nil {
				t.Fatalf("chainBundles: %v", err)
			}
			if !bytes.Equal(bundles[1], tb.bundles[2]) {
				t.Fatal("the second hop got another node's bundle")
			}
			if _, err := resolve(tb.p, true, tb.trust, two, bundles, t0); err != nil {
				t.Fatalf("resolve: %v", err)
			}
		})
	}
}

func TestEntryIsTheFirstNodeOfTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519)
	tb.publish(t, tb.bundles)
	reversed := []string{tb.addrs[2], tb.addrs[1], tb.addrs[0]}
	if _, err := chainBundles(tb.web, reversed, "9100", 1, 0); err != nil {
		t.Fatalf("chainBundles: %v", err)
	}
	if got := tb.requests(); got != [3]int32{0, 0, 1} {
		t.Fatalf("requests per node %v, want one at the first node of the chain", got)
	}
}

func TestMissingNodeRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519)
	m := mirrorOf(t, tb.addrs[:2], tb.bundles[:2])
	tb.info[0].mirror.Store(&m)

	_, err := chainBundles(tb.web, tb.addrs, "9100", 3, time.Millisecond)
	if !errors.Is(err, errNoBundle) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[2]+": ") {
		t.Fatalf("chainBundles = %v, want node %s: %v", err, tb.addrs[2], errNoBundle)
	}
	if got := tb.requests(); got != [3]int32{1, 0, 0} {
		t.Fatalf("requests per node %v, want one at the entry: a missing node is not asked itself", got)
	}
}

func TestEntryWithoutDescriptorsRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519)
	_, err := chainBundles(tb.web, tb.addrs, "9100", 3, time.Millisecond)
	if err == nil || !strings.HasPrefix(err.Error(), "node "+tb.addrs[0]+": ") {
		t.Fatalf("chainBundles = %v, want an error naming the entry", err)
	}
	if got := tb.requests(); got != [3]int32{3, 0, 0} {
		t.Fatalf("requests per node %v, want three tries at the entry", got)
	}
	if _, err := chainBundles(tb.web, []string{"relay-1"}, "9100", 1, 0); err == nil {
		t.Fatal("chainBundles accepted an entry address without a port")
	}
}

func TestTamperedMirrorRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519)
	_, foreign := enrolled(t, tb.p, newCA(t, tb.p), "relay-2", t0.Add(72*time.Hour))
	unsigned, err := pki.Unsigned(tb.p, tb.keys[1].link, tb.keys[1].onion)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pki.ParseBundle(tb.bundles[1])
	if err != nil {
		t.Fatal(err)
	}
	b.Descriptor[len(b.Descriptor)-1] ^= 1
	altered := b.Marshal()

	for _, c := range []struct {
		name   string
		second []byte
		want   error
	}{
		{"node certified by another CA", foreign, pki.ErrUnknownCA},
		{"bundle of another node", tb.bundles[2], pki.ErrWrongAddr},
		{"unsigned bundle", unsigned, pki.ErrFormat},
		{"descriptor signature altered", altered, pki.ErrDescSignature},
	} {
		tb.publish(t, [][]byte{tb.bundles[0], c.second, tb.bundles[2]})
		bundles, err := chainBundles(tb.web, tb.addrs, "9100", 1, 0)
		if err != nil {
			t.Fatalf("%s: chainBundles: %v", c.name, err)
		}
		_, err = resolve(tb.p, true, tb.trust, tb.addrs, bundles, t0)
		if !errors.Is(err, c.want) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[1]+": ") {
			t.Errorf("%s: resolve = %v, want node %s: %v", c.name, err, tb.addrs[1], c.want)
		}
	}
	if got := tb.requests(); got[1] != 0 || got[2] != 0 {
		t.Fatalf("requests per node %v, want none beyond the entry", got)
	}
}

func TestUnverifiedChainUsesTheSameMirror(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519)
	unsigned := make([][]byte, 3)
	for i, k := range tb.keys {
		b, err := pki.Unsigned(tb.p, k.link, k.onion)
		if err != nil {
			t.Fatal(err)
		}
		unsigned[i] = b
	}
	tb.publish(t, unsigned)
	bundles, err := chainBundles(tb.web, tb.addrs, "9100", 1, 0)
	if err != nil {
		t.Fatalf("chainBundles: %v", err)
	}
	nodes, err := resolve(tb.p, false, pki.Policy{}, tb.addrs, bundles, t0)
	if err != nil || !bytes.Equal(nodes[2].OnionPub, tb.keys[2].onion) {
		t.Fatalf("resolve without auth = %v, %v", nodes, err)
	}
	if got := tb.requests(); got != [3]int32{1, 0, 0} {
		t.Fatalf("requests per node %v, want one at the entry", got)
	}
}
