package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/fetch"
	"github.com/jimichi-org/jimichi/link"
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
			chain := chainOf(nodes, []int{0, 1, 2})
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
	routes  map[string]string
	web     *http.Client
}

// n enrolled nodes whose info ports the client reaches by the names in their
// certificates
func newTestbed(t *testing.T, s jcrypto.Suite, n int) *testbed {
	t.Helper()
	p := provider(t, s)
	ca := newCA(t, p)
	tb := &testbed{p: p, trust: pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}, routes: make(map[string]string)}
	for i := 1; i <= n; i++ {
		k, b := enrolled(t, p, ca, fmt.Sprintf("relay-%d", i), t0.Add(72*time.Hour))
		srv, at := serveInfo(t, b)
		tb.routes[infoAddr(t, k.addr)] = at
		tb.keys = append(tb.keys, k)
		tb.addrs = append(tb.addrs, k.addr)
		tb.bundles = append(tb.bundles, b)
		tb.info = append(tb.info, srv)
	}
	tb.web = fetch.NewClient()
	tb.web.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		to, ok := tb.routes[addr]
		if !ok {
			return nil, fmt.Errorf("no node at %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
	return tb
}

func infoAddr(t *testing.T, addr string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, "9100")
}

func (tb *testbed) publish(t *testing.T, bundles [][]byte) {
	t.Helper()
	m := mirrorOf(t, tb.addrs, bundles)
	for _, srv := range tb.info {
		srv.mirror.Store(&m)
	}
}

func (tb *testbed) requests() []int32 {
	out := make([]int32, len(tb.info))
	for i, srv := range tb.info {
		out[i] = srv.requests.Load()
	}
	return out
}

func (tb *testbed) selection(hops int, rnd io.Reader) selection {
	return selection{
		addrs: tb.addrs, hops: hops, infoPort: "9100", auth: true, trust: tb.trust,
		web: tb.web, attempts: 1, rnd: rnd,
	}
}

// a stream of the given 64-bit values, one per draw
func words(values ...uint64) *bytes.Reader {
	b := make([]byte, 0, 8*len(values))
	for _, v := range values {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return bytes.NewReader(b)
}

// the chain a selection builds and the lines it logs on the way
func build(s selection, p jcrypto.CryptoProvider) ([]client.Node, string, error) {
	var out bytes.Buffer
	chain, err := s.chain(p, log.New(&out, "", 0), t0)
	return chain, out.String(), err
}

func namesAny(text string, addrs []string) bool {
	for _, addr := range addrs {
		host, _, _ := net.SplitHostPort(addr)
		if strings.Contains(text, host) {
			return true
		}
	}
	return false
}

func TestNodeListIsCheckedBeforeAnythingIsDrawn(t *testing.T) {
	list := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = addrOf(fmt.Sprintf("relay-%d", i+1))
		}
		return out
	}
	for _, c := range []struct {
		name  string
		suite jcrypto.Suite
		addrs []string
		hops  int
		port  string
		ok    bool
	}{
		{"three of five", jcrypto.SuiteC25519, list(5), 3, "9100", true},
		{"as many hops as nodes", jcrypto.SuiteC25519, list(3), 3, "9100", true},
		{"four hops fit a c25519 setup cell", jcrypto.SuiteC25519, list(5), 4, "9100", true},
		{"five do not", jcrypto.SuiteC25519, list(5), 5, "9100", false},
		{"three hops fit a gost setup cell", jcrypto.SuiteGOST, list(5), 3, "9100", true},
		{"four do not", jcrypto.SuiteGOST, list(5), 4, "9100", false},
		{"one hop", jcrypto.SuiteC25519, list(5), 1, "9100", true},
		{"no hops", jcrypto.SuiteC25519, list(5), 0, "9100", false},
		{"negative hops", jcrypto.SuiteC25519, list(5), -1, "9100", false},
		{"fewer nodes than hops", jcrypto.SuiteC25519, list(2), 3, "9100", false},
		{"no nodes", jcrypto.SuiteC25519, nil, 3, "9100", false},
		{"a node listed twice", jcrypto.SuiteC25519, append(list(4), addrOf("relay-2")), 3, "9100", false},
		{"a node without a port", jcrypto.SuiteC25519, append(list(4), "relay-9"), 3, "9100", false},
		{"a node in upper case", jcrypto.SuiteC25519, append(list(4), "Relay-9:9000"), 3, "9100", false},
		{"an info port that is a path", jcrypto.SuiteC25519, list(5), 3, "9100/x", false},
	} {
		err := checkNodes(provider(t, c.suite), c.addrs, c.hops, c.port)
		if (err == nil) != c.ok {
			t.Errorf("%s: checkNodes = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func TestBundlesComeFromTheEntryOnly(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			tb := newTestbed(t, s, 3)
			tb.publish(t, tb.bundles)
			tb.info[0].unready.Store(2)

			bundles, err := nodeBundles(tb.web, tb.addrs, 0, "9100", 5, time.Millisecond)
			if err != nil {
				t.Fatalf("nodeBundles: %v", err)
			}
			nodes, err := resolve(tb.p, true, tb.trust, tb.addrs, bundles, t0)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			for i, k := range tb.keys {
				if nodes[i].Addr != k.addr || !bytes.Equal(nodes[i].OnionPub, k.onion) || !bytes.Equal(nodes[i].LinkPub, k.link) {
					t.Fatalf("node %d: %+v, want the keys of %s", i, nodes[i], k.addr)
				}
			}
			if got := tb.requests(); !slices.Equal(got, []int32{3, 0, 0}) {
				t.Fatalf("requests per node %v, want two retries and the answer at the entry and none elsewhere", got)
			}

			if _, err := nodeBundles(tb.web, tb.addrs, 2, "9100", 1, 0); err != nil {
				t.Fatalf("nodeBundles: %v", err)
			}
			if got := tb.requests(); !slices.Equal(got, []int32{3, 0, 1}) {
				t.Fatalf("requests per node %v, want one more at the third node as the entry", got)
			}
		})
	}
}

func TestMissingNodeRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 3)
	m := mirrorOf(t, tb.addrs[:2], tb.bundles[:2])
	tb.info[0].mirror.Store(&m)

	_, err := nodeBundles(tb.web, tb.addrs, 0, "9100", 3, time.Millisecond)
	if !errors.Is(err, errNoBundle) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[2]+": ") {
		t.Fatalf("nodeBundles = %v, want node %s: %v", err, tb.addrs[2], errNoBundle)
	}
	if got := tb.requests(); !slices.Equal(got, []int32{1, 0, 0}) {
		t.Fatalf("requests per node %v, want one at the entry: a missing node is not asked itself", got)
	}
}

func TestEntryWithoutDescriptorsRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 3)
	_, err := nodeBundles(tb.web, tb.addrs, 0, "9100", 3, time.Millisecond)
	var failed *entryError
	var status *fetch.StatusError
	if !errors.As(err, &failed) || !errors.As(err, &status) || status.Code != http.StatusServiceUnavailable {
		t.Fatalf("nodeBundles = %v, want the entry's 503", err)
	}
	if got := tb.requests(); !slices.Equal(got, []int32{3, 0, 0}) {
		t.Fatalf("requests per node %v, want three tries at the entry", got)
	}
	if _, err := nodeBundles(tb.web, []string{"relay-1"}, 0, "9100", 1, 0); !errors.As(err, &failed) {
		t.Fatalf("nodeBundles with an entry address without a port = %v, want a failure of the entry", err)
	}
}

func TestTamperedMirrorRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 3)
	_, foreign := enrolled(t, tb.p, newCA(t, tb.p), "relay-2", t0.Add(72*time.Hour))
	unsigned, err := pki.Unsigned(tb.p, tb.keys[1].link, tb.keys[1].onion)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name   string
		second []byte
		want   error
	}{
		{"node certified by another CA", foreign, pki.ErrUnknownCA},
		{"bundle of another node", tb.bundles[2], pki.ErrWrongAddr},
		{"unsigned bundle", unsigned, pki.ErrFormat},
		{"descriptor signature altered", altered(t, tb.bundles[1]), pki.ErrDescSignature},
	} {
		tb.publish(t, [][]byte{tb.bundles[0], c.second, tb.bundles[2]})
		bundles, err := nodeBundles(tb.web, tb.addrs, 0, "9100", 1, 0)
		if err != nil {
			t.Fatalf("%s: nodeBundles: %v", c.name, err)
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

// the bundle with one bit of its descriptor signature flipped
func altered(t *testing.T, bundle []byte) []byte {
	t.Helper()
	b, err := pki.ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b.Descriptor[len(b.Descriptor)-1] ^= 1
	return b.Marshal()
}

func TestUnverifiedChainUsesTheSameMirror(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 3)
	unsigned := make([][]byte, 3)
	for i, k := range tb.keys {
		b, err := pki.Unsigned(tb.p, k.link, k.onion)
		if err != nil {
			t.Fatal(err)
		}
		unsigned[i] = b
	}
	tb.publish(t, unsigned)
	s := tb.selection(3, words(7, 6, 5))
	s.auth, s.trust = false, pki.Policy{}
	// 7 mod 3 = 1 is the entry; 6 mod 2 = 0 takes node 0 of the others 0 2,
	// and the last draw has one node left
	chain, logged, err := build(s, tb.p)
	if err != nil || len(chain) != 3 || chain[0].Addr != tb.addrs[1] || chain[1].Addr != tb.addrs[0] || chain[2].Addr != tb.addrs[2] {
		t.Fatalf("chain without auth = %v, %v, want nodes 1, 0, 2", chain, err)
	}
	if !bytes.Equal(chain[2].StaticPub, tb.keys[2].onion) || logged != "" {
		t.Fatalf("chain without auth lost the unsigned onion key or logged %q", logged)
	}
	if got := tb.requests(); !slices.Equal(got, []int32{0, 1, 0}) {
		t.Fatalf("requests per node %v, want one at the entry", got)
	}
}

// the draws are worked by hand in client.TestChooseKnownAnswer: among five
// nodes the values 7, 6, 5 give the path 2, 3, 4, and a fourth hop on the value
// 9 takes 9 mod 2 = 1, the second of the remaining nodes 0 1
func TestDrawnChainAsksItsEntryAndVerifiesEveryListedNode(t *testing.T) {
	for _, c := range []struct {
		suite  jcrypto.Suite
		stream []uint64
		want   []int
	}{
		{jcrypto.SuiteC25519, []uint64{7, 6, 5}, []int{2, 3, 4}},
		{jcrypto.SuiteGOST, []uint64{7, 6, 5}, []int{2, 3, 4}},
		{jcrypto.SuiteC25519, []uint64{7, 6, 5, 9}, []int{2, 3, 4, 1}},
		{jcrypto.SuiteC25519, []uint64{6}, []int{1}},
	} {
		t.Run(fmt.Sprintf("%s-%d", c.suite, len(c.want)), func(t *testing.T) {
			tb := newTestbed(t, c.suite, 5)
			tb.publish(t, tb.bundles)
			stream := words(c.stream...)
			chain, logged, err := build(tb.selection(len(c.want), stream), tb.p)
			if err != nil {
				t.Fatalf("chain: %v", err)
			}
			if len(chain) != len(c.want) || stream.Len() != 0 {
				t.Fatalf("chain of %d hops with %d bytes of the stream left, want %d and 0", len(chain), stream.Len(), len(c.want))
			}
			for i, node := range c.want {
				k := tb.keys[node]
				if chain[i].Addr != k.addr || !bytes.Equal(chain[i].StaticPub, k.onion) || !bytes.Equal(chain[i].LinkPub, k.link) {
					t.Fatalf("hop %d: %+v, want the keys of node %d, %s", i, chain[i], node, k.addr)
				}
			}
			asked := make([]int32, 5)
			asked[c.want[0]] = 1
			if got := tb.requests(); !slices.Equal(got, asked) {
				t.Fatalf("requests per node %v, want one at the entry, node %d, and none elsewhere", got, c.want[0])
			}
			lines := strings.Split(strings.TrimSuffix(logged, "\n"), "\n")
			if len(lines) != 5 {
				t.Fatalf("%d lines logged, want one per listed node:\n%s", len(lines), logged)
			}
			for i, line := range lines {
				if !strings.HasPrefix(line, fmt.Sprintf("node relay-%d identity=", i+1)) {
					t.Fatalf("line %d is %q, want the listed order", i, line)
				}
			}
		})
	}
}

// 6, 4, 3: the entry is 6 mod 5 = 1 of the others 0 2 3 4, then 4 mod 4 = 0
// takes node 0 and 3 mod 3 = 0 takes node 2
func TestLogIsTheSameWhateverThePath(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)
	tb.publish(t, tb.bundles)
	first, logFirst, err := build(tb.selection(3, words(7, 6, 5)), tb.p)
	if err != nil {
		t.Fatal(err)
	}
	second, logSecond, err := build(tb.selection(3, words(6, 4, 3)), tb.p)
	if err != nil {
		t.Fatal(err)
	}
	for i, node := range []int{1, 0, 2} {
		if second[i].Addr != tb.addrs[node] {
			t.Fatalf("hop %d of the second chain is %s, want node %d", i, second[i].Addr, node)
		}
	}
	if first[0].Addr == second[0].Addr {
		t.Fatal("both chains start at one entry, the comparison shows nothing")
	}
	if logFirst != logSecond {
		t.Fatalf("the log depends on the path:\n%s\n%s", logFirst, logSecond)
	}
}

func TestNodeOffThePathStillRefusesTheChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)

	bad := slices.Clone(tb.bundles)
	bad[0] = altered(t, tb.bundles[0])
	tb.publish(t, bad)
	chain, _, err := build(tb.selection(3, words(7, 6, 5)), tb.p)
	if !errors.Is(err, pki.ErrDescSignature) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[0]+": ") || chain != nil {
		t.Fatalf("chain = %v, %v, want node %s: %v though the path 2, 3, 4 does not hold it", chain, err, tb.addrs[0], pki.ErrDescSignature)
	}

	bad = slices.Clone(tb.bundles)
	bad[4] = altered(t, tb.bundles[4])
	tb.publish(t, bad)
	s := tb.selection(3, nil)
	s.fixed = true
	chain, _, err = build(s, tb.p)
	if !errors.Is(err, pki.ErrDescSignature) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[4]+": ") || chain != nil {
		t.Fatalf("fixed chain = %v, %v, want node %s: %v though the chain ends at the third node", chain, err, tb.addrs[4], pki.ErrDescSignature)
	}

	m := mirrorOf(t, tb.addrs[1:], tb.bundles[1:])
	tb.info[2].mirror.Store(&m)
	chain, _, err = build(tb.selection(3, words(7, 6, 5)), tb.p)
	if !errors.Is(err, errNoBundle) || !strings.HasPrefix(err.Error(), "node "+tb.addrs[0]+": ") || chain != nil {
		t.Fatalf("chain = %v, %v, want node %s: %v", chain, err, tb.addrs[0], errNoBundle)
	}
}

func TestFixedChainKeepsTheListedOrder(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)
	tb.publish(t, tb.bundles)
	s := tb.selection(3, iotest.ErrReader(errors.New("a fixed chain draws nothing")))
	s.fixed = true
	chain, logged, err := build(s, tb.p)
	if err != nil || len(chain) != 3 {
		t.Fatalf("fixed chain = %v, %v", chain, err)
	}
	for i := range chain {
		if chain[i].Addr != tb.addrs[i] || !bytes.Equal(chain[i].StaticPub, tb.keys[i].onion) {
			t.Fatalf("hop %d is %s, want the listed node %s", i, chain[i].Addr, tb.addrs[i])
		}
	}
	if got := tb.requests(); !slices.Equal(got, []int32{1, 0, 0, 0, 0}) {
		t.Fatalf("requests per node %v, want one at the first listed node", got)
	}
	if strings.Count(logged, "\n") != 5 {
		t.Fatalf("a fixed chain verifies every listed node as well, logged:\n%s", logged)
	}
}

func TestStreamThatEndsGivesNoChain(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)
	tb.publish(t, tb.bundles)
	chain, _, err := build(tb.selection(3, words()), tb.p)
	if err == nil || chain != nil {
		t.Fatalf("chain without an entry draw = %v, %v", chain, err)
	}
	if got := tb.requests(); !slices.Equal(got, make([]int32, 5)) {
		t.Fatalf("requests per node %v, want none before the entry is drawn", got)
	}
	chain, _, err = build(tb.selection(3, words(7, 6)), tb.p)
	if !errors.Is(err, io.EOF) || chain != nil {
		t.Fatalf("chain with the last draw missing = %v, %v, want io.EOF and no chain", chain, err)
	}
}

func TestFailureOfTheEntryDoesNotNameIt(t *testing.T) {
	tb := newTestbed(t, jcrypto.SuiteC25519, 5)

	_, logged, err := build(tb.selection(3, words(7, 6, 5)), tb.p)
	const unpublished = "the entry: no descriptors published, the node does not hold a valid descriptor of every roster node"
	if err == nil || err.Error() != unpublished || logged != "" {
		t.Fatalf("chain = %v with the log %q, want %q and no line", err, logged, unpublished)
	}

	delete(tb.routes, infoAddr(t, tb.addrs[2]))
	tb.web.CloseIdleConnections()
	_, logged, err = build(tb.selection(3, words(7, 6, 5)), tb.p)
	if err == nil || err.Error() != "the entry: connection failed" || logged != "" {
		t.Fatalf("chain = %v with the log %q, want the entry: connection failed", err, logged)
	}

	big := bytes.Repeat([]byte{' '}, fetch.MaxMirror+1)
	tb.info[1].mirror.Store(&big)
	_, _, err = build(tb.selection(3, words(6, 4, 3)), tb.p)
	if err == nil || err.Error() != "the entry: "+fetch.ErrTooLarge.Error() || namesAny(err.Error(), tb.addrs) {
		t.Fatalf("chain = %v, want the entry: %v", err, fetch.ErrTooLarge)
	}

	s := tb.selection(3, nil)
	s.fixed = true
	_, _, err = build(s, tb.p)
	if err == nil || !strings.HasPrefix(err.Error(), "node "+tb.addrs[0]+": ") {
		t.Fatalf("fixed chain = %v, want the first listed node named", err)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestFailureClassNamesNoAddress(t *testing.T) {
	entry := &net.TCPAddr{IP: net.IPv4(10, 96, 0, 7), Port: 9000}
	refused := &net.OpError{Op: "dial", Net: "tcp", Addr: entry, Err: errors.New("connect: connection refused")}
	timedOut := &net.OpError{Op: "read", Net: "tcp", Addr: entry, Err: timeoutError{}}
	lookup := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "relay-3.jimichi.svc.cluster.local", IsNotFound: true}}
	for _, c := range []struct {
		err  error
		want string
	}{
		{refused, "connection failed"},
		{lookup, "connection failed"},
		{timedOut, "timed out"},
		{fmt.Errorf("dial: %w", context.DeadlineExceeded), "timed out"},
		{fmt.Errorf("%w: %w", link.ErrHandshake, timedOut), link.ErrHandshake.Error()},
		{fmt.Errorf("%w: node %s", client.ErrNodeKey, "relay-3.jimichi.svc.cluster.local:9000"), client.ErrNodeKey.Error()},
		{fmt.Errorf("%w of %d bytes", fetch.ErrTooLarge, fetch.MaxMirror), fetch.ErrTooLarge.Error()},
		{&fetch.StatusError{Code: http.StatusNotFound}, "request answered status 404"},
		{pki.ErrFormat, pki.ErrFormat.Error()},
		{errors.New("write tcp 10.244.0.9:51234->10.96.0.7:9000: broken pipe"), "connection failed"},
	} {
		drawn := selection{}.cause(c.err)
		if drawn != c.want || strings.Contains(drawn, "10.") || strings.Contains(drawn, "relay-") {
			t.Errorf("cause of %q with a drawn chain is %q, want %q", c.err, drawn, c.want)
		}
		if fixed := (selection{fixed: true}).cause(c.err); fixed != c.err.Error() {
			t.Errorf("cause of %q with a fixed chain is %q, want the error itself", c.err, fixed)
		}
	}
}
