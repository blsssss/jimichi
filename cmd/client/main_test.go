package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
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

func TestFetchBundle(t *testing.T) {
	p := provider(t, jcrypto.SuiteC25519)
	_, good := enrolled(t, p, newCA(t, p), "relay-1", t0.Add(time.Hour))

	serve := func(t *testing.T, answer func(n int32, w http.ResponseWriter)) (string, *atomic.Int32) {
		t.Helper()
		var n atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/descriptor" {
				http.NotFound(w, r)
				return
			}
			answer(n.Add(1), w)
		}))
		t.Cleanup(srv.Close)
		return srv.URL + "/descriptor", &n
	}
	web := &http.Client{Timeout: time.Second}

	t.Run("published after enrollment", func(t *testing.T) {
		url, n := serve(t, func(n int32, w http.ResponseWriter) {
			if n < 3 {
				http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(good)
		})
		b, err := fetchBundle(web, url, 5, time.Millisecond)
		if err != nil || !bytes.Equal(b, good) || n.Load() != 3 {
			t.Fatalf("fetchBundle = %d bytes, %v after %d requests", len(b), err, n.Load())
		}
	})

	t.Run("never enrolled", func(t *testing.T) {
		url, n := serve(t, func(_ int32, w http.ResponseWriter) {
			http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
		})
		if _, err := fetchBundle(web, url, 4, time.Millisecond); err == nil || n.Load() != 4 {
			t.Fatalf("fetchBundle = %v after %d requests, want an error after 4", err, n.Load())
		}
	})

	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
	}{
		{"not found", func(w http.ResponseWriter) { http.Error(w, "gone", http.StatusNotFound) }},
		{"redirect", func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://elsewhere.invalid/descriptor")
			w.WriteHeader(http.StatusFound)
		}},
		{"over the size limit", func(w http.ResponseWriter) { _, _ = w.Write(bytes.Repeat([]byte("a"), maxBundle+1)) }},
		{"loose json", func(w http.ResponseWriter) { _, _ = w.Write(append(good, '\n')) }},
		{"not json", func(w http.ResponseWriter) { _, _ = w.Write([]byte("pub=abc")) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			url, n := serve(t, func(_ int32, w http.ResponseWriter) { c.answer(w) })
			noRedirect := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			if _, err := fetchBundle(noRedirect, url, 5, time.Millisecond); err == nil || n.Load() != 1 {
				t.Fatalf("fetchBundle = %v after %d requests, want one request and an error", err, n.Load())
			}
		})
	}

	t.Run("nobody listening", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL + "/descriptor"
		srv.Close()
		start := time.Now()
		if _, err := fetchBundle(web, url, 3, 20*time.Millisecond); err == nil {
			t.Fatal("fetchBundle from a closed port succeeded")
		}
		if time.Since(start) < 40*time.Millisecond {
			t.Fatal("a connection error was not retried")
		}
	})
}

func TestDescriptorURL(t *testing.T) {
	for _, c := range []struct{ addr, want string }{
		{"relay-1.jimichi.svc.cluster.local:9000", "http://relay-1.jimichi.svc.cluster.local:9100/descriptor"},
		{"[::1]:9000", "http://[::1]:9100/descriptor"},
	} {
		if got, err := descriptorURL(c.addr, "9100"); err != nil || got != c.want {
			t.Errorf("descriptorURL(%q) = %q, %v, want %q", c.addr, got, err, c.want)
		}
	}
	if _, err := descriptorURL("relay-1", "9100"); err == nil {
		t.Error("descriptorURL accepted an address without a port")
	}
}
