package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

const (
	testName = "relay-1"
	testAddr = "relay-1.jimichi.svc.cluster.local:9000"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	p     jcrypto.CryptoProvider
	n     *node
	clock *clock
	info  *httptest.Server
	admin *httptest.Server
	log   *bytes.Buffer
}

func newFixture(t *testing.T, s jcrypto.Suite) *fixture {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.NewIdentity(p, testName, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	_, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	id.SetKeys(pub, pub, 0)
	f := &fixture{p: p, clock: &clock{now: t0}, log: &bytes.Buffer{}}
	f.n = &node{id: id, ttl: time.Hour, now: f.clock.Now, logger: log.New(f.log, "", 0)}
	f.serve(t)
	return f
}

func (f *fixture) serve(t *testing.T) {
	t.Helper()
	f.info = httptest.NewServer(f.n.infoMux())
	t.Cleanup(f.info.Close)
	f.admin = httptest.NewServer(f.n.adminMux(func() relay.Counters { return relay.Counters{Accepted: 7} }))
	t.Cleanup(f.admin.Close)
}

func call(t *testing.T, method, url string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func nonce(t *testing.T) [pki.NonceSize]byte {
	t.Helper()
	var n [pki.NonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) enroll(t *testing.T, ca *pki.CA, notAfter time.Time) {
	t.Helper()
	n := nonce(t)
	code, body := call(t, http.MethodPost, f.admin.URL+"/csr", n[:])
	if code != http.StatusOK {
		t.Fatalf("POST /csr = %d %s", code, body)
	}
	req, err := pki.ParseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Check(f.p, n, testName, testAddr); err != nil {
		t.Fatalf("Check: %v", err)
	}
	cert, err := ca.Issue(req, f.clock.Now(), notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, http.MethodPut, f.admin.URL+"/cert", cert.Marshal()); code != http.StatusNoContent {
		t.Fatalf("PUT /cert = %d %s", code, body)
	}
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

func TestEnrollmentPublishesAVerifiableDescriptor(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			f := newFixture(t, s)
			if code, _ := call(t, http.MethodGet, f.info.URL+"/descriptor", nil); code != http.StatusServiceUnavailable {
				t.Fatalf("GET /descriptor before enrollment = %d, want 503", code)
			}
			if got := f.n.certState(); got != certNone {
				t.Fatalf("cert state before enrollment = %s", got)
			}

			ca := newCA(t, f.p)
			f.enroll(t, ca, t0.Add(72*time.Hour))
			code, bundle := call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
			if code != http.StatusOK {
				t.Fatalf("GET /descriptor after enrollment = %d %s", code, bundle)
			}
			pol := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			v, err := pki.Verify(f.p, pol, testAddr, bundle, f.clock.Now())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !v.DescUntil.Equal(t0.Add(time.Hour)) {
				t.Fatalf("descriptor until %v, want %v", v.DescUntil, t0.Add(time.Hour))
			}
			if got := f.n.certState(); got != certValid {
				t.Fatalf("cert state after enrollment = %s", got)
			}
			if !strings.Contains(f.log.String(), "certificate installed serial=") {
				t.Fatalf("no installation line in the log: %q", f.log.String())
			}
		})
	}
}

func TestTimerRefreshesTheDescriptor(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ca := newCA(t, f.p)
	f.enroll(t, ca, t0.Add(72*time.Hour))
	pol := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}

	f.clock.advance(50 * time.Minute)
	f.n.refresh()
	_, bundle := call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
	v, err := pki.Verify(f.p, pol, testAddr, bundle, f.clock.Now())
	if err != nil {
		t.Fatalf("Verify after refresh: %v", err)
	}
	if want := t0.Add(50*time.Minute + time.Hour); !v.DescUntil.Equal(want) {
		t.Fatalf("descriptor until %v, want %v", v.DescUntil, want)
	}
}

func TestRequestingTheDescriptorNeverSigns(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ca := newCA(t, f.p)
	f.enroll(t, ca, t0.Add(72*time.Hour))
	_, first := call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
	f.clock.advance(10 * time.Minute)
	_, second := call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
	if !bytes.Equal(first, second) {
		t.Fatal("a request changed the descriptor; only the timer may sign")
	}
}

func TestExpiredCertificateWithdrawsTheDescriptor(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ca := newCA(t, f.p)
	f.enroll(t, ca, t0.Add(90*time.Minute))

	f.clock.advance(90 * time.Minute)
	if code, _ := call(t, http.MethodGet, f.info.URL+"/descriptor", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor at not_after = %d, want 503", code)
	}
	if got := f.n.certState(); got != certExpired {
		t.Fatalf("cert state at not_after = %s", got)
	}
	f.n.refresh()
	if _, ok := f.n.id.Bundle(); ok {
		t.Fatal("the refresh after not_after kept the bundle")
	}
	if !strings.Contains(f.log.String(), pki.ErrCertTime.Error()) {
		t.Fatalf("no refresh failure in the log: %q", f.log.String())
	}
}

func TestRequestEndpoint(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	for _, c := range []struct {
		name   string
		method string
		body   []byte
		want   int
	}{
		{"short nonce", http.MethodPost, make([]byte, pki.NonceSize-1), http.StatusBadRequest},
		{"long nonce", http.MethodPost, make([]byte, pki.NonceSize+1), http.StatusBadRequest},
		{"empty body", http.MethodPost, nil, http.StatusBadRequest},
		{"body over the cap", http.MethodPost, make([]byte, maxAdminBody+1), http.StatusRequestEntityTooLarge},
		{"wrong method", http.MethodGet, nil, http.StatusMethodNotAllowed},
	} {
		if code, body := call(t, c.method, f.admin.URL+"/csr", c.body); code != c.want {
			t.Errorf("%s: /csr = %d %s, want %d", c.name, code, body, c.want)
		}
	}
	if code, _ := call(t, http.MethodPost, f.info.URL+"/csr", make([]byte, pki.NonceSize)); code != http.StatusNotFound {
		t.Errorf("the public listener answered /csr with %d", code)
	}
}

func TestCertificateEndpointRefusesAndSaysWhy(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ca := newCA(t, f.p)

	issueFor := func(name, addr string, notBefore, notAfter time.Time) []byte {
		t.Helper()
		other, err := pki.NewIdentity(f.p, name, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		n := nonce(t)
		raw, err := other.Request(n)
		if err != nil {
			t.Fatal(err)
		}
		req, err := pki.ParseRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ca.Issue(req, notBefore, notAfter)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Marshal()
	}
	own := func(notBefore, notAfter time.Time) []byte {
		t.Helper()
		n := nonce(t)
		_, raw := call(t, http.MethodPost, f.admin.URL+"/csr", n[:])
		req, err := pki.ParseRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ca.Issue(req, notBefore, notAfter)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Marshal()
	}

	for _, c := range []struct {
		name string
		cert []byte
		want error
	}{
		{"truncated", []byte{pki.Version}, pki.ErrFormat},
		{"unknown version", []byte("not a certificate"), pki.ErrVersion},
		{"another identity", issueFor(testName, testAddr, t0, t0.Add(time.Hour)), pki.ErrCertMismatch},
		{"expired", own(t0.Add(-2*time.Hour), t0.Add(-time.Hour)), pki.ErrCertTime},
		{"not yet valid", own(t0.Add(time.Hour), t0.Add(2*time.Hour)), pki.ErrCertTime},
	} {
		code, body := call(t, http.MethodPut, f.admin.URL+"/cert", c.cert)
		if code != http.StatusBadRequest || !strings.Contains(string(body), c.want.Error()) {
			t.Errorf("%s: PUT /cert = %d %q, want 400 with %q", c.name, code, body, c.want)
		}
	}
	if code, _ := call(t, http.MethodPut, f.admin.URL+"/cert", make([]byte, maxAdminBody+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("PUT /cert over the cap = %d", code)
	}
	if got := f.n.certState(); got != certNone {
		t.Fatalf("a refused certificate changed the state to %s", got)
	}
	if code, _ := call(t, http.MethodGet, f.info.URL+"/descriptor", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor after refused certificates = %d, want 503", code)
	}
}

func TestUnsignedNodeServesTheBaselineAndNoEnrollment(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := pki.Unsigned(p, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{p: p, n: &node{unsigned: unsigned, ttl: time.Hour, now: time.Now, logger: log.New(io.Discard, "", 0)}}
	f.serve(t)

	code, bundle := call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /descriptor = %d", code)
	}
	nodes, err := pki.Unverified(p, []string{testAddr}, [][]byte{bundle})
	if err != nil || !bytes.Equal(nodes[0].OnionPub, pub) {
		t.Fatalf("Unverified = %v, %v", nodes, err)
	}
	ca := newCA(t, p)
	if _, err := pki.Verify(p, pki.Policy{Anchor: ca.Anchor()}, testAddr, bundle, time.Now()); !errors.Is(err, pki.ErrFormat) {
		t.Fatalf("Verify of the unsigned bundle = %v, want %v", err, pki.ErrFormat)
	}
	for _, path := range []string{"/csr", "/cert"} {
		if code, _ := call(t, http.MethodPost, f.admin.URL+path, make([]byte, pki.NonceSize)); code != http.StatusNotFound {
			t.Errorf("%s without -auth = %d, want 404", path, code)
		}
	}
	if code, body := call(t, http.MethodGet, f.admin.URL+"/stats", nil); code != http.StatusOK || !strings.Contains(string(body), `"accepted":7`) {
		t.Fatalf("GET /stats = %d %s", code, body)
	}
}

func TestAuthFlags(t *testing.T) {
	for _, c := range []struct {
		name, stats, node, advertise string
		ttl                          time.Duration
		ok                           bool
	}{
		{"defaults of the manifests", "127.0.0.1:9101", testName, testAddr, time.Hour, true},
		{"ipv6 loopback", "[::1]:9101", testName, testAddr, time.Hour, true},
		{"any address", ":9101", testName, testAddr, time.Hour, false},
		{"unspecified address", "0.0.0.0:9101", testName, testAddr, time.Hour, false},
		{"pod address", "10.244.1.7:9101", testName, testAddr, time.Hour, false},
		{"name instead of an address", "localhost:9101", testName, testAddr, time.Hour, false},
		{"no port", "127.0.0.1", testName, testAddr, time.Hour, false},
		{"no name", "127.0.0.1:9101", "", testAddr, time.Hour, false},
		{"bad name", "127.0.0.1:9101", "Relay_1", testAddr, time.Hour, false},
		{"no advertised address", "127.0.0.1:9101", testName, "", time.Hour, false},
		{"advertised address over the field", "127.0.0.1:9101", testName, strings.Repeat("a", 60) + ":9000", time.Hour, false},
		{"advertised address without a port", "127.0.0.1:9101", testName, "relay-1", time.Hour, false},
		{"descriptor ttl too short", "127.0.0.1:9101", testName, testAddr, time.Second, false},
		{"descriptor ttl over a day", "127.0.0.1:9101", testName, testAddr, 25 * time.Hour, false},
	} {
		err := checkAuthFlags(c.stats, c.node, c.advertise, c.ttl)
		if (err == nil) != c.ok {
			t.Errorf("%s: checkAuthFlags = %v, want ok %v", c.name, err, c.ok)
		}
	}
}
