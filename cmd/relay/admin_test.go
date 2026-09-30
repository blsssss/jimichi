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

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	p     jcrypto.CryptoProvider
	n     *node
	ca    *pki.CA
	clock *clock
	info  *httptest.Server
	admin *httptest.Server
	log   *logBuffer
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
	f := &fixture{p: p, ca: newCA(t, p), clock: &clock{now: t0}, log: &logBuffer{}}
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

func newCA(t *testing.T, p jcrypto.CryptoProvider) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	return ca
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

// POST /csr, checked the way jimichi enroll checks it
func (f *fixture) request(t *testing.T) *pki.Request {
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
	return req
}

func (f *fixture) issue(t *testing.T, req *pki.Request, notBefore, notAfter time.Time) []byte {
	t.Helper()
	cert, err := f.ca.Issue(req, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Marshal()
}

func (f *fixture) put(t *testing.T, cert []byte) (int, string) {
	t.Helper()
	code, body := call(t, http.MethodPut, f.admin.URL+"/cert", cert)
	return code, string(body)
}

func (f *fixture) enroll(t *testing.T, notAfter time.Time) {
	t.Helper()
	cert := f.issue(t, f.request(t), f.clock.Now(), notAfter)
	if code, body := f.put(t, cert); code != http.StatusNoContent {
		t.Fatalf("PUT /cert = %d %s", code, body)
	}
}

func (f *fixture) descriptor(t *testing.T) (int, []byte) {
	t.Helper()
	return call(t, http.MethodGet, f.info.URL+"/descriptor", nil)
}

func (f *fixture) verify(t *testing.T) *pki.Verified {
	t.Helper()
	code, bundle := f.descriptor(t)
	if code != http.StatusOK {
		t.Fatalf("GET /descriptor = %d %s", code, bundle)
	}
	v, err := pki.Verify(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, testAddr, bundle, f.clock.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return v
}

func (f *fixture) stats(t *testing.T) string {
	t.Helper()
	code, body := call(t, http.MethodGet, f.admin.URL+"/stats", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /stats = %d", code)
	}
	return string(body)
}

func TestEnrollmentPublishesAVerifiableDescriptor(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			f := newFixture(t, s)
			if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
				t.Fatalf("GET /descriptor before enrollment = %d, want 503", code)
			}
			if got := f.stats(t); !strings.Contains(got, `"cert":"none"`) {
				t.Fatalf("stats before enrollment: %s", got)
			}

			f.enroll(t, t0.Add(72*time.Hour))
			if v := f.verify(t); !v.DescUntil.Equal(t0.Add(time.Hour)) {
				t.Fatalf("descriptor until %v, want %v", v.DescUntil, t0.Add(time.Hour))
			}
			if got := f.stats(t); !strings.Contains(got, `"cert":"valid"`) || !strings.Contains(got, `"accepted":7`) {
				t.Fatalf("stats after enrollment: %s", got)
			}
			if !strings.Contains(f.log.String(), "certificate installed serial=") {
				t.Fatalf("no installation line in the log: %q", f.log.String())
			}
		})
	}
}

func TestInstallNeedsAFreshRequestAndKeepsTheServedBundle(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)

	req := f.request(t)
	early := f.issue(t, req, t0, t0.Add(72*time.Hour))
	f.clock.advance(installWindow + time.Second)
	if code, body := f.put(t, early); code != http.StatusConflict {
		t.Fatalf("PUT /cert after the window = %d %s, want 409", code, body)
	}
	if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
		t.Fatal("a refused installation published a descriptor")
	}

	f.enroll(t, f.clock.Now().Add(72*time.Hour))
	_, first := f.descriptor(t)
	served := func(when string) {
		t.Helper()
		if code, b := f.descriptor(t); code != http.StatusOK || !bytes.Equal(b, first) {
			t.Fatalf("%s: GET /descriptor = %d, the previous bundle should stay in service", when, code)
		}
		if got := f.stats(t); !strings.Contains(got, `"cert":"valid"`) {
			t.Fatalf("%s: stats %s", when, got)
		}
	}

	req = f.request(t)
	again := f.issue(t, req, f.clock.Now(), f.clock.Now().Add(72*time.Hour))
	if code, body := f.put(t, again); code != http.StatusNoContent {
		t.Fatalf("PUT /cert within the window = %d %s", code, body)
	}
	_, first = f.descriptor(t)
	if code, body := f.put(t, again); code != http.StatusConflict || !strings.Contains(body, "no open certificate request") {
		t.Fatalf("second PUT /cert for one request = %d %s, want 409", code, body)
	}
	served("second installation for one request")

	stale := f.issue(t, f.request(t), f.clock.Now().Add(-pki.Skew-time.Minute), f.clock.Now().Add(time.Hour))
	if code, body := f.put(t, stale); code != http.StatusConflict || !strings.Contains(body, errStaleCert.Error()) {
		t.Fatalf("PUT /cert issued before the request = %d %s, want 409", code, body)
	}
	served("certificate older than the request")

	other, err := pki.NewIdentity(f.p, testName, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	raw, err := other.Request(nonce(t))
	if err != nil {
		t.Fatal(err)
	}
	foreignReq, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.request(t)
	foreign := f.issue(t, foreignReq, f.clock.Now(), f.clock.Now().Add(time.Hour))
	if code, body := f.put(t, foreign); code != http.StatusBadRequest || !strings.Contains(body, pki.ErrCertMismatch.Error()) {
		t.Fatalf("PUT /cert of another identity = %d %s, want 400", code, body)
	}
	served("certificate of another identity")

	f.clock.advance(time.Second)
	replacement := f.issue(t, f.request(t), f.clock.Now(), f.clock.Now().Add(24*time.Hour))
	if code, body := f.put(t, replacement); code != http.StatusNoContent {
		t.Fatalf("PUT /cert after refusals = %d %s", code, body)
	}
	if v := f.verify(t); !v.CertUntil.Equal(f.clock.Now().Add(24 * time.Hour)) {
		t.Fatalf("serving a certificate until %v, want the replacement", v.CertUntil)
	}
}

func TestCertificateEndpointRefusesAndSaysWhy(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	for _, c := range []struct {
		name string
		cert func() []byte
		want error
	}{
		{"truncated", func() []byte { return []byte{pki.Version} }, pki.ErrFormat},
		{"unknown version", func() []byte { return []byte("not a certificate") }, pki.ErrVersion},
		{"expired", func() []byte { return f.issue(t, f.request(t), t0.Add(-pki.Skew), t0) }, pki.ErrCertTime},
		{"not yet valid", func() []byte { return f.issue(t, f.request(t), t0.Add(time.Hour), t0.Add(2*time.Hour)) }, pki.ErrCertTime},
	} {
		code, body := f.put(t, c.cert())
		if code != http.StatusBadRequest || !strings.Contains(body, c.want.Error()) {
			t.Errorf("%s: PUT /cert = %d %q, want 400 with %q", c.name, code, body, c.want)
		}
	}
	if code, _ := f.put(t, make([]byte, maxAdminBody+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("PUT /cert over the cap = %d", code)
	}
	if got := f.n.certState(); got != certNone {
		t.Fatalf("a refused certificate changed the state to %s", got)
	}
	if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor after refused certificates = %d, want 503", code)
	}
}

func TestDescriptorExpiresWithoutARefresh(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	f.enroll(t, t0.Add(72*time.Hour))

	f.clock.advance(time.Hour)
	if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor past its expiry = %d, want 503", code)
	}
	if got := f.n.certState(); got != certValid {
		t.Fatalf("cert state with an expired descriptor = %s, the certificate is still valid", got)
	}
	f.n.refreshIfDue()
	if v := f.verify(t); !v.DescUntil.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("descriptor until %v after the late refresh", v.DescUntil)
	}
}

func TestTimerResignsAtHalfLife(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	f.enroll(t, t0.Add(72*time.Hour))
	_, first := f.descriptor(t)

	f.clock.advance(29 * time.Minute)
	f.n.refreshIfDue()
	if _, b := f.descriptor(t); !bytes.Equal(b, first) {
		t.Fatal("re-signed before half of the lifetime")
	}
	f.clock.advance(time.Minute)
	f.n.refreshIfDue()
	if v := f.verify(t); !v.DescUntil.Equal(t0.Add(30*time.Minute + time.Hour)) {
		t.Fatalf("descriptor until %v, want a re-signing at half of the lifetime", v.DescUntil)
	}
}

func TestRequestingTheDescriptorNeverSigns(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	f.enroll(t, t0.Add(72*time.Hour))
	_, first := f.descriptor(t)
	f.clock.advance(50 * time.Minute)
	_, second := f.descriptor(t)
	if !bytes.Equal(first, second) {
		t.Fatal("a request changed the descriptor; only the timer may sign")
	}
}

func TestExpiredCertificateWithdrawsTheDescriptor(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	f.enroll(t, t0.Add(90*time.Minute))

	f.clock.advance(50 * time.Minute)
	f.n.refreshIfDue()
	if v := f.verify(t); !v.DescUntil.Equal(t0.Add(90 * time.Minute)) {
		t.Fatalf("descriptor until %v, want the certificate's not_after", v.DescUntil)
	}
	f.clock.advance(40 * time.Minute)
	if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor at not_after = %d, want 503", code)
	}
	if got := f.stats(t); !strings.Contains(got, `"cert":"expired"`) {
		t.Fatalf("stats at not_after: %s", got)
	}
	f.n.refreshIfDue()
	f.clock.advance(time.Minute)
	f.n.refreshIfDue()
	if _, ok := f.n.id.Bundle(); ok {
		t.Fatal("the refresh after not_after kept the bundle")
	}
	if n := strings.Count(f.log.String(), pki.ErrCertTime.Error()); n != 1 {
		t.Fatalf("the expiry was logged %d times, want once: %q", n, f.log.String())
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
	raw, err := f.n.id.Request(nonce(t))
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := f.put(t, f.issue(t, req, t0, t0.Add(time.Hour))); code != http.StatusConflict {
		t.Errorf("PUT /cert after refused requests only = %d %s, want 409", code, body)
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

	code, bundle := f.descriptor(t)
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
	if got := f.stats(t); !strings.Contains(got, `"accepted":7`) || !strings.Contains(got, `"cert":"none"`) {
		t.Fatalf("GET /stats = %s", got)
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
