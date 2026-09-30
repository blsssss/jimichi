package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

func addrOf(name string) string { return name + ".jimichi.svc.cluster.local:9000" }

func host(url string) string { return strings.TrimPrefix(url, "http://") }

// a relay's admin and info listeners around a pki.Identity, with hooks for a
// relay that misbehaves
type fakeRelay struct {
	p        jcrypto.CryptoProvider
	name     string
	id       *pki.Identity
	pin      string
	admin    *httptest.Server
	info     *httptest.Server
	requests atomic.Int32
	puts     atomic.Int32
	installs atomic.Int32

	request    func(nonce [pki.NonceSize]byte) ([]byte, error)
	refuseCert bool
	// answers requests and certificates the way a relay with a valid
	// certificate does
	holdsCert bool
	// fails the certificate with 500 after taking it
	failAfterInstall bool
	// installs the first certificate, then drops the connection unanswered
	dropFirstPut bool
	descriptor   func() ([]byte, bool)
}

const installedText = "certificate already installed and valid: a new one needs a relay restart"

func newRelay(t *testing.T, p jcrypto.CryptoProvider, name, certName, certAddr string) *fakeRelay {
	t.Helper()
	id, err := pki.NewIdentity(p, certName, certAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	id.SetKeys(pub, pub, 0)
	r := &fakeRelay{p: p, name: name, id: id, pin: id.KeyHash(), request: id.Request, descriptor: id.Bundle}

	admin := http.NewServeMux()
	admin.HandleFunc("POST /csr", func(w http.ResponseWriter, req *http.Request) {
		r.requests.Add(1)
		if r.holdsCert {
			http.Error(w, installedText, http.StatusConflict)
			return
		}
		body, _ := io.ReadAll(req.Body)
		var nonce [pki.NonceSize]byte
		if len(body) != len(nonce) {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		copy(nonce[:], body)
		out, err := r.request(nonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(out)
	})
	admin.HandleFunc("PUT /cert", func(w http.ResponseWriter, req *http.Request) {
		n := r.puts.Add(1)
		raw, _ := io.ReadAll(req.Body)
		switch {
		case r.refuseCert:
			http.Error(w, pki.ErrRoster.Error(), http.StatusBadRequest)
			return
		case r.holdsCert:
			http.Error(w, installedText, http.StatusConflict)
			return
		}
		now := time.Now()
		if err := r.id.Install(raw, now); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := r.id.Refresh(now, time.Hour); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.installs.Add(1)
		switch {
		case r.failAfterInstall:
			http.Error(w, "signing failed", http.StatusInternalServerError)
		case r.dropFirstPut && n == 1:
			panic(http.ErrAbortHandler)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	info := http.NewServeMux()
	info.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, ok := r.descriptor()
		if !ok {
			http.Error(w, "no valid descriptor", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(b)
	})
	r.admin = httptest.NewServer(admin)
	t.Cleanup(r.admin.Close)
	r.info = httptest.NewServer(info)
	t.Cleanup(r.info.Close)
	return r
}

func honestRelay(t *testing.T, p jcrypto.CryptoProvider, name string) *fakeRelay {
	return newRelay(t, p, name, name, addrOf(name))
}

func (r *fakeRelay) entry() rosterEntry {
	return rosterEntry{name: r.name, addr: addrOf(r.name), admin: host(r.admin.URL), info: host(r.info.URL), identity: r.pin}
}

func (r *fakeRelay) roster() string {
	e := r.entry()
	return fmt.Sprintf("%s=%s,admin=%s,info=%s,identity=%s", e.name, e.addr, e.admin, e.info, e.identity)
}

func enrollArgs(s jcrypto.Suite, relays ...*fakeRelay) []string {
	args := []string{"-suite", s.String(), "-cert-ttl", "1h", "-timeout", "5s", "-keymem", "zero", "-harden=false"}
	for _, r := range relays {
		args = append(args, "-node", r.roster())
	}
	return args
}

// counts every CA key made from here on, so a test can show that a refusal
// never got as far as one
func countCAs(t *testing.T) *atomic.Int32 {
	t.Helper()
	var made atomic.Int32
	orig := newCA
	newCA = func(p jcrypto.CryptoProvider) (*pki.CA, error) {
		made.Add(1)
		return orig(p)
	}
	t.Cleanup(func() { newCA = orig })
	return &made
}

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// a relay that answers with a key it shares with another relay: every request
// is valid on its own, only the batch shows the key twice
func shareKey(t *testing.T, p jcrypto.CryptoProvider, relays ...*fakeRelay) {
	t.Helper()
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	for _, r := range relays {
		name := r.name
		r.pin = pki.KeyHash(p, pub)
		r.request = func(nonce [pki.NonceSize]byte) ([]byte, error) {
			req := &pki.Request{Suite: p.Suite(), Nonce: nonce, Name: name, Addr: addrOf(name), Identity: pub}
			// Marshal of an unsigned request is its body and the zero length of
			// the missing signature
			unsigned := req.Marshal()
			sig, err := p.Sign(priv, append([]byte("jimichi/csr/v1\x00"), unsigned[:len(unsigned)-1]...))
			if err != nil {
				return nil, err
			}
			req.Sig = sig
			return req.Marshal(), nil
		}
	}
}

func TestEnrollCertifiesEveryRelay(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p := provider(t, s)
			relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), honestRelay(t, p, "relay-3")}
			var stdout, stderr bytes.Buffer
			if err := runEnroll(enrollArgs(s, relays...), &stdout, &stderr); err != nil {
				t.Fatalf("enroll: %v\n%s", err, stderr.String())
			}
			anchor, err := pki.ParseAnchor(strings.TrimSuffix(stdout.String(), "\n"))
			if err != nil || anchor.Suite != s {
				t.Fatalf("stdout %q is not an anchor of %v: %v", stdout.String(), s, err)
			}
			var addrs []string
			var bundles [][]byte
			for _, r := range relays {
				b, ok := r.id.Bundle()
				if !ok {
					t.Fatalf("%s serves no descriptor", r.name)
				}
				addrs = append(addrs, addrOf(r.name))
				bundles = append(bundles, b)
			}
			nodes, err := pki.VerifyChain(p, pki.Policy{Anchor: anchor, Skew: pki.Skew}, addrs, bundles, time.Now())
			if err != nil {
				t.Fatalf("a client would refuse the chain: %v", err)
			}
			if until := time.Until(nodes[0].CertUntil); until <= 0 || until > time.Hour {
				t.Fatalf("certificate valid for %v, want -cert-ttl 1h", until)
			}
			log := stderr.String()
			if !strings.Contains(log, "WARNING: the CA key is held without locked memory and process hardening") {
				t.Errorf("no warning about the unprotected CA key in %q", log)
			}
			if strings.Contains(log, "discarded CA") {
				t.Errorf("a successful run warned about a discarded CA: %q", log)
			}
			for _, r := range relays {
				if !strings.Contains(log, "enrolled "+r.name+" identity="+r.id.Fingerprint()) {
					t.Errorf("no line for %s in %q", r.name, log)
				}
			}
		})
	}
}

func TestEnrollIsAllOrNothing(t *testing.T) {
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	three := func(t *testing.T) []*fakeRelay {
		return []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), honestRelay(t, p, "relay-3")}
	}

	made := countCAs(t)
	for _, c := range []struct {
		name string
		// relays 1 to 3, one of them bent by the setup
		setup func(t *testing.T) []*fakeRelay
		want  error
		// the notice about relays left with a certificate of the discarded CA
		installed string
	}{
		{"relay certified under another name", func(t *testing.T) []*fakeRelay {
			return []*fakeRelay{honestRelay(t, p, "relay-1"), newRelay(t, p, "relay-2", "relay-9", addrOf("relay-2")), honestRelay(t, p, "relay-3")}
		}, pki.ErrRoster, ""},
		{"relay certified for another address", func(t *testing.T) []*fakeRelay {
			return []*fakeRelay{honestRelay(t, p, "relay-1"), newRelay(t, p, "relay-2", "relay-2", "relay-2.elsewhere:9000"), honestRelay(t, p, "relay-3")}
		}, pki.ErrRoster, ""},
		{"request replayed from an earlier nonce", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			old, err := relays[1].id.Request([pki.NonceSize]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			relays[1].request = func([pki.NonceSize]byte) ([]byte, error) { return old, nil }
			return relays
		}, pki.ErrNonce, ""},
		{"request with a broken signature", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[2].request = func(nonce [pki.NonceSize]byte) ([]byte, error) {
				out, err := relays[2].id.Request(nonce)
				out[len(out)-1] ^= 1
				return out, err
			}
			return relays
		}, pki.ErrRequestSignature, ""},
		{"well-formed request under a foreign identity", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			foreign, err := pki.NewIdentity(p, "relay-2", addrOf("relay-2"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(foreign.Close)
			relays[1].request = foreign.Request
			return relays
		}, errIdentityPin, ""},
		{"relay already holding a valid certificate", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[1].holdsCert = true
			return relays
		}, nil, ""},
		{"relay refuses its certificate", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[2].refuseCert = true
			return relays
		}, nil, "relays relay-1, relay-2 now hold"},
		{"relay fails after taking its certificate", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[2].failAfterInstall = true
			return relays
		}, nil, "relays relay-1, relay-2 now hold and relay-3 may hold"},
		{"relay serves another relay's descriptor", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[2].descriptor = relays[1].id.Bundle
			return relays
		}, pki.ErrWrongAddr, "relays relay-1, relay-2, relay-3 now hold"},
		{"relay serves no descriptor", func(t *testing.T) []*fakeRelay {
			relays := three(t)
			relays[1].descriptor = func() ([]byte, bool) { return nil, false }
			return relays
		}, nil, "relays relay-1, relay-2, relay-3 now hold"},
	} {
		t.Run(c.name, func(t *testing.T) {
			made.Store(0)
			relays := c.setup(t)
			var stdout, stderr bytes.Buffer
			err := runEnroll(enrollArgs(s, relays...), &stdout, &stderr)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("enroll = %v, want %v", err, c.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed enrollment printed %q", stdout.String())
			}
			log := stderr.String()
			if c.installed != "" {
				if !strings.Contains(log, c.installed+" certificates of a discarded CA") || !strings.Contains(log, "rollout restart deployment/relay-1") {
					t.Fatalf("no notice %q with a restart hint in %q", c.installed, log)
				}
				return
			}
			if strings.Contains(log, "discarded CA") {
				t.Fatalf("notice about a discarded CA although nothing was installed: %q", log)
			}
			if n := made.Load(); n != 0 {
				t.Fatalf("a refused enrollment made %d CA keys", n)
			}
			for _, r := range relays {
				if n := r.puts.Load(); n != 0 {
					t.Fatalf("%s was sent a certificate although the batch failed", r.name)
				}
			}
		})
	}
}

// the roster refuses two equal pins, so this reaches the check in run only
// through a roster built by hand
func TestDuplicateIdentityIsRefusedBeforeIssuing(t *testing.T) {
	made := countCAs(t)
	p := provider(t, jcrypto.SuiteC25519)
	relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")}
	shareKey(t, p, relays...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := &enrollment{p: p, nodes: roster{relays[0].entry(), relays[1].entry()}, certTTL: time.Hour, web: newWebClient(), now: time.Now, log: io.Discard}
	if _, err := e.run(ctx); !errors.Is(err, pki.ErrDuplicate) {
		t.Fatalf("run = %v, want %v", err, pki.ErrDuplicate)
	}
	if relays[0].puts.Load()+relays[1].puts.Load() != 0 || made.Load() != 0 {
		t.Fatal("a repeated identity got as far as a CA key")
	}
}

func TestHoldingRelayGetsARestartHint(t *testing.T) {
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")}
	relays[1].holdsCert = true
	var stdout, stderr bytes.Buffer
	if err := runEnroll(append(enrollArgs(s, relays...), "-namespace", "lab"), &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatalf("enroll = %v, stdout %q", err, stdout.String())
	}
	want := "relay relay-2 already holds a valid certificate; re-enrollment needs a fresh identity: kubectl -n lab rollout restart deployment/relay-2"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("no restart hint in %q", stderr.String())
	}
}

func TestRetryAfterALostAnswerSucceeds(t *testing.T) {
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")}
	relays[1].dropFirstPut = true
	var stdout, stderr bytes.Buffer
	if err := runEnroll(enrollArgs(s, relays...), &stdout, &stderr); err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr.String())
	}
	if n := relays[1].puts.Load(); n != 2 {
		t.Fatalf("relay-2 got %d certificate uploads, want the lost one and its retry", n)
	}
	if _, err := pki.ParseAnchor(strings.TrimSpace(stdout.String())); err != nil {
		t.Fatalf("stdout %q: %v", stdout.String(), err)
	}
}

func TestEnrollGivesUpOnAnUnreachableRelay(t *testing.T) {
	made := countCAs(t)
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")}
	relays[1].admin.Close()
	args := enrollArgs(s, relays...)
	args[5] = "700ms"
	var stdout, stderr bytes.Buffer
	start := time.Now()
	err := runEnroll(args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "relay-2") || stdout.Len() != 0 {
		t.Fatalf("enroll = %v, stdout %q", err, stdout.String())
	}
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Fatalf("gave up after %v, a refused connection should be retried until the deadline", d)
	}
	if relays[0].puts.Load() != 0 || made.Load() != 0 {
		t.Fatal("an unreachable relay did not stop the run before any CA key")
	}
}

func TestRosterIsCheckedBeforeAnyRequest(t *testing.T) {
	made := countCAs(t)
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	r1, r2 := honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")
	a1, i1, a2, i2 := host(r1.admin.URL), host(r1.info.URL), host(r2.admin.URL), host(r2.info.URL)
	h1, h2 := r1.pin, r2.pin
	entry := func(name, addr, admin, info, identity string) string {
		return fmt.Sprintf("%s=%s,admin=%s,info=%s,identity=%s", name, addr, admin, info, identity)
	}
	good := entry("relay-1", addrOf("relay-1"), a1, i1, h1)

	for _, c := range []struct {
		name  string
		nodes []string
	}{
		{"no nodes", nil},
		{"no address", []string{"relay-1,admin=" + a1 + ",info=" + i1 + ",identity=" + h1}},
		{"no admin endpoint", []string{"relay-1=" + addrOf("relay-1") + ",info=" + i1 + ",identity=" + h1}},
		{"no info endpoint", []string{"relay-1=" + addrOf("relay-1") + ",admin=" + a1 + ",identity=" + h1}},
		{"no identity", []string{"relay-1=" + addrOf("relay-1") + ",admin=" + a1 + ",info=" + i1}},
		{"short identity", []string{entry("relay-1", addrOf("relay-1"), a1, i1, h1[:62])}},
		{"identity in upper case", []string{entry("relay-1", addrOf("relay-1"), a1, i1, strings.ToUpper(h1))}},
		{"identity not hex", []string{entry("relay-1", addrOf("relay-1"), a1, i1, "g"+h1[1:])}},
		{"unknown part", []string{good + ",debug=1"}},
		{"repeated part", []string{good + ",admin=" + a2}},
		{"bad name", []string{entry("Relay_1", addrOf("relay-1"), a1, i1, h1)}},
		{"address without a port", []string{entry("relay-1", "relay-1", a1, i1, h1)}},
		{"address over the field", []string{entry("relay-1", strings.Repeat("a", 60)+":9000", a1, i1, h1)}},
		{"endpoint without a port", []string{entry("relay-1", addrOf("relay-1"), "127.0.0.1", i1, h1)}},
		{"repeated name", []string{good, entry("relay-1", addrOf("relay-2"), a2, i2, h2)}},
		{"repeated address", []string{good, entry("relay-2", addrOf("relay-1"), a2, i2, h2)}},
		{"repeated endpoint", []string{good, entry("relay-2", addrOf("relay-2"), a2, i1, h2)}},
		{"repeated identity", []string{good, entry("relay-2", addrOf("relay-2"), a2, i2, h1)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"-suite", s.String(), "-keymem", "zero", "-harden=false"}
			for _, n := range c.nodes {
				args = append(args, "-node", n)
			}
			var stdout bytes.Buffer
			if err := runEnroll(args, &stdout, io.Discard); err == nil || stdout.Len() != 0 {
				t.Fatalf("enroll = %v, stdout %q", err, stdout.String())
			}
			if r1.requests.Load()+r2.requests.Load() != 0 || made.Load() != 0 {
				t.Fatal("a relay was asked for a request before the roster was checked")
			}
		})
	}
}

func TestKeygenCA(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"keygen-ca", "-suite", s.String()}, &stdout, &stderr); code != 0 {
			t.Fatalf("keygen-ca exit %d: %s", code, stderr.String())
		}
		line := strings.TrimSuffix(stdout.String(), "\n")
		a, err := pki.ParseAnchor(line)
		if err != nil || a.Suite != s {
			t.Fatalf("keygen-ca printed %q: %v", line, err)
		}
		if seen[line] {
			t.Fatal("two runs printed the same anchor")
		}
		seen[line] = true
	}
}

func TestCommandLine(t *testing.T) {
	node := "relay-1=" + addrOf("relay-1") + ",admin=127.0.0.1:1,info=127.0.0.1:2,identity=" + strings.Repeat("ab", pki.HashSize)
	for _, c := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"issue"}, 2},
		{[]string{"help"}, 0},
		{[]string{"keygen-ca", "-suite", "rsa"}, 1},
		{[]string{"keygen-ca", "extra"}, 1},
		{[]string{"enroll", "-h"}, 0},
		{[]string{"enroll", "-cert-ttl", "1s", "-node", node}, 1},
		{[]string{"enroll", "-timeout", "61s", "-node", node}, 1},
		{[]string{"enroll", "-timeout", "0s", "-node", node}, 1},
	} {
		if code := run(c.args, io.Discard, io.Discard); code != c.code {
			t.Errorf("jimichi %v: exit %d, want %d", c.args, code, c.code)
		}
	}
}
