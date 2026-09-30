package main

import (
	"bytes"
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

// a relay's admin and info listeners around a pki.Identity, with hooks for a
// relay that misbehaves
type fakeRelay struct {
	p        jcrypto.CryptoProvider
	name     string
	id       *pki.Identity
	admin    *httptest.Server
	info     *httptest.Server
	requests atomic.Int32
	installs atomic.Int32

	request    func(nonce [pki.NonceSize]byte) ([]byte, error)
	refuseCert bool
	descriptor func() ([]byte, bool)
}

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
	r := &fakeRelay{p: p, name: name, id: id, request: id.Request, descriptor: id.Bundle}

	admin := http.NewServeMux()
	admin.HandleFunc("POST /csr", func(w http.ResponseWriter, req *http.Request) {
		r.requests.Add(1)
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
		raw, _ := io.ReadAll(req.Body)
		if r.refuseCert {
			http.Error(w, pki.ErrRoster.Error(), http.StatusBadRequest)
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
		w.WriteHeader(http.StatusNoContent)
	})
	info := http.NewServeMux()
	info.HandleFunc("GET /descriptor", func(w http.ResponseWriter, _ *http.Request) {
		b, ok := r.descriptor()
		if !ok {
			http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
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

func (r *fakeRelay) roster() string {
	host := func(url string) string { return strings.TrimPrefix(url, "http://") }
	return fmt.Sprintf("%s=%s,admin=%s,info=%s", r.name, addrOf(r.name), host(r.admin.URL), host(r.info.URL))
}

func enrollArgs(s jcrypto.Suite, relays ...*fakeRelay) []string {
	args := []string{"-suite", s.String(), "-cert-ttl", "1h", "-timeout", "5s", "-keymem", "zero", "-harden=false"}
	for _, r := range relays {
		args = append(args, "-node", r.roster())
	}
	return args
}

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
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

	shared := func(t *testing.T, relays ...*fakeRelay) {
		priv, pub, err := p.GenerateSigning()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(priv.Release)
		for _, r := range relays {
			name := r.name
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

	for _, c := range []struct {
		name string
		// relays 1 to 3, the second or third one bent by the setup
		setup func(t *testing.T) []*fakeRelay
		want  error
		// whether any relay may have been given a certificate before the failure
		issued bool
	}{
		{"relay certified under another name", func(t *testing.T) []*fakeRelay {
			return []*fakeRelay{honestRelay(t, p, "relay-1"), newRelay(t, p, "relay-2", "relay-9", addrOf("relay-2")), honestRelay(t, p, "relay-3")}
		}, pki.ErrRoster, false},
		{"relay certified for another address", func(t *testing.T) []*fakeRelay {
			return []*fakeRelay{honestRelay(t, p, "relay-1"), newRelay(t, p, "relay-2", "relay-2", "relay-2.elsewhere:9000"), honestRelay(t, p, "relay-3")}
		}, pki.ErrRoster, false},
		{"request replayed from an earlier nonce", func(t *testing.T) []*fakeRelay {
			r := honestRelay(t, p, "relay-2")
			old, err := r.id.Request([pki.NonceSize]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			r.request = func([pki.NonceSize]byte) ([]byte, error) { return old, nil }
			return []*fakeRelay{honestRelay(t, p, "relay-1"), r, honestRelay(t, p, "relay-3")}
		}, pki.ErrNonce, false},
		{"request with a broken signature", func(t *testing.T) []*fakeRelay {
			r := honestRelay(t, p, "relay-3")
			r.request = func(nonce [pki.NonceSize]byte) ([]byte, error) {
				out, err := r.id.Request(nonce)
				out[len(out)-1] ^= 1
				return out, err
			}
			return []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), r}
		}, pki.ErrRequestSignature, false},
		{"two relays with one identity", func(t *testing.T) []*fakeRelay {
			relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), honestRelay(t, p, "relay-3")}
			shared(t, relays[0], relays[2])
			return relays
		}, pki.ErrDuplicate, false},
		{"relay refuses its certificate", func(t *testing.T) []*fakeRelay {
			r := honestRelay(t, p, "relay-3")
			r.refuseCert = true
			return []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), r}
		}, nil, true},
		{"relay serves another relay's descriptor", func(t *testing.T) []*fakeRelay {
			relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), honestRelay(t, p, "relay-3")}
			relays[2].descriptor = relays[1].id.Bundle
			return relays
		}, pki.ErrWrongAddr, true},
		{"relay serves no descriptor", func(t *testing.T) []*fakeRelay {
			relays := []*fakeRelay{honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2"), honestRelay(t, p, "relay-3")}
			relays[1].descriptor = func() ([]byte, bool) { return nil, false }
			return relays
		}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			relays := c.setup(t)
			var stdout, stderr bytes.Buffer
			err := runEnroll(enrollArgs(s, relays...), &stdout, &stderr)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("enroll = %v, want %v", err, c.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed enrollment printed %q", stdout.String())
			}
			if c.issued {
				return
			}
			for _, r := range relays {
				if n := r.installs.Load(); n != 0 {
					t.Fatalf("%s got a certificate although the batch failed", r.name)
				}
			}
		})
	}
}

func TestEnrollGivesUpOnAnUnreachableRelay(t *testing.T) {
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
	if relays[0].installs.Load() != 0 {
		t.Fatal("relay-1 got a certificate although relay-2 never answered")
	}
}

func TestRosterIsCheckedBeforeAnyRequest(t *testing.T) {
	s := jcrypto.SuiteC25519
	p := provider(t, s)
	r1, r2 := honestRelay(t, p, "relay-1"), honestRelay(t, p, "relay-2")
	host := func(url string) string { return strings.TrimPrefix(url, "http://") }
	a1, i1, a2, i2 := host(r1.admin.URL), host(r1.info.URL), host(r2.admin.URL), host(r2.info.URL)
	entry := func(name, addr, admin, info string) string {
		return fmt.Sprintf("%s=%s,admin=%s,info=%s", name, addr, admin, info)
	}
	good := entry("relay-1", addrOf("relay-1"), a1, i1)

	for _, c := range []struct {
		name  string
		nodes []string
	}{
		{"no nodes", nil},
		{"no address", []string{"relay-1,admin=" + a1 + ",info=" + i1}},
		{"no admin endpoint", []string{"relay-1=" + addrOf("relay-1") + ",info=" + i1}},
		{"no info endpoint", []string{"relay-1=" + addrOf("relay-1") + ",admin=" + a1}},
		{"unknown part", []string{good + ",debug=1"}},
		{"repeated part", []string{good + ",admin=" + a2}},
		{"bad name", []string{entry("Relay_1", addrOf("relay-1"), a1, i1)}},
		{"address without a port", []string{entry("relay-1", "relay-1", a1, i1)}},
		{"address over the field", []string{entry("relay-1", strings.Repeat("a", 60)+":9000", a1, i1)}},
		{"endpoint without a port", []string{entry("relay-1", addrOf("relay-1"), "127.0.0.1", i1)}},
		{"repeated name", []string{good, entry("relay-1", addrOf("relay-2"), a2, i2)}},
		{"repeated address", []string{good, entry("relay-2", addrOf("relay-1"), a2, i2)}},
		{"repeated endpoint", []string{good, entry("relay-2", addrOf("relay-2"), a2, i1)}},
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
			if r1.requests.Load()+r2.requests.Load() != 0 {
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
		{[]string{"enroll", "-cert-ttl", "1s", "-node", "relay-1=" + addrOf("relay-1") + ",admin=127.0.0.1:1,info=127.0.0.1:2"}, 1},
	} {
		if code := run(c.args, io.Discard, io.Discard); code != c.code {
			t.Errorf("jimichi %v: exit %d, want %d", c.args, code, c.code)
		}
	}
}
