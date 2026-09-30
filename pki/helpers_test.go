package pki

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

var (
	t0    = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	until = t0.Add(72 * time.Hour)
)

func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			run(t, p)
		})
	}
}

func otherSuite(t testing.TB, p jcrypto.CryptoProvider) jcrypto.CryptoProvider {
	t.Helper()
	s := jcrypto.SuiteGOST
	if p.Suite() == jcrypto.SuiteGOST {
		s = jcrypto.SuiteC25519
	}
	q, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

type env struct {
	p   jcrypto.CryptoProvider
	ca  *CA
	pol Policy
}

func newEnv(t testing.TB, p jcrypto.CryptoProvider) *env {
	t.Helper()
	ca, err := NewCA(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	return &env{p: p, ca: ca, pol: Policy{Anchor: ca.Anchor(), Skew: Skew}}
}

type node struct {
	p     jcrypto.CryptoProvider
	id    *Identity
	name  string
	addr  string
	cert  *Cert
	raw   []byte
	onion []byte
}

func addrOf(name string) string { return name + ".jimichi.svc.cluster.local:9000" }

// a node taken through request, check, issue and install, with a certificate
// for [t0, until] and one key in both roles
func (e *env) node(t testing.TB, name string) *node {
	t.Helper()
	id, err := NewIdentity(e.p, name, addrOf(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	n := &node{p: e.p, id: id, name: name, addr: addrOf(name)}
	nonce := randomNonce(t)
	req, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Check(e.p, nonce, name, n.addr); err != nil {
		t.Fatal(err)
	}
	if n.cert, err = e.ca.Issue(r, t0, until); err != nil {
		t.Fatal(err)
	}
	n.raw = n.cert.Marshal()
	if err := id.Install(n.raw, t0); err != nil {
		t.Fatal(err)
	}
	n.onion = agreementKey(t, e.p)
	id.SetKeys(n.onion, n.onion, 0)
	return n
}

func (n *node) bundle(t testing.TB, now time.Time, ttl time.Duration) []byte {
	t.Helper()
	if err := n.id.Refresh(now, ttl); err != nil {
		t.Fatal(err)
	}
	b, ok := n.id.Bundle()
	if !ok {
		t.Fatal("no bundle after Refresh")
	}
	return b
}

func (n *node) sign(t testing.TB, domain string, body []byte) []byte {
	t.Helper()
	return signAs(t, n.id, domain, body)
}

func signAs(t testing.TB, id *Identity, domain string, body []byte) []byte {
	t.Helper()
	id.mu.Lock()
	defer id.mu.Unlock()
	sig, err := id.sign(domain, body)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// a request of this identity for any name and address, as a CA with no roster
// would accept it
func requestFor(t testing.TB, id *Identity, name, addr string) *Request {
	t.Helper()
	r := &Request{Suite: id.p.Suite(), Name: name, Addr: addr, Identity: id.pub}
	r.Sig = signAs(t, id, requestDomain, r.body())
	return r
}

func (n *node) descriptor(published, expires time.Time) *Descriptor {
	d := &Descriptor{
		Suite:     n.p.Suite(),
		Published: published.Unix(),
		Expires:   expires.Unix(),
		LinkPub:   n.onion,
		OnionPub:  n.onion,
	}
	copy(d.CertHash[:], n.p.Hash(n.raw))
	return d
}

func (n *node) pack(t testing.TB, d *Descriptor) []byte {
	t.Helper()
	d.Sig = n.sign(t, descriptorDomain, d.body())
	return pack(n.p, n.raw, d.Marshal())
}

func pack(p jcrypto.CryptoProvider, cert, desc []byte) []byte {
	return Bundle{V: Version, Suite: p.Suite().String(), Cert: cert, Descriptor: desc}.Marshal()
}

func agreementKey(t testing.TB, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
}

func randomNonce(t testing.TB) [NonceSize]byte {
	t.Helper()
	var n [NonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

func wantErr(t testing.TB, what string, got, want error) {
	t.Helper()
	if want == nil && got != nil || want != nil && !errors.Is(got, want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// one field of an encoding and the sentinel a flipped byte in it must give
type field struct {
	name string
	size int
	want error
}

// every byte in full mode; in short mode the first, middle and last byte of
// each field, since a GOST signature check costs milliseconds
func flipped(t *testing.T, raw []byte, layout []field, check func(b []byte) error) {
	t.Helper()
	total := 0
	for _, f := range layout {
		total += f.size
	}
	if total != len(raw) {
		t.Fatalf("layout covers %d of %d bytes", total, len(raw))
	}
	off := 0
	for _, f := range layout {
		positions := map[int]bool{0: true, f.size / 2: true, f.size - 1: true}
		if !testing.Short() {
			for i := range f.size {
				positions[i] = true
			}
		}
		for i := range positions {
			b := append([]byte(nil), raw...)
			b[off+i] ^= 0xff
			wantErr(t, fmt.Sprintf("byte %d of %s", i, f.name), check(b), f.want)
		}
		off += f.size
	}
}
