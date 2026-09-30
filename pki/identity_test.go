package pki

import (
	"errors"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestRequestCheck(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		nonce := randomNonce(t)
		raw, err := n.id.Request(nonce)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		other := nonce
		other[NonceSize-1] ^= 1

		wantErr(t, "genuine request", r.Check(p, nonce, n.name, n.addr), nil)
		wantErr(t, "another nonce", r.Check(p, other, n.name, n.addr), ErrNonce)
		wantErr(t, "another name", r.Check(p, nonce, "relay-2", n.addr), ErrRoster)
		wantErr(t, "another address", r.Check(p, nonce, n.name, addrOf("relay-2")), ErrRoster)
		wantErr(t, "another suite", r.Check(otherSuite(t, p), nonce, n.name, n.addr), ErrSuite)

		stranger, err := NewIdentity(p, "relay-2", addrOf("relay-2"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(stranger.Close)
		forged := *r
		forged.Sig = signAs(t, stranger, requestDomain, r.body())
		wantErr(t, "proof made by another key", forged.Check(p, nonce, n.name, n.addr), ErrRequestSignature)
		_, err = e.ca.Issue(&forged, t0, until)
		wantErr(t, "issue on a proof made by another key", err, ErrRequestSignature)

		flipped(t, raw, []field{
			{"version", 1, ErrVersion},
			{"suite", 1, ErrSuite},
			{"nonce", NonceSize, ErrNonce},
			{"name length", 1, ErrFormat},
			{"name", len(r.Name), ErrFormat},
			{"address length", 1, ErrFormat},
			{"address", len(r.Addr), ErrFormat},
			{"identity length", 1, ErrFormat},
			{"identity", len(r.Identity), ErrRequestSignature},
			{"signature length", 1, ErrFormat},
			{"signature", len(r.Sig), ErrRequestSignature},
		}, func(b []byte) error {
			r, err := ParseRequest(b)
			if err != nil {
				return err
			}
			return r.Check(p, nonce, n.name, n.addr)
		})
	})
}

func TestIssue(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		r := requestFor(t, n.id, n.name, n.addr)

		for _, c := range []struct {
			what       string
			start, end time.Time
		}{
			{"an empty window", t0, t0},
			{"a reversed window", until, t0},
			{"a window shorter than a second", t0, t0.Add(500 * time.Millisecond)},
		} {
			_, err := e.ca.Issue(r, c.start, c.end)
			wantErr(t, "issue for "+c.what, err, ErrCertTime)
		}
		foreign := *r
		foreign.Suite = otherSuite(t, p).Suite()
		_, err := e.ca.Issue(&foreign, t0, until)
		wantErr(t, "issue for another suite", err, ErrSuite)

		a, err := e.ca.Issue(r, t0.Add(700*time.Millisecond), until)
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.ca.Issue(r, t0, until)
		if err != nil {
			t.Fatal(err)
		}
		if a.NotBefore != t0.Unix() || a.CAID != e.ca.id {
			t.Fatalf("not_before %d and ca_id %x, want %d and %x", a.NotBefore, a.CAID, t0.Unix(), e.ca.id)
		}
		if a.Serial == b.Serial {
			t.Fatal("two certificates share a serial")
		}
	})
}

func TestInstallRefusesAnotherNodesCertificate(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		served := string(n.bundle(t, t0, time.Hour))

		twin, err := NewIdentity(p, n.name, n.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(twin.Close)
		issue := func(r *Request) []byte {
			t.Helper()
			c, err := e.ca.Issue(r, t0, until)
			if err != nil {
				t.Fatal(err)
			}
			return c.Marshal()
		}
		foreign := newEnv(t, otherSuite(t, p)).node(t, n.name)

		for _, c := range []struct {
			what string
			cert []byte
			now  time.Time
			want error
		}{
			{"another identity", issue(requestFor(t, twin, n.name, n.addr)), t0, ErrCertMismatch},
			{"another suite", foreign.raw, t0, ErrSuite},
			{"another name", issue(requestFor(t, n.id, "relay-2", n.addr)), t0, ErrRoster},
			{"another address", issue(requestFor(t, n.id, n.name, addrOf("relay-2"))), t0, ErrRoster},
			{"an expired certificate", n.raw, until, ErrCertTime},
			{"a certificate not yet valid", n.raw, t0.Add(-Skew - time.Second), ErrCertTime},
			{"a malformed certificate", append(n.raw, 0), t0, ErrFormat},
		} {
			wantErr(t, "install of "+c.what, n.id.Install(c.cert, c.now), c.want)
		}
		if b, ok := n.id.Bundle(); !ok || string(b) != served {
			t.Fatal("a refused certificate changed what the node serves")
		}

		wantErr(t, "install within the skew", n.id.Install(n.raw, t0.Add(-Skew)), nil)
		if _, ok := n.id.Bundle(); ok {
			t.Fatal("the bundle of the previous certificate is still served")
		}
	})
}

func TestBundleNeedsCertificateAndKeys(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		id, err := NewIdentity(p, "relay-1", addrOf("relay-1"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(id.Close)
		onion := agreementKey(t, p)

		if _, ok := id.Bundle(); ok {
			t.Fatal("a bundle before any certificate")
		}
		id.SetKeys(onion, onion, 7)
		wantErr(t, "refresh before install", id.Refresh(t0, time.Hour), ErrNoCert)

		cert, err := e.ca.Issue(requestFor(t, id, "relay-1", addrOf("relay-1")), t0, until)
		if err != nil {
			t.Fatal(err)
		}
		if err := id.Install(cert.Marshal(), t0); err != nil {
			t.Fatal(err)
		}
		id.SetKeys(nil, nil, 7)
		wantErr(t, "refresh without keys", id.Refresh(t0, time.Hour), ErrKeySize)
		id.SetKeys(onion[1:], onion, 7)
		wantErr(t, "refresh with a short link key", id.Refresh(t0, time.Hour), ErrKeySize)
		if _, ok := id.Bundle(); ok {
			t.Fatal("a bundle before the first successful refresh")
		}

		id.SetKeys(onion, onion, 7)
		if err := id.Refresh(t0, time.Hour); err != nil {
			t.Fatal(err)
		}
		b, ok := id.Bundle()
		if !ok {
			t.Fatal("no bundle after refresh")
		}
		v, err := Verify(p, e.pol, addrOf("relay-1"), b, t0)
		if err != nil {
			t.Fatal(err)
		}
		if v.Epoch != 7 {
			t.Fatalf("epoch %d, want 7", v.Epoch)
		}
	})
}

func TestRefreshBoundsTheDescriptor(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		for _, c := range []struct {
			what    string
			now     time.Time
			ttl     time.Duration
			expires time.Time
		}{
			{"far from not_after", t0, time.Hour, t0.Add(time.Hour)},
			{"close to not_after", until.Add(-30 * time.Minute), time.Hour, until},
			{"the longest ttl", t0, MaxDescriptorLife, t0.Add(MaxDescriptorLife)},
			{"within a second", t0.Add(700 * time.Millisecond), time.Hour, t0.Add(time.Hour)},
			{"in the last second", until.Add(-500 * time.Millisecond), time.Hour, until},
		} {
			b := n.bundle(t, c.now, c.ttl)
			parsed, err := ParseBundle(b)
			if err != nil {
				t.Fatal(err)
			}
			d, err := ParseDescriptor(parsed.Descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if d.Published != c.now.Unix() || d.Expires != c.expires.Unix() {
				t.Fatalf("%s: published %d expires %d, want %d and %d", c.what, d.Published, d.Expires, c.now.Unix(), c.expires.Unix())
			}
			if _, err := Verify(p, e.pol, n.addr, b, c.now); err != nil {
				t.Fatalf("%s: the refreshed bundle does not verify: %v", c.what, err)
			}
		}

		for _, ttl := range []time.Duration{0, -time.Hour, MaxDescriptorLife + time.Second} {
			wantErr(t, "refresh with ttl "+ttl.String(), n.id.Refresh(t0, ttl), ErrDescTime)
		}
		wantErr(t, "refresh at not_after", n.id.Refresh(until, time.Hour), ErrCertTime)
		if _, ok := n.id.Bundle(); ok {
			t.Fatal("the bundle outlived its certificate")
		}
	})
}

func TestBundleIsSafeToServeDuringRefresh(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		n.bundle(t, t0, time.Hour)

		done := make(chan struct{})
		errs := make(chan error, 4)
		var wg sync.WaitGroup
		var once sync.Once
		stop := func() { once.Do(func() { close(done); wg.Wait() }) }
		defer stop()
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					if b, ok := n.id.Bundle(); ok {
						if _, err := ParseBundle(b); err != nil {
							errs <- err
							return
						}
					}
				}
			}()
		}
		for i := range 5 {
			key := agreementKey(t, p)
			n.id.SetKeys(key, key, uint32(i))
			if err := n.id.Refresh(t0.Add(time.Duration(i)*time.Minute), time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		stop()
		close(errs)
		for err := range errs {
			t.Fatalf("a bundle served during refresh: %v", err)
		}
	})
}

func TestCloseReleasesTheKeys(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ca, err := NewCA(p)
		if err != nil {
			t.Fatal(err)
		}
		id, err := NewIdentity(p, "relay-1", addrOf("relay-1"))
		if err != nil {
			t.Fatal(err)
		}
		probe, err := secmem.New(32)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Release()
		if id.Locked() != probe.Locked() {
			t.Fatalf("identity key locked %v, a buffer under the same policy %v", id.Locked(), probe.Locked())
		}

		r := requestFor(t, id, "relay-1", addrOf("relay-1"))
		cert, err := ca.Issue(r, t0, until)
		if err != nil {
			t.Fatal(err)
		}
		idKey, caKey := id.priv, ca.priv
		id.Close()
		id.Close()
		ca.Close()
		ca.Close()
		if idKey.Bytes() != nil || caKey.Bytes() != nil {
			t.Fatal("Close left a private key buffer live")
		}
		if id.Locked() {
			t.Fatal("a closed identity reports a locked key")
		}

		_, err = ca.Issue(r, t0, until)
		wantErr(t, "issue after close", err, secmem.ErrReleased)
		_, err = id.Request(randomNonce(t))
		wantErr(t, "request after close", err, secmem.ErrReleased)
		wantErr(t, "install after close", id.Install(cert.Marshal(), t0), secmem.ErrReleased)
		if err := id.Refresh(t0, time.Hour); !errors.Is(err, secmem.ErrReleased) {
			t.Fatalf("refresh after close: %v", err)
		}
		if _, ok := id.Bundle(); ok {
			t.Fatal("a closed identity serves a bundle")
		}
	})
}
