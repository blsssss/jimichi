package pki

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestChainRoundTrip(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		anchor, err := ParseAnchor(e.ca.Anchor().String())
		if err != nil {
			t.Fatal(err)
		}
		pol := Policy{Anchor: anchor, Skew: Skew}

		var addrs []string
		var bundles [][]byte
		var nodes []*node
		for _, name := range []string{"relay-1", "relay-2", "relay-3"} {
			n := e.node(t, name)
			nodes = append(nodes, n)
			addrs = append(addrs, n.addr)
			bundles = append(bundles, n.bundle(t, t0, time.Hour))
		}

		got, err := VerifyChain(p, pol, addrs, bundles, t0)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range got {
			n := nodes[i]
			switch {
			case v.Addr != n.addr, v.Name != n.name:
				t.Fatalf("node %d: %s %s, want %s %s", i, v.Name, v.Addr, n.name, n.addr)
			case !bytes.Equal(v.Identity, n.cert.Identity):
				t.Fatalf("node %d: identity differs from the certificate", i)
			case !bytes.Equal(v.OnionPub, n.onion), !bytes.Equal(v.LinkPub, n.onion):
				t.Fatalf("node %d: keys differ from the ones the node set", i)
			case v.Epoch != 0, !v.CertUntil.Equal(until), !v.DescUntil.Equal(t0.Add(time.Hour)):
				t.Fatalf("node %d: epoch %d, until %v and %v", i, v.Epoch, v.CertUntil, v.DescUntil)
			}
			if Fingerprint(p, v.Identity) != n.id.Fingerprint() {
				t.Fatalf("node %d: fingerprint differs from the identity's own", i)
			}
		}
	})
}

func TestEveryFlippedByteHasItsSentinel(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		b, err := ParseBundle(n.bundle(t, t0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseDescriptor(b.Descriptor)
		if err != nil {
			t.Fatal(err)
		}
		c := n.cert

		t.Run("certificate", func(t *testing.T) {
			flipped(t, b.Cert, []field{
				{"version", 1, ErrVersion},
				{"suite", 1, ErrSuite},
				{"serial", SerialSize, ErrCertSignature},
				{"ca_id", IDSize, ErrUnknownCA},
				{"not_before", 8, ErrCertSignature},
				{"not_after", 8, ErrCertSignature},
				{"name length", 1, ErrFormat},
				{"name", len(c.Name), ErrFormat},
				{"address length", 1, ErrFormat},
				{"address", len(c.Addr), ErrFormat},
				{"identity length", 1, ErrFormat},
				{"identity", len(c.Identity), ErrCertSignature},
				{"signature length", 1, ErrFormat},
				{"signature", len(c.Sig), ErrCertSignature},
			}, func(cert []byte) error {
				_, err := Verify(p, e.pol, n.addr, pack(p, cert, b.Descriptor), t0)
				return err
			})
		})

		t.Run("descriptor", func(t *testing.T) {
			flipped(t, b.Descriptor, []field{
				{"version", 1, ErrVersion},
				{"suite", 1, ErrSuite},
				{"epoch", 4, ErrDescSignature},
				{"published", 8, ErrDescSignature},
				{"expires", 8, ErrDescSignature},
				{"cert_hash", HashSize, ErrCertMismatch},
				{"link length", 1, ErrFormat},
				{"link key", len(d.LinkPub), ErrDescSignature},
				{"onion length", 1, ErrFormat},
				{"onion key", len(d.OnionPub), ErrDescSignature},
				{"signature length", 1, ErrFormat},
				{"signature", len(d.Sig), ErrDescSignature},
			}, func(desc []byte) error {
				_, err := Verify(p, e.pol, n.addr, pack(p, b.Cert, desc), t0)
				return err
			})
		})
	})
}

func TestForeignCA(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		foreign := newEnv(t, p)

		_, err := Verify(p, foreign.pol, n.addr, n.bundle(t, t0, time.Hour), t0)
		wantErr(t, "certificate from another CA", err, ErrUnknownCA)

		// the foreign CA writes the trusted CA's id into a certificate it signs
		forged := *n.cert
		forged.CAID = e.ca.id
		sig, err := foreign.ca.sign(certDomain, forged.body())
		if err != nil {
			t.Fatal(err)
		}
		forged.Sig = sig
		n.raw = forged.Marshal()
		_, err = Verify(p, e.pol, n.addr, n.pack(t, n.descriptor(t0, t0.Add(time.Hour))), t0)
		wantErr(t, "forged ca_id", err, ErrCertSignature)
	})
}

func TestForeignIdentity(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		victim := e.node(t, "relay-1")
		other := e.node(t, "relay-2")

		// the other node signs a descriptor that names the victim's certificate
		impostor := &node{p: p, id: other.id, raw: victim.raw, onion: other.onion}
		_, err := Verify(p, e.pol, victim.addr, impostor.pack(t, impostor.descriptor(t0, t0.Add(time.Hour))), t0)
		wantErr(t, "descriptor signed by another identity", err, ErrDescSignature)

		b, err := ParseBundle(other.bundle(t, t0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(p, e.pol, victim.addr, pack(p, victim.raw, b.Descriptor), t0)
		wantErr(t, "descriptor of another certificate", err, ErrCertMismatch)
	})
}

type countingProvider struct {
	jcrypto.CryptoProvider
	verifies atomic.Int32
}

func (c *countingProvider) Verify(pub, msg, sig []byte) bool {
	c.verifies.Add(1)
	return c.CryptoProvider.Verify(pub, msg, sig)
}

func TestCrossSuiteStopsBeforeAnyKeyIsParsed(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		q := otherSuite(t, p)
		mine := newEnv(t, p)
		theirs := newEnv(t, q)
		n := theirs.node(t, "relay-1")
		foreign := n.bundle(t, t0, time.Hour)
		b, err := ParseBundle(foreign)
		if err != nil {
			t.Fatal(err)
		}
		relabelled := Bundle{V: Version, Suite: p.Suite().String(), Cert: b.Cert, Descriptor: b.Descriptor}.Marshal()
		unsigned, err := Unsigned(q, n.onion, n.onion)
		if err != nil {
			t.Fatal(err)
		}

		cp := &countingProvider{CryptoProvider: p}
		for _, c := range []struct {
			name   string
			pol    Policy
			bundle []byte
		}{
			{"envelope of the other suite", mine.pol, foreign},
			{"certificate of the other suite", mine.pol, relabelled},
			{"anchor of the other suite", theirs.pol, pack(p, b.Cert, b.Descriptor)},
		} {
			_, err := Verify(cp, c.pol, n.addr, c.bundle, t0)
			wantErr(t, c.name, err, ErrSuite)
		}
		for _, bundle := range [][]byte{foreign, relabelled, unsigned} {
			_, err := Unverified(cp, []string{n.addr}, [][]byte{bundle})
			wantErr(t, "unverified bundle of the other suite", err, ErrSuite)
		}
		if v := cp.verifies.Load(); v != 0 {
			t.Fatalf("%d signature checks ran on a bundle of the other suite", v)
		}
	})
}

func TestAddressMustMatchByteForByte(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		bundle := n.bundle(t, t0, time.Hour)
		for _, addr := range []string{
			addrOf("relay-2"),
			"Relay-1.jimichi.svc.cluster.local:9000",
			"relay-1.jimichi.svc.cluster.local.:9000",
			"relay-1.jimichi.svc.cluster.local:09000",
			"relay-1.jimichi.svc.cluster.local:9000\x00",
			"",
		} {
			_, err := Verify(p, e.pol, addr, bundle, t0)
			wantErr(t, "address "+addr, err, ErrWrongAddr)
		}
	})
}

func TestEveryTimeBoundary(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		hour, day := time.Hour, 24*time.Hour
		for _, c := range []struct {
			name               string
			published, expires time.Time
			now                time.Time
			maxLife            time.Duration
			want               error
		}{
			{"certificate starts within the skew", t0, t0.Add(hour), t0.Add(-Skew), 0, nil},
			{"certificate starts a second past the skew", t0, t0.Add(hour), t0.Add(-Skew - time.Second), 0, ErrCertTime},
			{"certificate starts a nanosecond past the skew", t0, t0.Add(hour), t0.Add(-Skew - 1), 0, ErrCertTime},
			{"certificate in its last second", until.Add(-hour), until, until.Add(-time.Second), 0, nil},
			{"certificate in its last nanosecond", until.Add(-hour), until, until.Add(-1), 0, nil},
			{"certificate at not_after", until.Add(-hour), until, until, 0, ErrCertTime},
			{"descriptor starts within the skew", t0.Add(hour), t0.Add(2 * hour), t0.Add(hour - Skew), 0, nil},
			{"descriptor starts a second past the skew", t0.Add(hour), t0.Add(2 * hour), t0.Add(hour - Skew - time.Second), 0, ErrDescTime},
			{"descriptor in its last second", t0, t0.Add(hour), t0.Add(hour - time.Second), 0, nil},
			{"descriptor at expires", t0, t0.Add(hour), t0.Add(hour), 0, ErrDescTime},
			{"descriptor expires after the certificate", until.Add(-hour), until.Add(time.Second), until.Add(-30 * time.Minute), 0, ErrDescTime},
			{"descriptor lives the maximum", t0, t0.Add(day), t0, 0, nil},
			{"descriptor lives a second over the maximum", t0, t0.Add(day + time.Second), t0, 0, ErrDescTime},
			{"descriptor lives over the policy", t0, t0.Add(hour), t0, 30 * time.Minute, ErrDescTime},
			{"policy above the maximum is cut", t0, t0.Add(day + hour), t0, 2 * day, ErrDescTime},
			{"descriptor expires when published", t0, t0, t0, 0, ErrDescTime},
			{"descriptor expires before published", t0.Add(hour), t0, t0, 0, ErrDescTime},
			{"lifetime that overflows int64", time.Unix(math.MinInt64+1, 0), t0.Add(hour), t0, 0, ErrDescTime},
		} {
			d := n.descriptor(c.published, c.expires)
			pol := e.pol
			pol.MaxLife = c.maxLife
			_, err := Verify(p, pol, n.addr, n.pack(t, d), c.now)
			wantErr(t, c.name, err, c.want)
		}
	})
}

func TestSignatureDomainsAreSeparate(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		d := n.descriptor(t0, t0.Add(time.Hour))

		req, err := n.id.Request(randomNonce(t))
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name string
			sig  []byte
			want error
		}{
			{"descriptor domain", n.sign(t, descriptorDomain, d.body()), nil},
			{"certificate domain", n.sign(t, certDomain, d.body()), ErrDescSignature},
			{"request domain", n.sign(t, requestDomain, d.body()), ErrDescSignature},
			{"no domain", n.sign(t, "", d.body()), ErrDescSignature},
			{"the node's request signature", r.Sig, ErrDescSignature},
		} {
			d.Sig = c.sig
			_, err := Verify(p, e.pol, n.addr, pack(p, n.raw, d.Marshal()), t0)
			wantErr(t, c.name, err, c.want)
		}

		// and the CA's signature over a certificate body under another domain
		cert := *n.cert
		if cert.Sig, err = e.ca.sign(descriptorDomain, cert.body()); err != nil {
			t.Fatal(err)
		}
		n.raw = cert.Marshal()
		_, err = Verify(p, e.pol, n.addr, n.pack(t, n.descriptor(t0, t0.Add(time.Hour))), t0)
		wantErr(t, "certificate signed under the descriptor domain", err, ErrCertSignature)
	})
}

func TestChainRejectsDuplicates(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		a, b := e.node(t, "relay-1"), e.node(t, "relay-2")
		ba := a.bundle(t, t0, time.Hour)

		_, err := VerifyChain(p, e.pol, []string{a.addr, a.addr}, [][]byte{ba, ba}, t0)
		wantErr(t, "same node twice", err, ErrDuplicate)

		b.id.SetKeys(a.onion, a.onion, 0)
		_, err = VerifyChain(p, e.pol, []string{a.addr, b.addr}, [][]byte{ba, b.bundle(t, t0, time.Hour)}, t0)
		wantErr(t, "two nodes with one onion key", err, ErrDuplicate)

		r := requestFor(t, a.id, "relay-3", addrOf("relay-3"))
		cert, err := e.ca.Issue(r, t0, until)
		if err != nil {
			t.Fatal(err)
		}
		twin := &node{p: p, id: a.id, raw: cert.Marshal(), onion: agreementKey(t, p)}
		_, err = VerifyChain(p, e.pol, []string{a.addr, r.Addr},
			[][]byte{ba, twin.pack(t, twin.descriptor(t0, t0.Add(time.Hour)))}, t0)
		wantErr(t, "one identity at two addresses", err, ErrDuplicate)

		_, err = Unverified(p, []string{a.addr, b.addr}, [][]byte{ba, ba})
		wantErr(t, "unverified chain with one onion key twice", err, ErrDuplicate)

		if _, err := VerifyChain(p, e.pol, []string{a.addr}, nil, t0); err == nil {
			t.Fatal("VerifyChain accepted more addresses than bundles")
		}
	})
}

func TestKeySizeIsChecked(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		d := n.descriptor(t0, t0.Add(time.Hour))
		d.OnionPub = d.OnionPub[1:]
		_, err := Verify(p, e.pol, n.addr, n.pack(t, d), t0)
		wantErr(t, "short onion key", err, ErrKeySize)

		d = n.descriptor(t0, t0.Add(time.Hour))
		d.LinkPub = append(bytes.Clone(d.LinkPub), 0)
		_, err = Verify(p, e.pol, n.addr, n.pack(t, d), t0)
		wantErr(t, "long link key", err, ErrKeySize)

		d.Sig = nil
		_, err = Unverified(p, []string{n.addr}, [][]byte{pack(p, nil, d.Marshal())})
		wantErr(t, "unverified long link key", err, ErrKeySize)
	})
}

func TestUnsignedBundle(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		link := agreementKey(t, p)
		b, err := Unsigned(p, link, n.onion)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unverified(p, []string{n.addr}, [][]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[0].LinkPub, link) || !bytes.Equal(got[0].OnionPub, n.onion) || got[0].Addr != n.addr {
			t.Fatal("unverified keys differ from the unsigned bundle")
		}
		parsed, err := ParseBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseDescriptor(parsed.Descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Cert) != 0 || d.CertHash != [HashSize]byte{} || len(d.Sig) != 0 {
			t.Fatal("an unsigned bundle carries a certificate, a hash or a signature")
		}

		_, err = Verify(p, e.pol, n.addr, b, t0)
		wantErr(t, "unsigned bundle under Verify", err, ErrFormat)

		if _, err := Unverified(p, []string{n.addr}, [][]byte{n.bundle(t, t0, time.Hour)}); err != nil {
			t.Fatalf("unverified read of a signed bundle: %v", err)
		}
		_, err = Unsigned(p, link[1:], n.onion)
		wantErr(t, "unsigned bundle with a short key", err, ErrKeySize)
	})
}

func TestVerifyErrorsNameTheNode(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		_, err := VerifyChain(p, e.pol, []string{addrOf("relay-9")}, [][]byte{n.bundle(t, t0, time.Hour)}, t0)
		if !errors.Is(err, ErrWrongAddr) || !strings.Contains(err.Error(), "relay-9") {
			t.Fatalf("error %q does not name the node", err)
		}
	})
}
