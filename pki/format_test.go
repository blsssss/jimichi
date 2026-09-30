package pki

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/wire"
)

func withByte(b []byte, i int, v byte) []byte {
	out := bytes.Clone(b)
	out[i] = v
	return out
}

func TestParsersKeepOneCanonicalForm(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		b, err := ParseBundle(n.bundle(t, t0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		req, err := n.id.Request(randomNonce(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name  string
			raw   []byte
			parse func([]byte) ([]byte, error)
		}{
			{"certificate", b.Cert, func(b []byte) ([]byte, error) {
				c, err := ParseCert(b)
				if err != nil {
					return nil, err
				}
				return c.Marshal(), nil
			}},
			{"descriptor", b.Descriptor, func(b []byte) ([]byte, error) {
				d, err := ParseDescriptor(b)
				if err != nil {
					return nil, err
				}
				return d.Marshal(), nil
			}},
			{"request", req, func(b []byte) ([]byte, error) {
				r, err := ParseRequest(b)
				if err != nil {
					return nil, err
				}
				return r.Marshal(), nil
			}},
		} {
			out, err := c.parse(c.raw)
			if err != nil || !bytes.Equal(out, c.raw) {
				t.Fatalf("%s does not survive a round trip: %v", c.name, err)
			}
			for _, bad := range []struct {
				what string
				b    []byte
				want error
			}{
				{"a trailing byte", append(bytes.Clone(c.raw), 0), ErrFormat},
				{"one byte short", c.raw[:len(c.raw)-1], ErrFormat},
				{"nothing", nil, ErrFormat},
				{"the version alone", c.raw[:1], ErrFormat},
				{"version 0", withByte(c.raw, 0, 0), ErrVersion},
				{"version 2", withByte(c.raw, 0, 2), ErrVersion},
				{"an unknown suite", withByte(c.raw, 1, 9), ErrSuite},
			} {
				_, err := c.parse(bad.b)
				wantErr(t, c.name+" with "+bad.what, err, bad.want)
			}
		}
	})
}

func TestFieldsOverTheirMaximum(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ok := func() *Cert {
			return &Cert{Suite: p.Suite(), Name: "relay-1", Addr: addrOf("relay-1"), Identity: []byte{1}, Sig: []byte{2}}
		}
		if _, err := ParseCert(ok().Marshal()); err != nil {
			t.Fatalf("control certificate: %v", err)
		}
		for _, c := range []struct {
			what string
			edit func(c *Cert)
		}{
			{"name", func(c *Cert) { c.Name = strings.Repeat("a", maxName+1) }},
			{"address", func(c *Cert) { c.Addr = strings.Repeat("a", wire.AddrSize-4) + ":9000" }},
			{"identity", func(c *Cert) { c.Identity = make([]byte, maxKey+1) }},
			{"signature", func(c *Cert) { c.Sig = make([]byte, maxSig+1) }},
			{"empty identity", func(c *Cert) { c.Identity = nil }},
		} {
			cert := ok()
			c.edit(cert)
			_, err := ParseCert(cert.Marshal())
			wantErr(t, "certificate "+c.what, err, ErrFormat)
		}

		d := &Descriptor{Suite: p.Suite(), LinkPub: make([]byte, maxKey+1), OnionPub: []byte{1}}
		_, err := ParseDescriptor(d.Marshal())
		wantErr(t, "descriptor link key", err, ErrFormat)
		r := &Request{Suite: p.Suite(), Name: "relay-1", Addr: addrOf("relay-1"), Identity: []byte{1}, Sig: make([]byte, maxSig+1)}
		_, err = ParseRequest(r.Marshal())
		wantErr(t, "request signature", err, ErrFormat)
	})
}

func TestNamesAndAddresses(t *testing.T) {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"relay-1", true},
		{"a", true},
		{"0-9", true},
		{strings.Repeat("a", maxName), true},
		{"", false},
		{strings.Repeat("a", maxName+1), false},
		{"Relay-1", false},
		{"relay 1", false},
		{"relay-1\x00", false},
		{"relay_1", false},
		{"relay.1", false},
		{"rélay", false},
	} {
		if validName(c.name) != c.ok {
			t.Fatalf("validName(%q) = %v", c.name, !c.ok)
		}
	}

	longest := strings.Repeat("a", wire.AddrSize-5) + ":9000"
	for _, c := range []struct {
		addr string
		ok   bool
	}{
		{addrOf("relay-1"), true},
		{"127.0.0.1:19201", true},
		{"[::1]:9000", true},
		{longest, true},
		{"", false},
		{"a" + longest, false},
		{"relay-1", false},
		{":9000", false},
		{"relay-1:", false},
		{"relay 1:9000", false},
		{"relay-1:9000\x00", false},
		{"\x00relay-1:9000", false},
		{"relay-1:9000\n", false},
		{"rélay:9000", false},
		{"a:b:9000", false},
	} {
		if validAddr(c.addr) != c.ok {
			t.Fatalf("validAddr(%q) = %v", c.addr, !c.ok)
		}
	}

	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, c := range []struct{ name, addr string }{
			{"relay 1", addrOf("relay-1")},
			{"relay\x00", addrOf("relay-1")},
			{strings.Repeat("a", maxName+1), addrOf("relay-1")},
			{"relay-1", "relay-1 .jimichi:9000"},
			{"relay-1", addrOf("relay-1") + "\x00"},
			{"relay-1", "a" + longest},
		} {
			_, err := NewIdentity(p, c.name, c.addr)
			wantErr(t, "identity "+c.name+" "+c.addr, err, ErrFormat)
		}
		id, err := NewIdentity(p, "relay-1", longest)
		if err != nil {
			t.Fatalf("identity at the longest address: %v", err)
		}
		t.Cleanup(id.Close)

		for _, bad := range []*Cert{
			{Suite: p.Suite(), Name: "relay 1", Addr: addrOf("relay-1"), Identity: []byte{1}},
			{Suite: p.Suite(), Name: "relay-1", Addr: "relay-1\x00:9000", Identity: []byte{1}},
		} {
			_, err := ParseCert(bad.Marshal())
			wantErr(t, "certificate for "+bad.Name+" at "+bad.Addr, err, ErrFormat)
		}
		r := &Request{Suite: p.Suite(), Name: "relay-1", Addr: "relay 1:9000", Identity: []byte{1}}
		_, err = ParseRequest(r.Marshal())
		wantErr(t, "request with a space in the address", err, ErrFormat)

		e := newEnv(t, p)
		_, err = e.ca.Issue(requestFor(t, id, "relay-1", "relay 1:9000"), t0, until)
		wantErr(t, "issue for an address with a space", err, ErrFormat)
		_, err = e.ca.Issue(requestFor(t, id, "Relay-1", longest), t0, until)
		wantErr(t, "issue for an upper-case name", err, ErrFormat)
	})
}

func TestAnchor(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		a := e.ca.Anchor()
		s := a.String()
		if !strings.HasPrefix(s, p.Suite().String()+":") {
			t.Fatalf("anchor %q does not start with its suite", s)
		}
		got, err := ParseAnchor(s)
		if err != nil || got.Suite != a.Suite || !bytes.Equal(got.Pub, a.Pub) {
			t.Fatalf("anchor round trip: %v, %v", got, err)
		}
		id := got.ID(p)
		if id != e.ca.id || !bytes.Equal(id[:], p.Hash(a.Pub)[:IDSize]) {
			t.Fatal("ca_id is not the first bytes of the key hash")
		}
		if Fingerprint(p, a.Pub) != hex.EncodeToString(id[:]) {
			t.Fatal("the fingerprint of the CA key differs from its ca_id")
		}

		a.Pub[0] ^= 0xff
		if e.ca.Anchor().Pub[0] == a.Pub[0] {
			t.Fatal("Anchor hands out the CA's own key slice")
		}

		enc := s[len(p.Suite().String())+1:]
		for _, c := range []struct {
			what, s string
			want    error
		}{
			{"no separator", strings.Replace(s, ":", "", 1), ErrFormat},
			{"an unknown suite", "rot13:" + enc, ErrSuite},
			{"no suite", ":" + enc, ErrSuite},
			{"an empty key", p.Suite().String() + ":", ErrFormat},
			{"not base64", p.Suite().String() + ":!!!!", ErrFormat},
			{"a trailing newline", s + "\n", ErrFormat},
			{"a line break inside", s[:10] + "\n" + s[10:], ErrFormat},
			{"a missing pad", strings.TrimRight(s, "="), ErrFormat},
			{"an oversized key", p.Suite().String() + ":" + strings.Repeat("AAAA", 44), ErrFormat},
		} {
			_, err := ParseAnchor(c.s)
			wantErr(t, "anchor with "+c.what, err, c.want)
		}
	})
}

func TestParseBundle(t *testing.T) {
	for _, c := range []struct {
		what, json string
		want       error
	}{
		{"an unknown field", `{"v":1,"suite":"c25519","cert":"","descriptor":"","x":1}`, ErrFormat},
		{"a second value", `{"v":1,"suite":"c25519","cert":"","descriptor":""}{}`, ErrFormat},
		{"version 2", `{"v":2,"suite":"c25519","cert":"","descriptor":""}`, ErrVersion},
		{"no version", `{"suite":"c25519","cert":"","descriptor":""}`, ErrVersion},
		{"a string version", `{"v":"1","suite":"c25519","cert":"","descriptor":""}`, ErrFormat},
		{"loose base64", `{"v":1,"suite":"c25519","cert":"AB==","descriptor":""}`, ErrFormat},
		{"a line break in base64", `{"v":1,"suite":"c25519","cert":"AA\n==","descriptor":""}`, ErrFormat},
		{"an array", `[]`, ErrFormat},
		{"no JSON", `v=1`, ErrFormat},
	} {
		_, err := ParseBundle([]byte(c.json))
		wantErr(t, "bundle with "+c.what, err, c.want)
	}

	b := Bundle{V: Version, Suite: "gost", Cert: []byte{1, 2, 3}, Descriptor: []byte{4}}
	raw := b.Marshal()
	if want := `{"v":1,"suite":"gost","cert":"AQID","descriptor":"BA=="}`; string(raw) != want {
		t.Fatalf("bundle encodes as %s, want %s", raw, want)
	}
	got, err := ParseBundle(append(raw, '\n'))
	if err != nil || got.Suite != b.Suite || !bytes.Equal(got.Cert, b.Cert) || !bytes.Equal(got.Descriptor, b.Descriptor) {
		t.Fatalf("bundle round trip: %+v, %v", got, err)
	}
	if empty := (Bundle{V: Version, Suite: "c25519"}).Marshal(); !bytes.Contains(empty, []byte(`"cert":""`)) {
		t.Fatalf("an empty certificate encodes as %s", empty)
	}
}
