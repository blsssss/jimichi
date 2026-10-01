package pki

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func TestRosterRoundTrip(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		r := Roster{Anchor: e.pol.Anchor, Nodes: []RosterNode{
			{Name: "relay-1", Addr: addrOf("relay-1")},
			{Name: "relay-2", Addr: addrOf("relay-2")},
		}}
		raw := r.Marshal()
		got, err := ParseRoster(raw)
		if err != nil {
			t.Fatalf("ParseRoster: %v", err)
		}
		if got.Anchor.String() != r.Anchor.String() || len(got.Nodes) != 2 || got.Nodes[1] != r.Nodes[1] {
			t.Fatalf("round trip gave %+v", got)
		}
		if !got.Has("relay-2", addrOf("relay-2")) || got.Has("relay-2", addrOf("relay-1")) || got.Has("relay-3", addrOf("relay-3")) {
			t.Fatal("Has matches a name with another node's address or a node outside the roster")
		}
	})
}

func TestRosterHasOneSpelling(t *testing.T) {
	p := c25519Provider(t)
	anchor := newEnv(t, p).pol.Anchor.String()
	node := func(name string) string { return `{"name":"` + name + `","addr":"` + addrOf(name) + `"}` }
	good := `{"anchor":"` + anchor + `","nodes":[` + node("relay-1") + `,` + node("relay-2") + `]}`
	if _, err := ParseRoster([]byte(good)); err != nil {
		t.Fatalf("ParseRoster of the canonical spelling: %v", err)
	}
	for _, c := range []struct {
		name string
		raw  string
		want error
	}{
		{"trailing newline", good + "\n", ErrFormat},
		{"space after a comma", strings.Replace(good, `,"nodes"`, `, "nodes"`, 1), ErrFormat},
		{"key in upper case", strings.Replace(good, `"anchor"`, `"Anchor"`, 1), ErrFormat},
		{"unknown key", strings.Replace(good, `]}`, `],"note":""}`, 1), ErrFormat},
		{"keys in another order", `{"nodes":[` + node("relay-1") + `],"anchor":"` + anchor + `"}`, ErrFormat},
		{"not json", "relay-1", ErrFormat},
		{"no nodes", `{"anchor":"` + anchor + `","nodes":[]}`, ErrFormat},
		{"no anchor", `{"anchor":"","nodes":[` + node("relay-1") + `]}`, ErrFormat},
		{"anchor of an unknown suite", `{"anchor":"rsa:AAAA","nodes":[` + node("relay-1") + `]}`, ErrSuite},
		{"bad name", `{"anchor":"` + anchor + `","nodes":[{"name":"Relay_1","addr":"` + addrOf("relay-1") + `"}]}`, ErrFormat},
		{"address without a port", `{"anchor":"` + anchor + `","nodes":[{"name":"relay-1","addr":"relay-1"}]}`, ErrFormat},
		{"repeated name", `{"anchor":"` + anchor + `","nodes":[` + node("relay-1") + `,{"name":"relay-1","addr":"` + addrOf("relay-2") + `"}]}`, ErrDuplicate},
		{"repeated address", `{"anchor":"` + anchor + `","nodes":[` + node("relay-1") + `,{"name":"relay-2","addr":"` + addrOf("relay-1") + `"}]}`, ErrDuplicate},
		{"host with a path", `{"anchor":"` + anchor + `","nodes":[{"name":"relay-1","addr":"relay-1/x:9000"}]}`, ErrFormat},
		{"host with user information", `{"anchor":"` + anchor + `","nodes":[{"name":"relay-1","addr":"a@relay-1:9000"}]}`, ErrFormat},
	} {
		_, err := ParseRoster([]byte(c.raw))
		wantErr(t, c.name, err, c.want)
	}
}

func TestRosterHasASizeLimit(t *testing.T) {
	r := Roster{Anchor: newEnv(t, c25519Provider(t)).pol.Anchor}
	for i := 0; len(r.Marshal()) <= MaxRoster; i++ {
		name := fmt.Sprintf("relay-%d", i)
		if raw := r.Marshal(); i > 0 {
			if _, err := ParseRoster(raw); err != nil {
				t.Fatalf("ParseRoster of %d bytes: %v", len(raw), err)
			}
		}
		r.Nodes = append(r.Nodes, RosterNode{Name: name, Addr: addrOf(name)})
	}
	if _, err := ParseRoster(r.Marshal()); !errors.Is(err, ErrFormat) {
		t.Fatalf("ParseRoster of %d bytes = %v, want %v over %d", len(r.Marshal()), err, ErrFormat, MaxRoster)
	}
}

// a roster of the testbed form, relay-N at relay-N.jimichi.svc.cluster.local:9000,
// counted by hand. The frame {"anchor":"","nodes":[]} is 24 bytes. The anchor
// is the suite name, a colon and the base64 of the CA key: 7 + 44 = 51 bytes
// on c25519 (a 32-byte key), 5 + 88 = 93 on GOST (64 bytes). A node is
// {"name":"","addr":""}, 21 bytes, with a 7-byte name and a 38-byte address:
// 66 bytes, 68 from relay-10 on, and a comma between nodes.
//
//	five nodes: 24 + 51 + 5*66 + 4 = 409 bytes on c25519, 451 on GOST
//	n nodes, 10 <= n < 100: 24 + anchor + 9*66 + 68*(n-9) + n-1 = 69n + 5 + anchor
//	c25519: 69n + 56 <= 4096 gives n = 58 (4058 bytes); GOST: 69n + 98 gives n = 57 (4031)
func TestRosterOfTheTestbedForm(t *testing.T) {
	for _, c := range []struct {
		suite   jcrypto.Suite
		five    int
		largest int
		size    int
	}{
		{jcrypto.SuiteC25519, 409, 58, 4058},
		{jcrypto.SuiteGOST, 451, 57, 4031},
	} {
		p, err := suite.New(c.suite)
		if err != nil {
			t.Fatal(err)
		}
		r := Roster{Anchor: newEnv(t, p).pol.Anchor}
		sizes := []int{len(r.Marshal())}
		for n := 1; sizes[n-1] <= MaxRoster; n++ {
			name := fmt.Sprintf("relay-%d", n)
			r.Nodes = append(r.Nodes, RosterNode{Name: name, Addr: addrOf(name)})
			raw := r.Marshal()
			if _, err := ParseRoster(raw); (err == nil) != (len(raw) <= MaxRoster) {
				t.Fatalf("%v: ParseRoster of %d nodes in %d bytes: %v", c.suite, n, len(raw), err)
			}
			sizes = append(sizes, len(raw))
		}
		if largest := len(sizes) - 2; sizes[5] != c.five || largest != c.largest || sizes[largest] != c.size {
			t.Fatalf("%v: five nodes take %d bytes and the largest roster holds %d nodes in %d bytes; want %d, %d and %d",
				c.suite, sizes[5], largest, sizes[largest], c.five, c.largest, c.size)
		}
	}
}

func c25519Provider(t *testing.T) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMirrorRoundTripIsSortedByAddress(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		b1 := e.node(t, "relay-1").bundle(t, t0, time.Hour)
		b2 := e.node(t, "relay-2").bundle(t, t0, time.Hour)
		b3 := e.node(t, "relay-3").bundle(t, t0, time.Hour)
		raw, err := MarshalMirror([]MirrorEntry{{addrOf("relay-3"), b3}, {addrOf("relay-1"), b1}, {addrOf("relay-2"), b2}})
		if err != nil {
			t.Fatalf("MarshalMirror: %v", err)
		}
		again, err := MarshalMirror([]MirrorEntry{{addrOf("relay-2"), b2}, {addrOf("relay-3"), b3}, {addrOf("relay-1"), b1}})
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatalf("the same bundles in another order encode differently: %v", err)
		}
		got, err := ParseMirror(raw)
		if err != nil {
			t.Fatalf("ParseMirror: %v", err)
		}
		for i, want := range []MirrorEntry{{addrOf("relay-1"), b1}, {addrOf("relay-2"), b2}, {addrOf("relay-3"), b3}} {
			if got[i].Addr != want.Addr || !bytes.Equal(got[i].Bundle, want.Bundle) {
				t.Fatalf("entry %d: %s, want %s with its bundle byte for byte", i, got[i].Addr, want.Addr)
			}
			if _, err := Verify(p, e.pol, got[i].Addr, got[i].Bundle, t0); err != nil {
				t.Fatalf("entry %d does not verify after the round trip: %v", i, err)
			}
		}
	})
}

func TestMirrorHasOneSpelling(t *testing.T) {
	p := c25519Provider(t)
	e := newEnv(t, p)
	b1 := string(e.node(t, "relay-1").bundle(t, t0, time.Hour))
	b2 := string(e.node(t, "relay-2").bundle(t, t0, time.Hour))
	item := func(name, bundle string) string { return `{"addr":"` + addrOf(name) + `","bundle":` + bundle + `}` }
	good := `[` + item("relay-1", b1) + `,` + item("relay-2", b2) + `]`
	if _, err := ParseMirror([]byte(good)); err != nil {
		t.Fatalf("ParseMirror of the canonical spelling: %v", err)
	}
	for _, c := range []struct {
		name string
		raw  string
		want error
	}{
		{"empty list", `[]`, ErrFormat},
		{"null", `null`, ErrFormat},
		{"not json", `addr=relay-1`, ErrFormat},
		{"trailing newline", good + "\n", ErrFormat},
		{"unsorted", `[` + item("relay-2", b2) + `,` + item("relay-1", b1) + `]`, ErrFormat},
		{"repeated address", `[` + item("relay-1", b1) + `,` + item("relay-1", b2) + `]`, ErrDuplicate},
		{"address without a port", `[{"addr":"relay-1","bundle":` + b1 + `}]`, ErrFormat},
		{"unknown key", `[{"addr":"` + addrOf("relay-1") + `","bundle":` + b1 + `,"note":""}]`, ErrFormat},
		{"key in upper case", `[{"Addr":"` + addrOf("relay-1") + `","bundle":` + b1 + `}]`, ErrFormat},
		{"bundle as a string", `[{"addr":"` + addrOf("relay-1") + `","bundle":"x"}]`, ErrFormat},
		{"bundle missing", `[{"addr":"` + addrOf("relay-1") + `"}]`, ErrFormat},
		{"bundle with a space inside", `[` + item("relay-1", strings.Replace(b1, `,"suite"`, `, "suite"`, 1)) + `]`, ErrFormat},
		{"bundle of an unknown version", `[` + item("relay-1", strings.Replace(b1, `"v":1`, `"v":2`, 1)) + `]`, ErrVersion},
	} {
		_, err := ParseMirror([]byte(c.raw))
		wantErr(t, c.name, err, c.want)
	}
	if _, err := MarshalMirror([]MirrorEntry{{addrOf("relay-1"), []byte(b1)}, {addrOf("relay-1"), []byte(b2)}}); err == nil {
		t.Fatal("MarshalMirror wrote one address twice")
	}
	if _, err := MarshalMirror([]MirrorEntry{{addrOf("relay-1"), []byte(`{"v":1}`)}}); err == nil {
		t.Fatal("MarshalMirror wrote something that is not a bundle")
	}
	if _, err := MarshalMirror(nil); err == nil {
		t.Fatal("MarshalMirror wrote an empty mirror")
	}
}
