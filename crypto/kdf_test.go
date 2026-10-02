package crypto_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

var suites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// every label of the scheme, written out; none holds a zero byte and none is
// longer than 50 bytes
func TestLabels(t *testing.T) {
	for _, tc := range []struct {
		suite   jcrypto.Suite
		purpose string
		want    string
	}{
		{jcrypto.SuiteC25519, "agree", "jimichi/v1/c25519/agree"},
		{jcrypto.SuiteC25519, "mix", "jimichi/v1/c25519/mix"},
		{jcrypto.SuiteC25519, "setup", "jimichi/v1/c25519/setup"},
		{jcrypto.SuiteC25519, "cell", "jimichi/v1/c25519/cell"},
		{jcrypto.SuiteC25519, "setup/replay", "jimichi/v1/c25519/setup/replay"},
		{jcrypto.SuiteC25519, "counter/fwd", "jimichi/v1/c25519/counter/fwd"},
		{jcrypto.SuiteC25519, "counter/bwd", "jimichi/v1/c25519/counter/bwd"},
		{jcrypto.SuiteC25519, "link/i2r", "jimichi/v1/c25519/link/i2r"},
		{jcrypto.SuiteC25519, "link/r2i", "jimichi/v1/c25519/link/r2i"},
		{jcrypto.SuiteGOST, "agree", "jimichi/v1/gost/agree"},
		{jcrypto.SuiteGOST, "mix", "jimichi/v1/gost/mix"},
		{jcrypto.SuiteGOST, "setup", "jimichi/v1/gost/setup"},
		{jcrypto.SuiteGOST, "cell", "jimichi/v1/gost/cell"},
		{jcrypto.SuiteGOST, "setup/replay", "jimichi/v1/gost/setup/replay"},
		{jcrypto.SuiteGOST, "counter/fwd", "jimichi/v1/gost/counter/fwd"},
		{jcrypto.SuiteGOST, "counter/bwd", "jimichi/v1/gost/counter/bwd"},
		{jcrypto.SuiteGOST, "link/i2r", "jimichi/v1/gost/link/i2r"},
		{jcrypto.SuiteGOST, "link/r2i", "jimichi/v1/gost/link/r2i"},
	} {
		got, err := jcrypto.Label(tc.suite, tc.purpose)
		if err != nil || string(got) != tc.want {
			t.Fatalf("Label(%v, %q) = %q, %v; want %q", tc.suite, tc.purpose, got, err, tc.want)
		}
		if bytes.IndexByte(got, 0x00) >= 0 || len(got) > 50 {
			t.Fatalf("label %q holds a zero byte or is %d bytes long", got, len(got))
		}
	}

	longest, err := jcrypto.Label(jcrypto.SuiteC25519, strings.Repeat("a", 32))
	if err != nil || len(longest) != 50 {
		t.Fatalf("the longest label is %d bytes, %v; want 50", len(longest), err)
	}
}

func TestBadPurposeIsRefused(t *testing.T) {
	for _, purpose := range []string{
		"", "Cell", "cell ", "cell\x00", "cell\x00x", "/cell", "cell/", "link//i2r", "link_i2r",
		"link.i2r", "Ñ", strings.Repeat("a", 33),
	} {
		for _, s := range suites {
			if _, err := jcrypto.Label(s, purpose); !errors.Is(err, jcrypto.ErrBadLabel) {
				t.Fatalf("Label(%q): %v, want ErrBadLabel", purpose, err)
			}
			if _, err := jcrypto.DeriveLabel(s, purpose); !errors.Is(err, jcrypto.ErrBadLabel) {
				t.Fatalf("DeriveLabel(%q): %v, want ErrBadLabel", purpose, err)
			}
			if _, err := jcrypto.TranscriptBytes(s, purpose, []byte{1}); !errors.Is(err, jcrypto.ErrBadLabel) {
				t.Fatalf("TranscriptBytes(%q): %v, want ErrBadLabel", purpose, err)
			}
		}
	}
	for _, s := range []jcrypto.Suite{0, 3, 99} {
		if _, err := jcrypto.Label(s, "cell"); !errors.Is(err, jcrypto.ErrBadLabel) {
			t.Fatalf("Label under suite %d: %v, want ErrBadLabel", s, err)
		}
		if _, err := jcrypto.TranscriptBytes(s, "setup", []byte{1}); !errors.Is(err, jcrypto.ErrBadContext) {
			t.Fatalf("TranscriptBytes under suite %d: %v, want ErrBadContext", s, err)
		}
	}
}

// a caller of DeriveKey must not reach the labels of Agree and MixKey or the
// transcript prefix; the providers themselves get them through Label
func TestReservedPurposes(t *testing.T) {
	for _, s := range suites {
		for _, purpose := range []string{"agree", "mix", "transcript/setup", "transcript/link", "transcript/x"} {
			if _, err := jcrypto.DeriveLabel(s, purpose); !errors.Is(err, jcrypto.ErrBadLabel) {
				t.Fatalf("DeriveLabel(%q): %v, want ErrBadLabel", purpose, err)
			}
		}
		for _, purpose := range []string{"agree", "mix"} {
			if _, err := jcrypto.Label(s, purpose); err != nil {
				t.Fatalf("Label(%q): %v", purpose, err)
			}
		}
		for _, purpose := range []string{"agree/x", "mixer", "transcript", "e2e/send", "auth/tag", "link/ratchet", "cell/ratchet"} {
			got, err := jcrypto.DeriveLabel(s, purpose)
			want, _ := jcrypto.Label(s, purpose)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("DeriveLabel(%q) = %q, %v", purpose, got, err)
			}
		}
	}
}

func goldenParts(n int) [3][][]byte {
	return [3][][]byte{
		{{0x02}, {0x00}, {0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, n), seq(0x00, n)},
		{{0x02}, {0x01}, seq(0x00, n), seq(0x40, n), seq(0x80, n)},
		{{0x02}, {0x00}, seq(0x00, n), seq(0x40, n)},
	}
}

var goldenExchange = [3]string{"setup", "link", "link"}

func hexSeq(first byte, n int) string { return hex.EncodeToString(seq(first, n)) }

// the transcripts G1, G2, G3 of the golden vectors, byte for byte: the ASCII
// head, a zero byte, the number of parts, then every part behind its two-byte
// big-endian length. P is 32 on c25519 and 64 on GOST, which gives 120, 143, 109
// and 182, 237, 171 bytes
func TestTranscriptBytes(t *testing.T) {
	for _, tc := range []struct {
		suite   jcrypto.Suite
		pub     int
		head    string
		lenPub  string
		lengths [3]int
		sums    [3]string
	}{
		{
			jcrypto.SuiteC25519, 32, "jimichi/v1/c25519/transcript/", "0020", [3]int{120, 143, 109},
			[3]string{
				"bf5988647af2c8b161b8992b8015c2bea0aed5837cc53e37b60450f5fc43aeb7",
				"70b1a866bbce04b1e398435c381fe1cb1e9160a8d7e54a86efe2763c51353fd1",
				"412a81d7b53b40da47fab9eade99cd91d6b4c56b40d2a2d7e0c5d85a88fb9381",
			},
		},
		{
			jcrypto.SuiteGOST, 64, "jimichi/v1/gost/transcript/", "0040", [3]int{182, 237, 171},
			[3]string{
				"89a0d93bcff53a1914892c6fdf5b8cad7a726f6678cb09c01d91aa532a2b5f1c",
				"27f9517518d0f810964dc8caa1f85fd088216ec3a1b4140482a27ea8f1339ce0",
				"9d44cf104c23a21dc4d25daf8383d800307304309eea1ee7b651d2c00da3afe2",
			},
		},
	} {
		n, l := tc.pub, tc.lenPub
		want := [3]string{
			hex.EncodeToString([]byte(tc.head+"setup")) + "00 05" + "0001 02" + "0001 00" + "0008 00000000000000c8" +
				l + hexSeq(0x80, n) + l + hexSeq(0x00, n),
			hex.EncodeToString([]byte(tc.head+"link")) + "00 05" + "0001 02" + "0001 01" +
				l + hexSeq(0x00, n) + l + hexSeq(0x40, n) + l + hexSeq(0x80, n),
			hex.EncodeToString([]byte(tc.head+"link")) + "00 04" + "0001 02" + "0001 00" +
				l + hexSeq(0x00, n) + l + hexSeq(0x40, n),
		}
		parts := goldenParts(n)
		p := provider(t, tc.suite)
		for i := range parts {
			got, err := jcrypto.TranscriptBytes(tc.suite, goldenExchange[i], parts[i]...)
			if err != nil {
				t.Fatalf("%v G%d: %v", tc.suite, i+1, err)
			}
			if !bytes.Equal(got, unhex(t, want[i])) || len(got) != tc.lengths[i] {
				t.Fatalf("%v T(G%d) = %x (%d bytes)\nwant %s (%d bytes)", tc.suite, i+1, got, len(got), want[i], tc.lengths[i])
			}
			ctx, err := jcrypto.NewContext(p, goldenExchange[i], parts[i]...)
			if err != nil {
				t.Fatalf("%v G%d: %v", tc.suite, i+1, err)
			}
			if !bytes.Equal(ctx.Sum(), p.Hash(got)) || hex.EncodeToString(ctx.Sum()) != tc.sums[i] {
				t.Fatalf("%v th(G%d) = %x, want %s", tc.suite, i+1, ctx.Sum(), tc.sums[i])
			}
			if !ctx.Valid() || ctx.Suite() != tc.suite {
				t.Fatalf("%v G%d: context is not valid or names suite %v", tc.suite, i+1, ctx.Suite())
			}
		}
	}

	// T(G1) on c25519 once more as one literal string
	g1 := unhex(t, "6a696d696368692f76312f6332353531392f7472616e7363726970742f7365747570 00 05"+
		"0001 02 0001 00 0008 00000000000000c8"+
		"0020 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"+
		"0020 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	got, err := jcrypto.TranscriptBytes(jcrypto.SuiteC25519, "setup", goldenParts(32)[0]...)
	if err != nil || !bytes.Equal(got, g1) {
		t.Fatalf("T(G1) = %x, %v", got, err)
	}
}

// the same bytes cut at different places are different transcripts
func TestTranscriptIsInjective(t *testing.T) {
	for _, s := range suites {
		p := provider(t, s)
		sums := map[string]string{}
		for name, parts := range map[string][][]byte{
			"ab, c":    {[]byte("ab"), []byte("c")},
			"a, bc":    {[]byte("a"), []byte("bc")},
			"abc":      {[]byte("abc")},
			"a, b, c":  {[]byte("a"), []byte("b"), []byte("c")},
			"c, ab":    {[]byte("c"), []byte("ab")},
			"abc, 00":  {[]byte("abc"), {0x00}},
			"0003abc":  {{0x00, 0x03, 'a', 'b', 'c'}},
			"ab, 0001": {[]byte("ab"), {0x00, 0x01}},
		} {
			ctx, err := jcrypto.NewContext(p, "test", parts...)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			key := string(ctx.Sum())
			if other, seen := sums[key]; seen {
				t.Fatalf("%v: %q and %q hash to one context", s, name, other)
			}
			sums[key] = name
		}

		one, err := jcrypto.NewContext(p, "setup", []byte("abc"))
		if err != nil {
			t.Fatal(err)
		}
		other, err := jcrypto.NewContext(p, "link", []byte("abc"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(one.Sum(), other.Sum()) {
			t.Fatalf("%v: two exchanges gave one context", s)
		}
	}

	parts := [][]byte{[]byte("abc")}
	c, err := jcrypto.TranscriptBytes(jcrypto.SuiteC25519, "test", parts...)
	if err != nil {
		t.Fatal(err)
	}
	g, err := jcrypto.TranscriptBytes(jcrypto.SuiteGOST, "test", parts...)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, g) {
		t.Fatal("the transcript does not name the suite")
	}
}

func TestBadContextIsRefused(t *testing.T) {
	var zero jcrypto.Context
	if zero.Valid() {
		t.Fatal("the zero Context is valid")
	}
	if _, err := jcrypto.NewContext(nil, "test", []byte{1}); !errors.Is(err, jcrypto.ErrBadContext) {
		t.Fatalf("NewContext without a provider: %v, want ErrBadContext", err)
	}

	many := make([][]byte, 256)
	for i := range many {
		many[i] = []byte{byte(i)}
	}
	for _, s := range suites {
		p := provider(t, s)
		for name, parts := range map[string][][]byte{
			"no parts":           nil,
			"256 parts":          many,
			"an empty part":      {[]byte("a"), {}, []byte("b")},
			"a nil part":         {nil},
			"a part of 65536":    {make([]byte, 65536)},
			"an empty last part": append(many[:254:254], nil),
		} {
			if _, err := jcrypto.NewContext(p, "test", parts...); !errors.Is(err, jcrypto.ErrBadContext) {
				t.Fatalf("%v, %s: %v, want ErrBadContext", s, name, err)
			}
			if _, err := jcrypto.TranscriptBytes(s, "test", parts...); !errors.Is(err, jcrypto.ErrBadContext) {
				t.Fatalf("%v, %s: TranscriptBytes gave %v, want ErrBadContext", s, name, err)
			}
		}
		for name, parts := range map[string][][]byte{
			"255 parts":       many[:255],
			"a part of 65535": {make([]byte, 65535)},
			"one byte":        {{0x00}},
		} {
			ctx, err := jcrypto.NewContext(p, "test", parts...)
			if err != nil || !ctx.Valid() || ctx.Suite() != s {
				t.Fatalf("%v, %s: %v", s, name, err)
			}
		}
	}
}

// the parts are hashed when the context is made, and Sum hands out a copy, so
// neither a later write to a part nor one to the sum reaches the context
func TestContextIsFixedAtCreation(t *testing.T) {
	for _, s := range suites {
		p := provider(t, s)
		part := []byte("cell body")
		ctx, err := jcrypto.NewContext(p, "test", part)
		if err != nil {
			t.Fatal(err)
		}
		before := ctx.Sum()
		part[0] ^= 0xff
		sum := ctx.Sum()
		sum[0] ^= 0xff
		if !bytes.Equal(ctx.Sum(), before) || len(before) != jcrypto.ContextSize {
			t.Fatalf("%v: the context changed after it was made", s)
		}
	}
}
