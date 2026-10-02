package providertest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// every purpose the system derives under, with the size it takes
var purposes = []struct {
	name string
	size int
}{
	{"setup", 32},
	{"cell", 32},
	{"setup/replay", 16},
	{"counter/fwd", 8},
	{"counter/bwd", 8},
	{"link/i2r", 32},
	{"link/r2i", 32},
}

func testAgreeMatches(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, aPub := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()

	ctx := mustContext(t, p, "test", aPub, bPub)

	aSecret, err := p.Agree(aPriv, bPub, ctx)
	if err != nil {
		t.Fatalf("Agree(a): %v", err)
	}
	defer aSecret.Release()

	bSecret, err := p.Agree(bPriv, aPub, ctx)
	if err != nil {
		t.Fatalf("Agree(b): %v", err)
	}
	defer bSecret.Release()

	if !bytes.Equal(aSecret.Bytes(), bSecret.Bytes()) {
		t.Fatal("both sides must agree on the same secret")
	}
	if aSecret.Len() != p.KeySize() || allZero(aSecret.Bytes()) {
		t.Fatalf("shared secret of %d bytes, or all zeroes", aSecret.Len())
	}
}

func testAgreeContext(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, _ := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()

	first, err := p.Agree(aPriv, bPub, mustContext(t, p, "test", []byte("session-1")))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer first.Release()

	second, err := p.Agree(aPriv, bPub, mustContext(t, p, "test", []byte("session-2")))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer second.Release()

	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different contexts must produce different secrets")
	}
}

func testAgreeBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	priv, pub := mustEphemeral(t, p)
	defer priv.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))
	short := fixedSecret(t, 1, 3)
	defer short.Release()

	for _, tc := range []struct {
		name string
		priv *secmem.Buffer
		pub  []byte
		ctx  jcrypto.Context
		want error
	}{
		{"nil private key", nil, pub, ctx, jcrypto.ErrBadKeySize},
		{"short private key", short, pub, ctx, jcrypto.ErrBadKeySize},
		{"short public key", priv, []byte{1, 2, 3}, ctx, jcrypto.ErrBadPublicKey},
		{"long public key", priv, append(bytes.Clone(pub), 0), ctx, jcrypto.ErrBadPublicKey},
		{"zero context", priv, pub, jcrypto.Context{}, jcrypto.ErrBadContext},
		{"context of another suite", priv, pub, foreignContext(t, p), jcrypto.ErrBadContext},
		// the context is checked before the public key is looked at
		{"zero context and a bad public key", priv, []byte{1, 2, 3}, jcrypto.Context{}, jcrypto.ErrBadContext},
	} {
		if out, err := p.Agree(tc.priv, tc.pub, tc.ctx); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("Agree(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

func testDeriveKey(t *testing.T, p jcrypto.CryptoProvider) {
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	forward := mustDerive(t, p, secret, "forward", ctx, p.KeySize())
	backward := mustDerive(t, p, secret, "backward", ctx, p.KeySize())
	if len(forward) != p.KeySize() {
		t.Fatalf("derived key size = %d, want %d", len(forward), p.KeySize())
	}
	if bytes.Equal(forward, backward) {
		t.Fatal("different purposes must produce different keys")
	}
	if !bytes.Equal(forward, mustDerive(t, p, secret, "forward", ctx, p.KeySize())) {
		t.Fatal("DeriveKey must be deterministic")
	}

	other := mustContext(t, p, "test", []byte("session-2"))
	if bytes.Equal(forward, mustDerive(t, p, secret, "forward", other, p.KeySize())) {
		t.Fatal("different contexts must produce different keys")
	}

	// wire derives a 16-byte replay tag and 8-byte offsets: every size up to
	// KeySize must work and is the prefix of the full block
	for size := 1; size <= p.KeySize(); size++ {
		short := mustDerive(t, p, secret, "forward", ctx, size)
		if len(short) != size || !bytes.Equal(short, forward[:size]) {
			t.Fatalf("size %d is not the prefix of the full key", size)
		}
	}
	if bytes.Equal(mustDerive(t, p, secret, "replay", ctx, 16), forward[:16]) {
		t.Fatal("different purposes must produce different outputs at a short size too")
	}
}

func testDeriveKeyBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	secret := fixedSecret(t, 0x40, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))
	short := fixedSecret(t, 0x40, p.KeySize()-1)
	defer short.Release()
	long := fixedSecret(t, 0x40, p.KeySize()+1)
	defer long.Release()

	for _, tc := range []struct {
		name    string
		secret  *secmem.Buffer
		purpose string
		ctx     jcrypto.Context
		size    int
		want    error
	}{
		{"size 0", secret, "cell", ctx, 0, jcrypto.ErrBadKeySize},
		{"negative size", secret, "cell", ctx, -1, jcrypto.ErrBadKeySize},
		{"size above KeySize", secret, "cell", ctx, p.KeySize() + 1, jcrypto.ErrBadKeySize},
		{"nil secret", nil, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"short secret", short, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"long secret", long, "cell", ctx, p.KeySize(), jcrypto.ErrBadKeySize},
		{"zero context", secret, "cell", jcrypto.Context{}, p.KeySize(), jcrypto.ErrBadContext},
		{"context of another suite", secret, "cell", foreignContext(t, p), p.KeySize(), jcrypto.ErrBadContext},
		{"purpose of Agree", secret, "agree", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"purpose of MixKey", secret, "mix", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"transcript prefix", secret, "transcript/test", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"empty purpose", secret, "", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"upper case", secret, "Cell", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"zero byte", secret, "cell\x00", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"empty segment", secret, "link//i2r", ctx, p.KeySize(), jcrypto.ErrBadLabel},
		{"33 bytes", secret, strings.Repeat("a", 33), ctx, p.KeySize(), jcrypto.ErrBadLabel},
	} {
		if out, err := p.DeriveKey(tc.secret, tc.purpose, tc.ctx, tc.size); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("DeriveKey(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

func testMixKey(t *testing.T, p jcrypto.CryptoProvider) {
	chain := fixedSecret(t, 0x40, p.KeySize())
	defer chain.Release()
	secret := fixedSecret(t, 0x60, p.KeySize())
	defer secret.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	mixed := mustMix(t, p, chain, secret, ctx)
	if len(mixed) != p.KeySize() {
		t.Fatalf("mixed key of %d bytes, want %d", len(mixed), p.KeySize())
	}
	if !bytes.Equal(mixed, mustMix(t, p, chain, secret, ctx)) {
		t.Fatal("MixKey must be deterministic")
	}
	if bytes.Equal(mixed, mustMix(t, p, secret, chain, ctx)) {
		t.Fatal("MixKey must depend on the order of its secrets")
	}
	if bytes.Equal(mixed, mustMix(t, p, chain, secret, mustContext(t, p, "test", []byte("session-2")))) {
		t.Fatal("MixKey must depend on the context")
	}
	if bytes.Equal(mixed, chain.Bytes()) || bytes.Equal(mixed, secret.Bytes()) {
		t.Fatal("MixKey returned one of its inputs")
	}

	// the result must depend on both secrets, not on one of them alone
	otherChain := fixedSecret(t, 0x41, p.KeySize())
	defer otherChain.Release()
	otherSecret := fixedSecret(t, 0x61, p.KeySize())
	defer otherSecret.Release()
	if bytes.Equal(mixed, mustMix(t, p, otherChain, secret, ctx)) {
		t.Fatal("MixKey ignores the chain key")
	}
	if bytes.Equal(mixed, mustMix(t, p, chain, otherSecret, ctx)) {
		t.Fatal("MixKey ignores the mixed secret")
	}
}

func testMixKeyBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	key := fixedSecret(t, 0x40, p.KeySize())
	defer key.Release()
	short := fixedSecret(t, 0x40, p.KeySize()-1)
	defer short.Release()
	long := fixedSecret(t, 0x40, 2*p.KeySize())
	defer long.Release()
	ctx := mustContext(t, p, "test", []byte("session-1"))

	for _, tc := range []struct {
		name          string
		chain, secret *secmem.Buffer
		ctx           jcrypto.Context
		want          error
	}{
		{"nil chain", nil, key, ctx, jcrypto.ErrBadKeySize},
		{"nil secret", key, nil, ctx, jcrypto.ErrBadKeySize},
		{"short chain", short, key, ctx, jcrypto.ErrBadKeySize},
		{"short secret", key, short, ctx, jcrypto.ErrBadKeySize},
		{"two keys glued as a chain", long, key, ctx, jcrypto.ErrBadKeySize},
		{"two keys glued as a secret", key, long, ctx, jcrypto.ErrBadKeySize},
		{"zero context", key, key, jcrypto.Context{}, jcrypto.ErrBadContext},
		{"context of another suite", key, key, foreignContext(t, p), jcrypto.ErrBadContext},
	} {
		if out, err := p.MixKey(tc.chain, tc.secret, tc.ctx); !errors.Is(err, tc.want) {
			drop(out)
			t.Fatalf("MixKey(%s): %v, want %v", tc.name, err, tc.want)
		}
	}
}

// a change of the exchange, of any part, of a boundary between parts or of
// their order must change everything derived under the context
func testTranscriptSeparates(t *testing.T, p jcrypto.CryptoProvider) {
	priv, _ := mustEphemeral(t, p)
	defer priv.Release()
	peer, pub := mustEphemeral(t, p)
	peer.Release()
	chain := fixedSecret(t, 0x40, p.KeySize())
	defer chain.Release()
	secret := fixedSecret(t, 0x60, p.KeySize())
	defer secret.Release()

	outputs := func(ctx jcrypto.Context) [][]byte {
		t.Helper()
		out := [][]byte{ctx.Sum(), mustMix(t, p, chain, secret, ctx)}
		agreed, err := p.Agree(priv, pub, ctx)
		if err != nil {
			t.Fatalf("Agree: %v", err)
		}
		out = append(out, bytes.Clone(agreed.Bytes()))
		agreed.Release()
		for _, pu := range purposes {
			out = append(out, mustDerive(t, p, chain, pu.name, ctx, pu.size))
		}
		return out
	}

	size := len(pub)
	base := [][]byte{{0x02}, {0x00}, {0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, size), seq(0x00, size)}
	want := outputs(mustContext(t, p, "setup", base...))

	differs := func(name, exchange string, parts [][]byte) {
		t.Helper()
		got := outputs(mustContext(t, p, exchange, parts...))
		for i := range want {
			if bytes.Equal(got[i], want[i]) {
				t.Fatalf("%s: output %d did not change", name, i)
			}
		}
	}

	differs("another exchange", "link", base)
	differs("a part appended", "setup", append(clone(base), []byte{0x00}))
	differs("the last part dropped", "setup", clone(base)[:4])

	swapped := clone(base)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	differs("two keys swapped", "setup", swapped)

	// the same bytes in the same order, cut at other places
	moved := clone(base)
	moved[3], moved[4] = moved[3][:size-1], append([]byte{moved[3][size-1]}, moved[4]...)
	differs("a boundary moved", "setup", moved)
	merged := append(clone(base)[:3], append(bytes.Clone(base[3]), base[4]...))
	differs("two parts merged", "setup", merged)
	split := append(clone(base)[:4], base[4][:1], base[4][1:])
	differs("a part split", "setup", split)

	for i := range base {
		for _, bit := range []int{0, 8*len(base[i]) - 1} {
			flipped := clone(base)
			flipped[i][bit/8] ^= 1 << (bit % 8)
			differs("a bit of part "+string(rune('1'+i)), "setup", flipped)
		}
	}

	// every single bit of the version, the hop index, the link id and both keys
	cell := mustDerive(t, p, chain, "cell", mustContext(t, p, "setup", base...), p.KeySize())
	for i := range base {
		for bit := 0; bit < 8*len(base[i]); bit++ {
			flipped := clone(base)
			flipped[i][bit/8] ^= 1 << (bit % 8)
			ctx := mustContext(t, p, "setup", flipped...)
			if bytes.Equal(ctx.Sum(), want[0]) || bytes.Equal(mustDerive(t, p, chain, "cell", ctx, p.KeySize()), cell) {
				t.Fatalf("bit %d of part %d does not reach the derived key", bit, i+1)
			}
		}
	}
}

// Golden vectors of the key schedule. Common inputs: K = 40 41 .. 5f, P = the
// public key size of the suite (32 or 64), version 02, link id 200.
//
//	G1  setup: 02, 00, 00000000000000c8, onion 80..(80+P-1), ephemeral 00..(P-1)
//	G2  link:  02, 01, ephI 00.., ephR 40.., static 80.. (P bytes each)
//	G3  link:  02, 00, ephI 00.., ephR 40..
//
//	T  = "jimichi/v1/<suite>/transcript/<exchange>" || 00 || u8(n) || n times (u16be(len) || part)
//	th = Hash(T)
//
// T(G1) on c25519, 120 bytes:
//
//	6a696d696368692f76312f6332353531392f7472616e7363726970742f7365747570 00 05
//	0001 02  0001 00  0008 00000000000000c8  0020 80..9f  0020 00..1f
//
// How to recompute without this code, with label = "jimichi/v1/<suite>/<purpose>":
//
//	c25519  th: sha256sum over T
//	        DeriveKey(K, purpose, th, n) = HMAC-SHA256(K, label || 00 || th || 01)[:n]
//	          openssl dgst -sha256 -mac HMAC -macopt hexkey:<K>
//	        MixKey(chain, secret, th): PRK = HMAC-SHA256(chain, secret), then as DeriveKey
//	          under PRK with purpose mix
//	        Agree: Z = X25519(priv, pub), PRK = HMAC-SHA256(th, Z), then as DeriveKey under
//	          PRK with purpose agree
//	gost    th: Streebog-256 over T, in the byte order of RFC 6986
//	        DeriveKey(K, purpose, th, n) = HMAC-Streebog256(K, 01 || label || 00 || th || 01 00)[:n]
//	        MixKey(chain, secret, th) = HMAC-Streebog256(chain, 01 || label || 00 || th || secret || 01 00)
//	        Agree: UKM = th[0:8] little endian, KEK = VKO_GOSTR3410_2012_256(priv, pub, UKM),
//	          then as DeriveKey under KEK with purpose agree
//
// The c25519 values were computed with Python hashlib and hmac. The GOST values
// come from a second implementation written from the standards (Streebog, HMAC,
// VKO in affine coordinates) that first reproduced RFC 6986 M1, the KDF example
// of R 50.1.113-2016 and VKO of RFC 7836 A.1. No standard publishes a VKO
// example on the 256-bit paramSetA, so the primitives are held by the standard
// vectors in crypto/gost and these vectors pin the composition.
type goldenSuite struct {
	pubSize int
	th      [3]string
	derive  []goldenDerive
	mix     string
	agree   goldenAgree
}

type goldenDerive struct {
	ctx     int
	purpose string
	size    int
	want    string
}

// context: setup with 02, 00, link id 200, onion key = pubB, ephemeral = pubA
type goldenAgree struct {
	privA, pubA string
	privB, pubB string
	th          string
	secret      string
	setupKey    string
}

var golden = map[jcrypto.Suite]goldenSuite{
	jcrypto.SuiteC25519: {
		pubSize: 32,
		th: [3]string{
			"bf5988647af2c8b161b8992b8015c2bea0aed5837cc53e37b60450f5fc43aeb7",
			"70b1a866bbce04b1e398435c381fe1cb1e9160a8d7e54a86efe2763c51353fd1",
			"412a81d7b53b40da47fab9eade99cd91d6b4c56b40d2a2d7e0c5d85a88fb9381",
		},
		derive: []goldenDerive{
			{0, "setup", 32, "bbdb94e3db59eb24395f61014dd755ca9c42c4fad7744b70f74818fbb063cf72"},
			{0, "cell", 32, "53c25931ed7343bc6b7863ee8b0dcb2092bdf345c173f9af84e1ed9673c28c2d"},
			{0, "setup/replay", 16, "39131933108b87d63360f0a508b0c163"},
			{0, "counter/fwd", 8, "bdeca6ae015c8e00"},
			{0, "counter/bwd", 8, "29b99d95ce52c6cc"},
			{1, "link/i2r", 32, "cb4c6f2fd373b45125177550d5a0346ee485d6ff0b40e0c416085bfadb4e2f56"},
			{1, "link/r2i", 32, "13a0e7369e8b5a94789d6c026d4141ee94df3a5d0876554018a12c5fcff171bd"},
			{2, "link/i2r", 32, "ead3c39eaf9538eff5d8eaf7cba03de331ab76aa8eaa1c5f49c5acf15c93878f"},
			{2, "link/r2i", 32, "d7bd715509b70ea6aebed17bc9c4aa6dfa71912d4016be09c344eed12649b4f2"},
		},
		mix: "5c607126ffc60f41031bb890ad1690aac86a11950e034fff1c13a461eefc7986",
		// the keys of RFC 7748, 6.1, whose shared secret
		// Z = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
		// is published there, so no curve arithmetic is needed to recompute:
		// PRK = HMAC-SHA256(th, Z) =
		// ed81c394df51741baeedcf9854644eb6194cc74841f878c6ef1bfc3a7e061019
		agree: goldenAgree{
			privA:    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			pubA:     "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
			privB:    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			pubB:     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			th:       "2b69213d29f83bb7d5462cf15a8d6fe210293961f064da936e3e659477d96eb3",
			secret:   "870bde20fe244bf87732677687c31b9c89a245b9fe102471babcfc7123dddd15",
			setupKey: "0a0d88469644b07cd9797e2eef6c2efcde74cc78964d74940ff7e77656772e02",
		},
	},
	jcrypto.SuiteGOST: {
		pubSize: 64,
		th: [3]string{
			"89a0d93bcff53a1914892c6fdf5b8cad7a726f6678cb09c01d91aa532a2b5f1c",
			"27f9517518d0f810964dc8caa1f85fd088216ec3a1b4140482a27ea8f1339ce0",
			"9d44cf104c23a21dc4d25daf8383d800307304309eea1ee7b651d2c00da3afe2",
		},
		derive: []goldenDerive{
			{0, "setup", 32, "e79642ec159e3952d9f73857e904c805e34c77aeafbc861966c174c7243e3925"},
			{0, "cell", 32, "8610ecb34c90a4a7107f4572268da52bea9e39504426c7ca963f3449ae11cd66"},
			{0, "setup/replay", 16, "f55b60a5c251ada92ee3c75356bedc4e"},
			{0, "counter/fwd", 8, "2f610511654c3e3a"},
			{0, "counter/bwd", 8, "bf3555cb42b9c5ed"},
			{1, "link/i2r", 32, "bd1e75680c071be9a5f8e676bf26bfb86c2015252544d040c9c2624e32cee6b9"},
			{1, "link/r2i", 32, "ff23986d951a4ea71f3478c82497295e84ef82386a230b2e0fbdda3dba1caf9b"},
			{2, "link/i2r", 32, "580774a14697a2bf809b813ec8913c722f61689f6744041f88732c1c8fa68eba"},
			{2, "link/r2i", 32, "156bb92d584bca80759e34b4cc815e94e97f6414c484d35509be9960e5e7efd7"},
		},
		mix: "76407e65b18e593b841a48d07c4dbe53f7d4efe3a1826bbf0720ac1d41c3a829",
		// private keys 01..20 and 11..30 as little-endian scalars, both below q;
		// UKM = 28381a1c9c8e2531 (th[0:8]),
		// KEK = e50506395189f57d28577d26b265f204e048cb78976dd3bee1fbe7098d75ca94;
		// after the KEK everything is one HMAC
		agree: goldenAgree{
			privA: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			pubA: "000ad8811b8280e56a2c9b37b7170a3de04039df9151482097e3cc0669ecb7a0" +
				"623f29508cc68b124c3d15a4e2a26e3e71dc391fb2c62d558071878e6814f9a3",
			privB: "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
			pubB: "b6749ce1d202dd4550a1ad7a8797e16e47cfdb0a0b446465e447f56abb4dae1b" +
				"43cad001b96e51d4f10df16549327c9eea30e0a74adf0ce5a01c5934ec52edc6",
			th:       "28381a1c9c8e25317741bfb03e9d4748c573c6d2750e97df93da1a936c513ce7",
			secret:   "5c5fec204c5e66ce9b4286dca04128aded5d48a3e42be031edda68e3e8ee8ae0",
			setupKey: "7e9d78151bab2b2fd46d348e3a08aeba7a9aacfc406b301fb05b1220d833babb",
		},
	},
}

func goldenFor(t *testing.T, p jcrypto.CryptoProvider) goldenSuite {
	t.Helper()
	g, ok := golden[p.Suite()]
	if !ok {
		t.Fatalf("no golden vectors listed for suite %v", p.Suite())
	}
	return g
}

func goldenContexts(t *testing.T, p jcrypto.CryptoProvider) [3]jcrypto.Context {
	t.Helper()
	n := goldenFor(t, p).pubSize
	return [3]jcrypto.Context{
		mustContext(t, p, "setup", []byte{0x02}, []byte{0x00}, []byte{0, 0, 0, 0, 0, 0, 0, 200}, seq(0x80, n), seq(0x00, n)),
		mustContext(t, p, "link", []byte{0x02}, []byte{0x01}, seq(0x00, n), seq(0x40, n), seq(0x80, n)),
		mustContext(t, p, "link", []byte{0x02}, []byte{0x00}, seq(0x00, n), seq(0x40, n)),
	}
}

func testGoldenTranscript(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	_, pub := mustEphemeral(t, p)
	if len(pub) != g.pubSize {
		t.Fatalf("public key of %d bytes, the vectors assume %d", len(pub), g.pubSize)
	}
	for i, ctx := range goldenContexts(t, p) {
		if got := hex.EncodeToString(ctx.Sum()); got != g.th[i] {
			t.Fatalf("th(G%d) = %s, want %s", i+1, got, g.th[i])
		}
	}
}

func testGoldenDeriveKey(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	ctxs := goldenContexts(t, p)
	k := fixedSecret(t, 0x40, 32)
	defer k.Release()
	for _, d := range g.derive {
		got := hex.EncodeToString(mustDerive(t, p, k, d.purpose, ctxs[d.ctx], d.size))
		if got != d.want {
			t.Fatalf("DeriveKey(K, %s, G%d, %d) = %s, want %s", d.purpose, d.ctx+1, d.size, got, d.want)
		}
	}
}

func testGoldenMixKey(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p)
	chain := fixedSecret(t, 0x40, 32)
	defer chain.Release()
	secret := fixedSecret(t, 0x60, 32)
	defer secret.Release()
	got := hex.EncodeToString(mustMix(t, p, chain, secret, goldenContexts(t, p)[1]))
	if got != g.mix {
		t.Fatalf("MixKey(K, 60..7f, G2) = %s, want %s", got, g.mix)
	}
}

func testGoldenAgree(t *testing.T, p jcrypto.CryptoProvider) {
	g := goldenFor(t, p).agree
	pubA, pubB := unhex(t, g.pubA), unhex(t, g.pubB)
	ctx := mustContext(t, p, "setup", []byte{0x02}, []byte{0x00}, []byte{0, 0, 0, 0, 0, 0, 0, 200}, pubB, pubA)
	if got := hex.EncodeToString(ctx.Sum()); got != g.th {
		t.Fatalf("th = %s, want %s", got, g.th)
	}

	for _, side := range []struct {
		name string
		priv string
		pub  []byte
	}{
		{"Agree(a, B)", g.privA, pubB},
		{"Agree(b, A)", g.privB, pubA},
	} {
		priv, err := secmem.NewFrom(unhex(t, side.priv))
		if err != nil {
			t.Fatal(err)
		}
		secret, err := p.Agree(priv, side.pub, ctx)
		priv.Release()
		if err != nil {
			t.Fatalf("%s: %v", side.name, err)
		}
		if got := hex.EncodeToString(secret.Bytes()); got != g.secret {
			secret.Release()
			t.Fatalf("%s = %s, want %s", side.name, got, g.secret)
		}
		got := hex.EncodeToString(mustDerive(t, p, secret, "setup", ctx, 32))
		secret.Release()
		if got != g.setupKey {
			t.Fatalf("DeriveKey(%s, setup) = %s, want %s", side.name, got, g.setupKey)
		}
	}
}

// reports the other suite, so a context built through it carries a suite the
// provider under test must refuse
type otherSuite struct{ jcrypto.CryptoProvider }

func (o otherSuite) Suite() jcrypto.Suite {
	if o.CryptoProvider.Suite() == jcrypto.SuiteGOST {
		return jcrypto.SuiteC25519
	}
	return jcrypto.SuiteGOST
}

func foreignContext(t *testing.T, p jcrypto.CryptoProvider) jcrypto.Context {
	t.Helper()
	return mustContext(t, otherSuite{p}, "test", []byte("session-1"))
}

func mustContext(t *testing.T, p jcrypto.CryptoProvider, exchange string, parts ...[]byte) jcrypto.Context {
	t.Helper()
	ctx, err := jcrypto.NewContext(p, exchange, parts...)
	if err != nil {
		t.Fatalf("NewContext(%s): %v", exchange, err)
	}
	return ctx
}

func mustDerive(t *testing.T, p jcrypto.CryptoProvider, secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) []byte {
	t.Helper()
	key, err := p.DeriveKey(secret, purpose, ctx, size)
	if err != nil {
		t.Fatalf("DeriveKey(%s, %d): %v", purpose, size, err)
	}
	defer key.Release()
	return bytes.Clone(key.Bytes())
}

func mustMix(t *testing.T, p jcrypto.CryptoProvider, chain, secret *secmem.Buffer, ctx jcrypto.Context) []byte {
	t.Helper()
	key, err := p.MixKey(chain, secret, ctx)
	if err != nil {
		t.Fatalf("MixKey: %v", err)
	}
	defer key.Release()
	return bytes.Clone(key.Bytes())
}

func fixedSecret(t *testing.T, first byte, n int) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom(seq(first, n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func drop(b *secmem.Buffer) {
	if b != nil {
		b.Release()
	}
}

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func clone(parts [][]byte) [][]byte {
	out := make([][]byte, len(parts))
	for i := range parts {
		out[i] = bytes.Clone(parts[i])
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
