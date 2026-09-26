package gost

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/pedroalbanese/gogost/gost3410"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/providertest"
	"github.com/blsssss/jimichi/crypto/secmem"
)

func TestProviderConformance(t *testing.T) {
	providertest.Run(t, func() jcrypto.CryptoProvider { return New() })
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 7836 appendix A.1: VKO GOST R 34.10-2012 with the 256-bit output, on the
// 512-bit paramSetA curve the example uses. Both sides must reach the same KEK
func TestVKOKnownAnswer(t *testing.T) {
	c := gost3410.CurveIdtc26gost341012512paramSetA()
	ukm := unhex(t, "1d80603c8544c727")
	prvA := unhex(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubA := unhex(t, "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	prvB := unhex(t, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	pubB := unhex(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	want := unhex(t, "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")

	kekA, err := vko(c, prvA, pubB, ukm)
	if err != nil {
		t.Fatalf("vko A: %v", err)
	}
	kekB, err := vko(c, prvB, pubA, ukm)
	if err != nil {
		t.Fatalf("vko B: %v", err)
	}
	if !bytes.Equal(kekA, want) || !bytes.Equal(kekB, want) {
		t.Fatalf("KEK %x / %x, want %x", kekA, kekB, want)
	}
}

// R 50.1.113-2016, 4.4: KDF_GOSTR3411_2012_256 with key 00..1f, label
// 26bdb878 and seed af21434145656378
func TestKDFKnownAnswer(t *testing.T) {
	key := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	got := make([]byte, 32)
	derive(got, key, unhex(t, "26bdb878"), unhex(t, "af21434145656378"))
	want := unhex(t, "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
	if !bytes.Equal(got, want) {
		t.Fatalf("KDF %x, want %x", got, want)
	}
}

// RFC 9058 appendix A.1: Kuznyechik in MGM, through the provider's AEAD so the
// nonce, tag size and output layout are the ones wire gets
func TestMGMKnownAnswer(t *testing.T) {
	key, err := secmem.NewFrom(unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Release()
	a, err := New().NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	defer a.Destroy()

	ad := unhex(t, "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505")
	pt := unhex(t, "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc")
	want := unhex(t, "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552"+
		"cf5d656f40c34f5c46e8bb0e29fcdb4c")
	nonce := pt[:16]

	if a.NonceSize() != 16 || a.Overhead() != 16 {
		t.Fatalf("nonce %d, overhead %d; want 16 and 16", a.NonceSize(), a.Overhead())
	}
	sealed := a.Seal(nil, nonce, pt, ad)
	if !bytes.Equal(sealed, want) {
		t.Fatalf("sealed %x\nwant   %x", sealed, want)
	}
	opened, err := a.Open(nil, nonce, sealed, ad)
	if err != nil || !bytes.Equal(opened, pt) {
		t.Fatalf("Open: %v", err)
	}
}

// RFC 6986 section 10.1: Streebog-256 of M1, "0123456789" six times and "012"
func TestStreebogKnownAnswer(t *testing.T) {
	m1 := []byte(strings.Repeat("0123456789", 6) + "012")
	want := unhex(t, "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")
	if got := New().Hash(m1); !bytes.Equal(got, want) {
		t.Fatalf("Streebog-256 %x, want %x", got, want)
	}
}

// a point off the curve must be refused before the static key touches it
func TestOffCurvePointIsRefused(t *testing.T) {
	p := New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()

	bad := bytes.Clone(pub)
	bad[0] ^= 0x01
	if _, err := p.Agree(priv, bad, []byte("ukm")); !errors.Is(err, jcrypto.ErrBadPublicKey) {
		t.Fatalf("Agree with an off-curve point: %v, want ErrBadPublicKey", err)
	}
	if p.Verify(bad, []byte("m"), make([]byte, 64)) {
		t.Fatal("Verify accepted an off-curve key")
	}

	tooBig := bytes.Repeat([]byte{0xff}, len(pub))
	if _, err := p.Agree(priv, tooBig, []byte("ukm")); !errors.Is(err, jcrypto.ErrBadPublicKey) {
		t.Fatalf("Agree with coordinates above p: %v, want ErrBadPublicKey", err)
	}
}

// the scalar must be a valid key below q and the public key 64 bytes, which is
// what the setup layer budget in wire is sized for
func TestKeysHaveTheExpectedShape(t *testing.T) {
	c := curve()
	for i := 0; i < 16; i++ {
		priv, pub, err := New().GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		k := littleEndian(priv.Bytes())
		if k.Sign() <= 0 || k.Cmp(c.Q) >= 0 || len(pub) != 64 {
			t.Fatalf("scalar out of range or public key of %d bytes", len(pub))
		}
		priv.Release()
	}
}

func TestDeriveKeyRefusesMoreThanOneBlock(t *testing.T) {
	secret, err := secmem.NewFrom(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Release()
	if _, err := New().DeriveKey(secret, []byte("x"), 33); err == nil {
		t.Fatal("DeriveKey accepted 33 bytes")
	}
	short, err := New().DeriveKey(secret, []byte("x"), 16)
	if err != nil {
		t.Fatal(err)
	}
	full, err := New().DeriveKey(secret, []byte("x"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(short.Bytes(), full.Bytes()[:16]) {
		t.Fatal("a shorter key must be the prefix of the full block")
	}
	short.Release()
	full.Release()
}
