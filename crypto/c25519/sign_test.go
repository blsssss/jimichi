package c25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 8032, section 7.1, test 2
func TestSignKnownAnswer(t *testing.T) {
	seed, _ := hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	pub, _ := hex.DecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	want, _ := hex.DecodeString("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
		"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

	got := sign(append(seed, pub...), []byte{0x72})
	if !bytes.Equal(got, want) {
		t.Fatalf("signature\n got %x\nwant %x", got, want)
	}
}

func TestGenerateSigningMatchesStandardLibrary(t *testing.T) {
	p := New()
	for i := 0; i < 32; i++ {
		priv, pub, err := p.GenerateSigning()
		if err != nil {
			t.Fatal(err)
		}
		want := ed25519.NewKeyFromSeed(bytes.Clone(priv.Bytes()[:ed25519.SeedSize]))
		if !bytes.Equal(pub, want.Public().(ed25519.PublicKey)) {
			t.Fatalf("key %d: public key %x, stdlib %x", i, pub, want.Public())
		}
		if !bytes.Equal(priv.Bytes(), want) {
			t.Fatalf("key %d: private key layout differs from stdlib", i)
		}
		msg := make([]byte, i*5)
		_, _ = rand.Read(msg)
		sig, err := p.Sign(priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig, ed25519.Sign(want, msg)) {
			t.Fatalf("key %d: signature differs from stdlib", i)
		}
		priv.Release()
	}
}

func TestSignMatchesStandardLibrary(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, i*7)
		_, _ = rand.Read(msg)

		got := sign(priv, msg)
		if want := ed25519.Sign(priv, msg); !bytes.Equal(got, want) {
			t.Fatalf("message of %d bytes: got %x, want %x", len(msg), got, want)
		}
		if !ed25519.Verify(pub, msg, got) {
			t.Fatalf("message of %d bytes: signature does not verify", len(msg))
		}
	}
}
