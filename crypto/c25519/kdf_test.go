package c25519_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func mac(key []byte, msg ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, m := range msg {
		h.Write(m)
	}
	return h.Sum(nil)
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func secret(t *testing.T, first byte) *secmem.Buffer {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = first + byte(i)
	}
	b, err := secmem.NewFrom(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func context(t *testing.T, parts ...[]byte) jcrypto.Context {
	t.Helper()
	ctx, err := jcrypto.NewContext(c25519.New(), "test", parts...)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// the three operations written out as plain HMAC-SHA-256 calls (RFC 5869, 2.2
// and 2.3 with one output block), with info = label || 00 || th
func TestKeyScheduleIsHKDF(t *testing.T) {
	p := c25519.New()
	ctx := context(t, []byte("session-1"))
	th := ctx.Sum()
	info := func(purpose string) []byte {
		return append(append([]byte("jimichi/v1/c25519/"+purpose), 0x00), th...)
	}

	// RFC 7748, 6.1: Alice's private key, Bob's public key, their shared secret
	priv, err := secmem.NewFrom(unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	pub := unhex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	z := unhex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	agreed, err := p.Agree(priv, pub, ctx)
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer agreed.Release()
	if want := mac(mac(th, z), info("agree"), []byte{0x01}); !bytes.Equal(agreed.Bytes(), want) {
		t.Fatalf("Agree %x, want %x", agreed.Bytes(), want)
	}

	chain, mixed := secret(t, 0x40), secret(t, 0x60)
	defer chain.Release()
	defer mixed.Release()
	out, err := p.MixKey(chain, mixed, ctx)
	if err != nil {
		t.Fatalf("MixKey: %v", err)
	}
	defer out.Release()
	if want := mac(mac(chain.Bytes(), mixed.Bytes()), info("mix"), []byte{0x01}); !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("MixKey %x, want %x", out.Bytes(), want)
	}

	want := mac(chain.Bytes(), info("setup/replay"), []byte{0x01})
	for _, size := range []int{16, 32} {
		key, err := p.DeriveKey(chain, "setup/replay", ctx, size)
		if err != nil {
			t.Fatalf("DeriveKey(%d): %v", size, err)
		}
		if !bytes.Equal(key.Bytes(), want[:size]) {
			t.Fatalf("DeriveKey(%d) %x, want %x", size, key.Bytes(), want[:size])
		}
		key.Release()
	}
}

// X25519 ignores the top bit of the u-coordinate, so two encodings of one key
// give one shared point; only the transcript tells them apart
func TestAnotherEncodingOfTheKeyChangesTheSecret(t *testing.T) {
	p := c25519.New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	peer, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	peer.Release()
	twin := bytes.Clone(pub)
	twin[31] ^= 0x80

	agree := func(pub []byte, ctx jcrypto.Context) []byte {
		t.Helper()
		s, err := p.Agree(priv, pub, ctx)
		if err != nil {
			t.Fatalf("Agree: %v", err)
		}
		defer s.Release()
		return bytes.Clone(s.Bytes())
	}

	fixed := context(t, []byte("session-1"))
	if !bytes.Equal(agree(pub, fixed), agree(twin, fixed)) {
		t.Fatal("the top bit changed the shared point")
	}
	if bytes.Equal(agree(pub, context(t, pub)), agree(twin, context(t, twin))) {
		t.Fatal("two encodings of one key gave one secret under their own transcripts")
	}
}
