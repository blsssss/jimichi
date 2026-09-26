// Package providertest is the conformance suite every CryptoProvider must pass,
// so a difference between suites shows up here and not in the wire format.
package providertest

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
)

func Run(t *testing.T, newProvider func() jcrypto.CryptoProvider) {
	t.Helper()

	t.Run("AgreeMatches", func(t *testing.T) { testAgreeMatches(t, newProvider()) })
	t.Run("AgreeUKMSeparates", func(t *testing.T) { testAgreeUKM(t, newProvider()) })
	t.Run("AgreeRejectsBadInput", func(t *testing.T) { testAgreeBadInput(t, newProvider()) })
	t.Run("DeriveKeyLabelSeparates", func(t *testing.T) { testDeriveKey(t, newProvider()) })
	t.Run("AEADRoundTrip", func(t *testing.T) { testAEADRoundTrip(t, newProvider()) })
	t.Run("AEADDetectsTampering", func(t *testing.T) { testAEADTamper(t, newProvider()) })
	t.Run("Signatures", func(t *testing.T) { testSignatures(t, newProvider()) })
	t.Run("HashIsStable", func(t *testing.T) { testHash(t, newProvider()) })
}

func testAgreeMatches(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, aPub := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()

	ukm := []byte("session-1")

	aSecret, err := p.Agree(aPriv, bPub, ukm)
	if err != nil {
		t.Fatalf("Agree(a): %v", err)
	}
	defer aSecret.Release()

	bSecret, err := p.Agree(bPriv, aPub, ukm)
	if err != nil {
		t.Fatalf("Agree(b): %v", err)
	}
	defer bSecret.Release()

	if !bytes.Equal(aSecret.Bytes(), bSecret.Bytes()) {
		t.Fatal("both sides must agree on the same secret")
	}
	if allZero(aSecret.Bytes()) {
		t.Fatal("shared secret is all zeroes")
	}
}

func testAgreeUKM(t *testing.T, p jcrypto.CryptoProvider) {
	aPriv, aPub := mustEphemeral(t, p)
	defer aPriv.Release()
	bPriv, bPub := mustEphemeral(t, p)
	defer bPriv.Release()
	_ = aPub

	first, err := p.Agree(aPriv, bPub, []byte("session-1"))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer first.Release()

	second, err := p.Agree(aPriv, bPub, []byte("session-2"))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	defer second.Release()

	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different ukm must produce different secrets")
	}
}

func testAgreeBadInput(t *testing.T, p jcrypto.CryptoProvider) {
	priv, pub := mustEphemeral(t, p)
	defer priv.Release()

	if _, err := p.Agree(nil, pub, nil); err == nil {
		t.Fatal("Agree(nil private key) must fail")
	}
	if _, err := p.Agree(priv, []byte{1, 2, 3}, nil); err == nil {
		t.Fatal("Agree(short public key) must fail")
	}
}

func testDeriveKey(t *testing.T, p jcrypto.CryptoProvider) {
	secret := mustSharedSecret(t, p)
	defer secret.Release()

	forward, err := p.DeriveKey(secret, []byte("forward"), p.KeySize())
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	defer forward.Release()

	backward, err := p.DeriveKey(secret, []byte("backward"), p.KeySize())
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	defer backward.Release()

	if forward.Len() != p.KeySize() {
		t.Fatalf("derived key size = %d, want %d", forward.Len(), p.KeySize())
	}
	if bytes.Equal(forward.Bytes(), backward.Bytes()) {
		t.Fatal("different labels must produce different keys")
	}

	if _, err := p.DeriveKey(secret, []byte("forward"), 0); err == nil {
		t.Fatal("DeriveKey(size 0) must fail")
	}
}

func testAEADRoundTrip(t *testing.T, p jcrypto.CryptoProvider) {
	key := mustKey(t, p)
	defer key.Release()

	a, err := p.NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	defer a.Destroy()

	nonce := wireNonce(t, a.NonceSize())
	plaintext := []byte("cell payload of fixed size")
	ad := []byte("hop-1")

	ciphertext := a.Seal(nil, nonce, plaintext, ad)
	if len(ciphertext) != len(plaintext)+a.Overhead() {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+a.Overhead())
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}

	out, err := a.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("round trip = %q, want %q", out, plaintext)
	}
}

func testAEADTamper(t *testing.T, p jcrypto.CryptoProvider) {
	key := mustKey(t, p)
	defer key.Release()

	a, err := p.NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	defer a.Destroy()

	nonce := wireNonce(t, a.NonceSize())
	ad := []byte("hop-1")
	ciphertext := a.Seal(nil, nonce, []byte("payload"), ad)

	corrupt := bytes.Clone(ciphertext)
	corrupt[0] ^= 0xFF
	if _, err := a.Open(nil, nonce, corrupt, ad); err == nil {
		t.Fatal("Open must reject a modified ciphertext")
	}

	if _, err := a.Open(nil, nonce, ciphertext, []byte("hop-2")); err == nil {
		t.Fatal("Open must reject wrong associated data")
	}

	otherNonce := wireNonce(t, a.NonceSize())
	if _, err := a.Open(nil, otherNonce, ciphertext, ad); err == nil {
		t.Fatal("Open must reject a wrong nonce")
	}

	// wire never builds such a nonce, but an open must fail, not take the node down
	topBit := bytes.Clone(nonce)
	topBit[0] |= 0x80
	if _, err := a.Open(nil, topBit, ciphertext, ad); err == nil {
		t.Fatal("Open must reject a nonce with the top bit set")
	}
}

// the nonce wire builds: random here, but with the top bit clear, as MGM needs
func wireNonce(t *testing.T, size int) []byte {
	n := randomBytes(t, size)
	n[0] &= 0x7f
	return n
}

func testSignatures(t *testing.T, p jcrypto.CryptoProvider) {
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		t.Fatalf("GenerateSigning: %v", err)
	}
	defer priv.Release()

	msg := []byte("node identity statement")
	sig, err := p.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !p.Verify(pub, msg, sig) {
		t.Fatal("Verify must accept a valid signature")
	}
	if p.Verify(pub, []byte("other message"), sig) {
		t.Fatal("Verify must reject another message")
	}

	corrupt := bytes.Clone(sig)
	corrupt[0] ^= 0xFF
	if p.Verify(pub, msg, corrupt) {
		t.Fatal("Verify must reject a modified signature")
	}
}

func testHash(t *testing.T, p jcrypto.CryptoProvider) {
	first := p.Hash([]byte("abc"))
	second := p.Hash([]byte("a"), []byte("bc"))
	if !bytes.Equal(first, second) {
		t.Fatal("Hash must treat split input as one stream")
	}
	if len(first) == 0 {
		t.Fatal("Hash returned nothing")
	}
	if bytes.Equal(first, p.Hash([]byte("abd"))) {
		t.Fatal("Hash collision on trivial input")
	}
}

func mustEphemeral(t *testing.T, p jcrypto.CryptoProvider) (*secmem.Buffer, []byte) {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatalf("GenerateEphemeral: %v", err)
	}
	if len(pub) == 0 {
		t.Fatal("GenerateEphemeral returned an empty public key")
	}
	return priv, pub
}

func mustSharedSecret(t *testing.T, p jcrypto.CryptoProvider) *secmem.Buffer {
	t.Helper()
	aPriv, _ := mustEphemeral(t, p)
	defer aPriv.Release()
	_, bPub := mustEphemeral(t, p)

	secret, err := p.Agree(aPriv, bPub, []byte("ukm"))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	return secret
}

func mustKey(t *testing.T, p jcrypto.CryptoProvider) *secmem.Buffer {
	t.Helper()
	secret := mustSharedSecret(t, p)
	defer secret.Release()

	key, err := p.DeriveKey(secret, []byte("aead"), p.KeySize())
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	return key
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return b
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
