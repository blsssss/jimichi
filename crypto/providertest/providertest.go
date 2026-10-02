// Package providertest is the conformance suite every CryptoProvider must pass,
// so a difference between suites shows up here and not in the wire format.
package providertest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func Run(t *testing.T, newProvider func() jcrypto.CryptoProvider) {
	t.Helper()

	t.Run("AgreeMatches", func(t *testing.T) { testAgreeMatches(t, newProvider()) })
	t.Run("AgreeContextSeparates", func(t *testing.T) { testAgreeContext(t, newProvider()) })
	t.Run("AgreeRejectsBadInput", func(t *testing.T) { testAgreeBadInput(t, newProvider()) })
	t.Run("DeriveKeyPurposeSeparates", func(t *testing.T) { testDeriveKey(t, newProvider()) })
	t.Run("DeriveKeyRejectsBadInput", func(t *testing.T) { testDeriveKeyBadInput(t, newProvider()) })
	t.Run("MixKey", func(t *testing.T) { testMixKey(t, newProvider()) })
	t.Run("MixKeyRejectsBadInput", func(t *testing.T) { testMixKeyBadInput(t, newProvider()) })
	t.Run("TranscriptSeparates", func(t *testing.T) { testTranscriptSeparates(t, newProvider()) })
	t.Run("GoldenTranscript", func(t *testing.T) { testGoldenTranscript(t, newProvider()) })
	t.Run("GoldenDeriveKey", func(t *testing.T) { testGoldenDeriveKey(t, newProvider()) })
	t.Run("GoldenMixKey", func(t *testing.T) { testGoldenMixKey(t, newProvider()) })
	t.Run("GoldenAgree", func(t *testing.T) { testGoldenAgree(t, newProvider()) })
	t.Run("AEADRoundTrip", func(t *testing.T) { testAEADRoundTrip(t, newProvider()) })
	t.Run("AEADDetectsTampering", func(t *testing.T) { testAEADTamper(t, newProvider()) })
	t.Run("AEADIsSafeForConcurrentUse", func(t *testing.T) { testAEADConcurrent(t, newProvider()) })
	t.Run("Signatures", func(t *testing.T) { testSignatures(t, newProvider()) })
	t.Run("HashIsStable", func(t *testing.T) { testHash(t, newProvider()) })
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

	otherPriv, otherPub, err := p.GenerateSigning()
	if err != nil {
		t.Fatalf("GenerateSigning: %v", err)
	}
	defer otherPriv.Release()
	otherSig, err := p.Sign(otherPriv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if p.Verify(pub, msg, otherSig) || p.Verify(otherPub, msg, sig) {
		t.Fatal("Verify must reject a signature made by another key")
	}

	for _, bad := range [][]byte{nil, pub[:len(pub)-1], append(bytes.Clone(pub), 0)} {
		if p.Verify(bad, msg, sig) {
			t.Fatalf("Verify must reject a %d-byte public key", len(bad))
		}
	}
	for _, bad := range [][]byte{nil, sig[:len(sig)-1], append(bytes.Clone(sig), 0)} {
		if p.Verify(pub, msg, bad) {
			t.Fatalf("Verify must reject a %d-byte signature", len(bad))
		}
	}

	keys := smallOrderKeys[p.Suite()]
	if len(keys) == 0 {
		t.Fatalf("no small-order keys listed for suite %v", p.Suite())
	}
	for _, h := range keys {
		weak, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range [][]byte{sig, make([]byte, len(sig)), forgedUnderNeutral(len(sig))} {
			if p.Verify(weak, msg, s) {
				t.Fatalf("Verify must reject the small-order key %s", h)
			}
		}
	}
}

// under a key of small order a signature can be made for any message without a
// private key, so Verify must refuse the key before it looks at the signature.
// Ed25519: the neutral point and a point of order 2, 4 and 8. GOST paramSetA:
// the points of order 2 and 4; the neutral point has no affine encoding
var smallOrderKeys = map[jcrypto.Suite][]string{
	jcrypto.SuiteC25519: {
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	},
	jcrypto.SuiteGOST: {
		"aa4aa1e7dc7530a67ec42a195cfe448758d978d4444b978e15ff95f573fe0001" +
			"0000000000000000000000000000000000000000000000000000000000000000",
		"77592f8c11c5e7acc09d6af3d1805dbc5393c3955d5ab43875003505c6807f7f" +
			"cd0e8ea4344fb70642d93fda75821835fbb94ac1180f1daa5f019f0f52827e7e",
		"77592f8c11c5e7acc09d6af3d1805dbc5393c3955d5ab43875003505c6807f7f" +
			"caee715bcbb048f9bd26c0258a7de7ca0446b53ee7f0e255a0fe60f0ad7d8181",
	},
}

// the Ed25519 forgery under the neutral point: R = [0]B encoded, then S = 0
func forgedUnderNeutral(size int) []byte {
	s := make([]byte, size)
	s[0] = 1
	return s
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

	secret, err := p.Agree(aPriv, bPub, mustContext(t, p, "test", []byte("session-1")))
	if err != nil {
		t.Fatalf("Agree: %v", err)
	}
	return secret
}

func mustKey(t *testing.T, p jcrypto.CryptoProvider) *secmem.Buffer {
	t.Helper()
	secret := mustSharedSecret(t, p)
	defer secret.Release()

	key, err := p.DeriveKey(secret, "aead", mustContext(t, p, "test", []byte("session-1")), p.KeySize())
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

// a relay seals backward cells and opens forward ones under one hop key from
// different goroutines; every result must match what one goroutine gets alone
func testAEADConcurrent(t *testing.T, p jcrypto.CryptoProvider) {
	key := mustKey(t, p)
	defer key.Release()
	a, err := p.NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	defer a.Destroy()

	const cells = 32
	nonces := make([][]byte, cells)
	plains := make([][]byte, cells)
	sealed := make([][]byte, cells)
	for i := range nonces {
		nonces[i] = wireNonce(t, a.NonceSize())
		plains[i] = randomBytes(t, 494-a.Overhead())
		sealed[i] = a.Seal(nil, nonces[i], plains[i], []byte{byte(i)})
	}

	var wg sync.WaitGroup
	errs := make(chan string, 8*cells)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < 20; r++ {
				i := (w*7 + r) % cells
				if got := a.Seal(nil, nonces[i], plains[i], []byte{byte(i)}); !bytes.Equal(got, sealed[i]) {
					errs <- "concurrent Seal differs from the sequential result"
					return
				}
				out, err := a.Open(nil, nonces[i], sealed[i], []byte{byte(i)})
				if err != nil || !bytes.Equal(out, plains[i]) {
					errs <- "concurrent Open failed on a genuine cell"
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
