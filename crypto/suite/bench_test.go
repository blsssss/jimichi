package suite_test

import (
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/suite"
)

// the per-suite cost block 6 compares: what a circuit setup and a cell cost
func each(b *testing.B, run func(b *testing.B, p jcrypto.CryptoProvider)) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(s.String(), func(b *testing.B) { run(b, p) })
	}
}

func BenchmarkGenerateEphemeral(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		for b.Loop() {
			priv, _, err := p.GenerateEphemeral()
			if err != nil {
				b.Fatal(err)
			}
			priv.Release()
		}
	})
}

func BenchmarkAgree(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, _, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		peer, pub, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		peer.Release()
		ukm := []byte("circuit1")
		for b.Loop() {
			s, err := p.Agree(priv, pub, ukm)
			if err != nil {
				b.Fatal(err)
			}
			s.Release()
		}
	})
}

// one onion layer of a 512-byte cell: what every relay pays per cell
func BenchmarkSealCell(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		secret, err := p.Agree(priv, pub, []byte("circuit1"))
		if err != nil {
			b.Fatal(err)
		}
		defer secret.Release()
		key, err := p.DeriveKey(secret, []byte("cell"), p.KeySize())
		if err != nil {
			b.Fatal(err)
		}
		defer key.Release()
		a, err := p.NewAEAD(key)
		if err != nil {
			b.Fatal(err)
		}
		defer a.Destroy()
		nonce := make([]byte, a.NonceSize())
		body := make([]byte, 494-a.Overhead())
		b.SetBytes(int64(len(body)))
		for b.Loop() {
			a.Seal(nil, nonce, body, []byte("ad"))
		}
	})
}

func BenchmarkSign(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, _, err := p.GenerateSigning()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		msg := []byte("node descriptor")
		for b.Loop() {
			if _, err := p.Sign(priv, msg); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateSigning()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		msg := []byte("node descriptor")
		sig, err := p.Sign(priv, msg)
		if err != nil {
			b.Fatal(err)
		}
		for b.Loop() {
			if !p.Verify(pub, msg, sig) {
				b.Fatal("signature did not verify")
			}
		}
	})
}
