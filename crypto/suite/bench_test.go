package suite_test

import (
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
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
		ctx := setupContext(b, p, pub)
		for b.Loop() {
			s, err := p.Agree(priv, pub, ctx)
			if err != nil {
				b.Fatal(err)
			}
			s.Release()
		}
	})
}

// the transcript of one hop of a circuit setup: version, hop index, link id,
// onion key, ephemeral key
func setupContext(b *testing.B, p jcrypto.CryptoProvider, pub []byte) jcrypto.Context {
	b.Helper()
	ctx, err := jcrypto.NewContext(p, "setup", []byte{2}, []byte{0}, make([]byte, 8), pub, pub)
	if err != nil {
		b.Fatal(err)
	}
	return ctx
}

func BenchmarkNewContext(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		priv.Release()
		for b.Loop() {
			setupContext(b, p, pub)
		}
	})
}

// what a hop pays after the agreement: the setup key, the cell key, the replay
// tag and the two counter offsets
func BenchmarkDeriveHopKeys(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		ctx := setupContext(b, p, pub)
		secret, err := p.Agree(priv, pub, ctx)
		if err != nil {
			b.Fatal(err)
		}
		defer secret.Release()
		keys := []struct {
			purpose string
			size    int
		}{{"setup", p.KeySize()}, {"cell", p.KeySize()}, {"setup/replay", 16}, {"counter/fwd", 8}, {"counter/bwd", 8}}
		for b.Loop() {
			for _, k := range keys {
				key, err := p.DeriveKey(secret, k.purpose, ctx, k.size)
				if err != nil {
					b.Fatal(err)
				}
				key.Release()
			}
		}
	})
}

// the chaining step of an authenticated link handshake
func BenchmarkMixKey(b *testing.B) {
	each(b, func(b *testing.B, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			b.Fatal(err)
		}
		defer priv.Release()
		ctx := setupContext(b, p, pub)
		secret, err := p.Agree(priv, pub, ctx)
		if err != nil {
			b.Fatal(err)
		}
		defer secret.Release()
		for b.Loop() {
			key, err := p.MixKey(secret, secret, ctx)
			if err != nil {
				b.Fatal(err)
			}
			key.Release()
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
		ctx := setupContext(b, p, pub)
		secret, err := p.Agree(priv, pub, ctx)
		if err != nil {
			b.Fatal(err)
		}
		defer secret.Release()
		key, err := p.DeriveKey(secret, "cell", ctx, p.KeySize())
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
