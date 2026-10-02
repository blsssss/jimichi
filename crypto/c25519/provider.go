// Package c25519 implements CryptoProvider over X25519, XChaCha20-Poly1305 and
// Ed25519, as the comparison point for the GOST suite.
package c25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	privSize = curve25519.ScalarSize
	pubSize  = curve25519.PointSize
	keySize  = chacha20poly1305.KeySize
)

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Suite() jcrypto.Suite { return jcrypto.SuiteC25519 }

func (p *Provider) KeySize() int { return keySize }

func (p *Provider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, err := secmem.New(privSize)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, priv.Bytes()); err != nil {
		priv.Release()
		return nil, nil, fmt.Errorf("c25519: read random: %w", err)
	}
	pub, err := curve25519.X25519(priv.Bytes(), curve25519.Basepoint)
	if err != nil {
		priv.Release()
		return nil, nil, fmt.Errorf("c25519: derive public key: %w", err)
	}
	return priv, pub, nil
}

// HKDF-SHA-256 (RFC 5869) with the transcript hash as the extract salt and
// again in the expand info, so the raw X25519 output never leaves this call
func (p *Provider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if priv == nil || priv.Len() != privSize {
		return nil, jcrypto.ErrBadKeySize
	}
	if !p.owns(ctx) {
		return nil, jcrypto.ErrBadContext
	}
	label, err := jcrypto.Label(p.Suite(), "agree")
	if err != nil {
		return nil, err
	}
	if len(peerPub) != pubSize {
		return nil, jcrypto.ErrBadPublicKey
	}

	// with both lengths right the only refusal left is a point of small order,
	// whose shared value is all zeroes
	shared, err := curve25519.X25519(priv.Bytes(), peerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", jcrypto.ErrBadPublicKey, err)
	}
	defer secmem.Zero(shared)

	th := ctx.Sum()
	return extractExpand(th, shared, info(label, th))
}

func (p *Provider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if chain == nil || chain.Len() != keySize || secret == nil || secret.Len() != keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	if !p.owns(ctx) {
		return nil, jcrypto.ErrBadContext
	}
	label, err := jcrypto.Label(p.Suite(), "mix")
	if err != nil {
		return nil, err
	}
	return extractExpand(chain.Bytes(), secret.Bytes(), info(label, ctx.Sum()))
}

func (p *Provider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	if secret == nil || secret.Len() != keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	if size <= 0 || size > keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	if !p.owns(ctx) {
		return nil, jcrypto.ErrBadContext
	}
	label, err := jcrypto.DeriveLabel(p.Suite(), purpose)
	if err != nil {
		return nil, err
	}
	return expand(secret.Bytes(), info(label, ctx.Sum()), size)
}

func (p *Provider) owns(ctx jcrypto.Context) bool {
	return ctx.Valid() && ctx.Suite() == p.Suite()
}

// the label holds no zero byte and the hash has a fixed size, so the split
// between them is unambiguous
func info(label, th []byte) []byte {
	out := make([]byte, 0, len(label)+1+len(th))
	out = append(out, label...)
	out = append(out, 0x00)
	return append(out, th...)
}

func extractExpand(salt, ikm, info []byte) (*secmem.Buffer, error) {
	prk := hkdf.Extract(sha256.New, ikm, salt)
	defer secmem.Zero(prk)
	return expand(prk, info, keySize)
}

func expand(prk, info []byte, size int) (*secmem.Buffer, error) {
	out, err := secmem.New(size)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), out.Bytes()); err != nil {
		out.Release()
		return nil, fmt.Errorf("c25519: hkdf expand: %w", err)
	}
	return out, nil
}

func (p *Provider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	if key == nil || key.Len() != keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	inner, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("c25519: new aead: %w", err)
	}
	return &aead{inner: inner}, nil
}

func (p *Provider) GenerateSigning() (*secmem.Buffer, []byte, error) {
	priv, err := secmem.New(ed25519.PrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	key := priv.Bytes()
	if _, err := io.ReadFull(rand.Reader, key[:ed25519.SeedSize]); err != nil {
		priv.Release()
		return nil, nil, fmt.Errorf("c25519: read random: %w", err)
	}
	pub := publicKey(key[:ed25519.SeedSize])
	copy(key[ed25519.SeedSize:], pub)
	return priv, pub, nil
}

func (p *Provider) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	if priv == nil || priv.Len() != ed25519.PrivateKeySize {
		return nil, jcrypto.ErrBadKeySize
	}
	return sign(priv.Bytes(), msg), nil
}

func (p *Provider) Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || !validPublicKey(pub) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func (p *Provider) Hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

type aead struct {
	inner interface {
		NonceSize() int
		Overhead() int
		Seal(dst, nonce, plaintext, ad []byte) []byte
		Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	}
}

func (a *aead) NonceSize() int { return a.inner.NonceSize() }
func (a *aead) Overhead() int  { return a.inner.Overhead() }

func (a *aead) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return a.inner.Seal(dst, nonce, plaintext, ad)
}

func (a *aead) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	out, err := a.inner.Open(dst, nonce, ciphertext, ad)
	if err != nil {
		return nil, jcrypto.ErrOpen
	}
	return out, nil
}

// chacha20poly1305 keeps its expanded key on the Go heap and offers no wipe, so
// this only drops our reference; recorded in docs/LIMITATIONS.md
func (a *aead) Destroy() { a.inner = nil }
