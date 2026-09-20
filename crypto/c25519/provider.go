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

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
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

// ukm goes in as the HKDF salt, which gives it the role VKO gives it in the GOST
// suite: two sessions between the same keys never share a secret
func (p *Provider) Agree(priv *secmem.Buffer, peerPub, ukm []byte) (*secmem.Buffer, error) {
	if priv == nil || priv.Len() != privSize {
		return nil, jcrypto.ErrBadKeySize
	}
	if len(peerPub) != pubSize {
		return nil, jcrypto.ErrBadPublicKey
	}

	shared, err := curve25519.X25519(priv.Bytes(), peerPub)
	if err != nil {
		return nil, fmt.Errorf("c25519: x25519: %w", err)
	}
	defer secmem.Zero(shared)

	out, err := secmem.New(keySize)
	if err != nil {
		return nil, err
	}
	kdf := hkdf.New(sha256.New, shared, ukm, []byte("jimichi/agree"))
	if _, err := io.ReadFull(kdf, out.Bytes()); err != nil {
		out.Release()
		return nil, fmt.Errorf("c25519: hkdf: %w", err)
	}
	return out, nil
}

func (p *Provider) DeriveKey(secret *secmem.Buffer, label []byte, size int) (*secmem.Buffer, error) {
	if secret == nil || secret.Len() == 0 {
		return nil, jcrypto.ErrBadKeySize
	}
	if size <= 0 {
		return nil, jcrypto.ErrBadKeySize
	}
	out, err := secmem.New(size)
	if err != nil {
		return nil, err
	}
	kdf := hkdf.Expand(sha256.New, secret.Bytes(), label)
	if _, err := io.ReadFull(kdf, out.Bytes()); err != nil {
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("c25519: generate signing key: %w", err)
	}
	// NewFrom zeroes the heap copy the stdlib handed us
	buf, err := secmem.NewFrom(priv)
	if err != nil {
		return nil, nil, err
	}
	return buf, pub, nil
}

func (p *Provider) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	if priv == nil || priv.Len() != ed25519.PrivateKeySize {
		return nil, jcrypto.ErrBadKeySize
	}
	return ed25519.Sign(ed25519.PrivateKey(priv.Bytes()), msg), nil
}

func (p *Provider) Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
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
