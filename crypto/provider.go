package crypto

import (
	"errors"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// both suites implement the same contract, so a run switches between them
// without touching wire or relay
type Suite uint8

const (
	SuiteGOST Suite = iota + 1
	SuiteC25519
)

func (s Suite) String() string {
	switch s {
	case SuiteGOST:
		return "gost"
	case SuiteC25519:
		return "c25519"
	default:
		return "unknown"
	}
}

var (
	ErrBadKeySize   = errors.New("crypto: bad key size")
	ErrOpen         = errors.New("crypto: message authentication failed")
	ErrBadPublicKey = errors.New("crypto: bad public key")
)

// secrets cross this boundary as secmem buffers, never as plain slices, so a
// caller cannot leave key material on the Go heap by accident
type CryptoProvider interface {
	Suite() Suite

	GenerateEphemeral() (priv *secmem.Buffer, pub []byte, err error)

	// ctx binds the secret to the transcript and must match on both sides
	Agree(priv *secmem.Buffer, peerPub []byte, ctx Context) (*secmem.Buffer, error)

	// chains a second agreement onto the first; both are KeySize secrets
	MixKey(chain, secret *secmem.Buffer, ctx Context) (*secmem.Buffer, error)

	// purpose separates keys derived from one secret; the provider builds the
	// label from it, the suite and the scheme version
	DeriveKey(secret *secmem.Buffer, purpose string, ctx Context, size int) (*secmem.Buffer, error)

	KeySize() int

	NewAEAD(key *secmem.Buffer) (AEAD, error)

	GenerateSigning() (priv *secmem.Buffer, pub []byte, err error)
	Sign(priv *secmem.Buffer, msg []byte) ([]byte, error)
	Verify(pub, msg, sig []byte) bool

	Hash(data ...[]byte) []byte
}

// nonce management belongs to the caller: wire assigns one per cell and never
// reuses it under the same key. An AEAD must be safe for concurrent use: a
// relay opens forward and seals backward cells under one hop key at once
type AEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	Destroy()
}
