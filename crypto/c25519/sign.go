package c25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// RFC 8032, section 5.1.6, over the key where it lies. crypto/ed25519 since Go
// 1.25 caches the expanded key in a map keyed by a weak pointer to the key: on
// mmap memory the runtime aborts, and on the heap the expanded key outlives the
// call until the garbage collector gets to it
func sign(priv, msg []byte) []byte {
	seed, pub := priv[:ed25519.SeedSize], priv[ed25519.SeedSize:]

	h := sha512.Sum512(seed)
	defer clear(h[:])
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("c25519: clamping a 32-byte scalar cannot fail")
	}
	defer zeroScalar(s)

	var digest [sha512.Size]byte
	defer clear(digest[:])

	d := sha512.New()
	d.Write(h[32:])
	d.Write(msg)
	r, err := edwards25519.NewScalar().SetUniformBytes(d.Sum(digest[:0]))
	if err != nil {
		panic("c25519: a 64-byte digest is always uniform")
	}
	defer zeroScalar(r)
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()

	d.Reset()
	d.Write(R)
	d.Write(pub)
	d.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(d.Sum(digest[:0]))
	if err != nil {
		panic("c25519: a 64-byte digest is always uniform")
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)
	sig := make([]byte, 0, ed25519.SignatureSize)
	return append(append(sig, R...), S.Bytes()...)
}

// RFC 8032, section 5.1.5: crypto/ed25519.GenerateKey would leave the seed and
// the expanded key on the heap, while the node identity key lives as long as
// the process
func publicKey(seed []byte) []byte {
	h := sha512.Sum512(seed)
	defer clear(h[:])
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("c25519: clamping a 32-byte scalar cannot fail")
	}
	defer zeroScalar(s)
	return new(edwards25519.Point).ScalarBaseMult(s).Bytes()
}

// crypto/ed25519 verifies without the cofactor and takes any point as a key: under
// a key of small order R = [S]B signs every message, so such keys are refused, and
// so is a second encoding of a point, which would give one key two spellings
func validPublicKey(pub []byte) bool {
	a, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil || !bytes.Equal(a.Bytes(), pub) {
		return false
	}
	return new(edwards25519.Point).MultByCofactor(a).Equal(edwards25519.NewIdentityPoint()) == 0
}

func zeroScalar(s *edwards25519.Scalar) { s.Set(edwards25519.NewScalar()) }
