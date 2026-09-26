package gost

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/mgm"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/secmem"
)

const (
	keySize = 32
	tagSize = 16
)

// tc26 paramSetA: the 256-bit twisted Edwards curve TC26 recommends for new
// protocols; its cofactor of 4 is cleared inside VKO
var curve = sync.OnceValue(gost3410.CurveIdtc26gost341012256paramSetA)

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Suite() jcrypto.Suite { return jcrypto.SuiteGOST }

func (p *Provider) KeySize() int { return keySize }

func (p *Provider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	return generate(curve())
}

func (p *Provider) GenerateSigning() (*secmem.Buffer, []byte, error) {
	return generate(curve())
}

// rejection sampling keeps the scalar uniform below q; reducing a random
// 256-bit value modulo a q near 2^254 would favour the low quarter
func generate(c *gost3410.Curve) (*secmem.Buffer, []byte, error) {
	size := c.PointSize()
	priv, err := secmem.New(size)
	if err != nil {
		return nil, nil, err
	}
	for {
		if _, err := io.ReadFull(rand.Reader, priv.Bytes()); err != nil {
			priv.Release()
			return nil, nil, fmt.Errorf("gost: read random: %w", err)
		}
		k := littleEndian(priv.Bytes())
		ok := k.Sign() > 0 && k.Cmp(c.Q) < 0
		wipe(k)
		if ok {
			break
		}
	}
	prv, err := gost3410.NewPrivateKey(c, priv.Bytes())
	if err != nil {
		priv.Release()
		return nil, nil, fmt.Errorf("gost: private key: %w", err)
	}
	defer wipe(prv.Key)
	pub, err := prv.PublicKey()
	if err != nil {
		priv.Release()
		return nil, nil, fmt.Errorf("gost: public key: %w", err)
	}
	return priv, pub.Raw(), nil
}

// ukm goes in twice: as the VKO factor, which is how the standard binds the
// secret to a session, and as the KDF seed next to the label
func (p *Provider) Agree(priv *secmem.Buffer, peerPub, ukm []byte) (*secmem.Buffer, error) {
	c := curve()
	if priv == nil || priv.Len() != c.PointSize() {
		return nil, jcrypto.ErrBadKeySize
	}
	kek, err := vko(c, priv.Bytes(), peerPub, ukm)
	if err != nil {
		return nil, err
	}
	defer secmem.Zero(kek)

	out, err := secmem.New(keySize)
	if err != nil {
		return nil, err
	}
	derive(out.Bytes(), kek, []byte("jimichi/agree"), ukm)
	return out, nil
}

// VKO GOST R 34.10-2012 with the 256-bit Streebog output (RFC 7836); the peer
// point is checked first, since the library computes on whatever it is given
func vko(c *gost3410.Curve, priv, peerPub, ukm []byte) ([]byte, error) {
	pub, err := publicKey(c, peerPub)
	if err != nil {
		return nil, err
	}
	prv, err := gost3410.NewPrivateKey(c, priv)
	if err != nil {
		return nil, fmt.Errorf("gost: private key: %w", err)
	}
	defer wipe(prv.Key)

	u := gost3410.NewUKM(ukm)
	// RFC 7836 replaces a zero factor by one
	if u.Sign() == 0 {
		u.SetInt64(1)
	}
	kek, err := prv.KEK2012256(pub, u)
	if err != nil {
		return nil, fmt.Errorf("gost: vko: %w", err)
	}
	return kek, nil
}

// an off-curve point would let a peer run the static key through a weaker
// curve and learn it piece by piece
func publicKey(c *gost3410.Curve, raw []byte) (*gost3410.PublicKey, error) {
	if len(raw) != 2*c.PointSize() {
		return nil, jcrypto.ErrBadPublicKey
	}
	pub, err := gost3410.NewPublicKey(c, raw)
	if err != nil {
		return nil, jcrypto.ErrBadPublicKey
	}
	if pub.X.Cmp(c.P) >= 0 || pub.Y.Cmp(c.P) >= 0 || !c.Contains(pub.X, pub.Y) {
		return nil, jcrypto.ErrBadPublicKey
	}
	return pub, nil
}

// KDF_GOSTR3411_2012_256 (R 50.1.113-2016) gives 32 bytes, which is every size
// wire and link ask for
func (p *Provider) DeriveKey(secret *secmem.Buffer, label []byte, size int) (*secmem.Buffer, error) {
	if secret == nil || secret.Len() == 0 {
		return nil, jcrypto.ErrBadKeySize
	}
	if size <= 0 || size > keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	out, err := secmem.New(size)
	if err != nil {
		return nil, err
	}
	var full [keySize]byte
	derive(full[:], secret.Bytes(), label, nil)
	copy(out.Bytes(), full[:size])
	secmem.Zero(full[:])
	return out, nil
}

func derive(dst, key, label, seed []byte) {
	kdf := gost34112012256.NewKDF(key)
	sum := kdf.Derive(nil, label, seed)
	copy(dst, sum)
	secmem.Zero(sum)
}

func (p *Provider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	if key == nil || key.Len() != keySize {
		return nil, jcrypto.ErrBadKeySize
	}
	inner, err := mgm.NewMGM(gost3412128.NewCipher(key.Bytes()), tagSize)
	if err != nil {
		return nil, fmt.Errorf("gost: new aead: %w", err)
	}
	return &aead{inner: inner}, nil
}

func (p *Provider) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	c := curve()
	if priv == nil || priv.Len() != c.PointSize() {
		return nil, jcrypto.ErrBadKeySize
	}
	prv, err := gost3410.NewPrivateKey(c, priv.Bytes())
	if err != nil {
		return nil, fmt.Errorf("gost: private key: %w", err)
	}
	defer wipe(prv.Key)
	sig, err := prv.SignDigest(streebog(msg), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gost: sign: %w", err)
	}
	return sig, nil
}

func (p *Provider) Verify(pub, msg, sig []byte) bool {
	c := curve()
	key, err := publicKey(c, pub)
	if err != nil || len(sig) != 2*c.PointSize() {
		return false
	}
	ok, err := key.VerifyDigest(streebog(msg), sig)
	return err == nil && ok
}

func (p *Provider) Hash(data ...[]byte) []byte {
	h := gost34112012256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func streebog(msg []byte) []byte {
	h := gost34112012256.New()
	h.Write(msg)
	return h.Sum(nil)
}

// big.Int keeps its words after SetInt64, so they are cleared first; copies
// the library made during the computation are out of reach
func wipe(k *big.Int) {
	clear(k.Bits())
	k.SetInt64(0)
}

func littleEndian(raw []byte) *big.Int {
	be := make([]byte, len(raw))
	for i := range raw {
		be[len(raw)-1-i] = raw[i]
	}
	k := new(big.Int).SetBytes(be)
	secmem.Zero(be)
	return k
}

type aead struct {
	inner cipher.AEAD
}

func (a *aead) NonceSize() int { return a.inner.NonceSize() }
func (a *aead) Overhead() int  { return a.inner.Overhead() }

func (a *aead) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return a.inner.Seal(dst, nonce, plaintext, ad)
}

// MGM panics on a nonce with the top bit set or a short input; wire never
// builds such a nonce, and an open must fail rather than take the node down
func (a *aead) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if !a.nonceOK(nonce) || len(ciphertext) < tagSize {
		return nil, jcrypto.ErrOpen
	}
	out, err := a.inner.Open(dst, nonce, ciphertext, ad)
	if err != nil {
		return nil, jcrypto.ErrOpen
	}
	return out, nil
}

func (a *aead) nonceOK(nonce []byte) bool {
	return len(nonce) == a.inner.NonceSize() && nonce[0]&0x80 == 0
}

// the Kuznyechik round keys sit in the library's cipher on the Go heap and have
// no wipe, so this only drops the reference; listed in CRYPTO under known gaps
func (a *aead) Destroy() { a.inner = nil }
