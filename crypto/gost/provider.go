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
	// MGM takes a nonce of one Kuznyechik block
	nonceSize = 16
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

// rejection sampling keeps the scalar exactly uniform below q; with q just
// above 2^254 about one draw in four is kept
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
	// the library hashes the shared point into the front of the same array, so
	// the tail still holds half of it
	defer secmem.Zero(kek[:cap(kek)])

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

	kek, err := prv.KEK2012256(pub, vkoFactor(ukm))
	if err != nil {
		return nil, fmt.Errorf("gost: vko: %w", err)
	}
	return kek, nil
}

// RFC 7836 takes a 64-bit UKM; a longer one, such as the link handshake's
// public key, would turn the factor into a 512-bit number and double the cost,
// so it is hashed down first. The full value still seeds the KDF
func vkoFactor(ukm []byte) *big.Int {
	short := ukm
	if len(short) > 8 {
		short = streebog(ukm)[:8]
	}
	u := gost3410.NewUKM(short)
	// RFC 7836 replaces a zero factor by one
	if u.Sign() == 0 {
		u.SetInt64(1)
	}
	return u
}

// an off-curve point would let a peer run the static key through a weaker
// curve and learn it piece by piece; a point of order 2 or 4 would make the
// shared point degenerate, and the library computes on it without complaint
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
	// in Weierstrass form a point of order 2 has y = 0, and one of order 4
	// doubles to such a point; together they are the whole 4-torsion
	if pub.Y.Sign() == 0 {
		return nil, jcrypto.ErrBadPublicKey
	}
	_, y2, err := c.Exp(big.NewInt(2), pub.X, pub.Y)
	if err != nil || y2.Sign() == 0 {
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
	block := gost3412128.NewCipher(key.Bytes())
	inner, err := mgm.NewMGM(block, tagSize)
	if err != nil {
		return nil, fmt.Errorf("gost: new aead: %w", err)
	}
	return &aead{inner: inner, block: block}, nil
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
	// the digest goes in in gogost's byte order; nothing outside this system
	// verifies these signatures, so interoperability is not claimed
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
	if secmem.CurrentPolicy().Zero {
		clear(k.Bits())
	}
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

// gogost's MGM keeps per-call state in the struct, while a relay seals and
// opens with one hop key from several goroutines; the lock makes it safe
type aead struct {
	mu    sync.Mutex
	inner cipher.AEAD
	// the round keys, the first two of them the key itself; kept so Destroy can
	// clear them, which the library has no call for
	block *gost3412128.Cipher
}

func (a *aead) NonceSize() int { return nonceSize }
func (a *aead) Overhead() int  { return tagSize }

func (a *aead) Seal(dst, nonce, plaintext, ad []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inner.Seal(dst, nonce, plaintext, ad)
}

// MGM panics on a nonce with the top bit set or a short input; wire never
// builds such a nonce, and an open must fail rather than take the node down
func (a *aead) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if !a.nonceOK(nonce) || len(ciphertext) < tagSize {
		return nil, jcrypto.ErrOpen
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out, err := a.inner.Open(dst, nonce, ciphertext, ad)
	if err != nil {
		return nil, jcrypto.ErrOpen
	}
	return out, nil
}

func (a *aead) nonceOK(nonce []byte) bool {
	return len(nonce) == nonceSize && nonce[0]&0x80 == 0
}

func (a *aead) Destroy() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.block != nil && secmem.CurrentPolicy().Zero {
		*a.block = gost3412128.Cipher{}
	}
	a.block, a.inner = nil, nil
}
