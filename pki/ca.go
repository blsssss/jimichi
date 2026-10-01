package pki

import (
	"bytes"
	"crypto/rand"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type CA struct {
	p      jcrypto.CryptoProvider
	anchor Anchor
	id     [IDSize]byte

	mu   sync.Mutex
	priv *secmem.Buffer
}

func NewCA(p jcrypto.CryptoProvider) (*CA, error) {
	priv, pub, err := p.GenerateSigning()
	if err != nil {
		return nil, err
	}
	a := Anchor{Suite: p.Suite(), Pub: pub}
	return &CA{p: p, anchor: a, id: a.ID(p), priv: priv}, nil
}

func (c *CA) Anchor() Anchor {
	return Anchor{Suite: c.anchor.Suite, Pub: bytes.Clone(c.anchor.Pub)}
}

// the caller runs Check against its nonce and roster first; Issue repeats
// only what needs neither, the format and the proof of possession
func (c *CA) Issue(r *Request, notBefore, notAfter time.Time) (*Cert, error) {
	if r.Suite != c.p.Suite() {
		return nil, ErrSuite
	}
	if !ValidName(r.Name) || !ValidAddr(r.Addr) || len(r.Identity) == 0 || len(r.Identity) > maxKey {
		return nil, ErrFormat
	}
	if err := r.verify(c.p); err != nil {
		return nil, err
	}
	if notAfter.Unix() <= notBefore.Unix() {
		return nil, ErrCertTime
	}
	cert := &Cert{
		Suite:     c.p.Suite(),
		CAID:      c.id,
		NotBefore: notBefore.Unix(),
		NotAfter:  notAfter.Unix(),
		Name:      r.Name,
		Addr:      r.Addr,
		Identity:  bytes.Clone(r.Identity),
	}
	if _, err := rand.Read(cert.Serial[:]); err != nil {
		return nil, err
	}
	sig, err := c.sign(certDomain, cert.body())
	if err != nil {
		return nil, err
	}
	cert.Sig = sig
	return cert, nil
}

func (c *CA) sign(domain string, body []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.priv == nil {
		return nil, secmem.ErrReleased
	}
	return c.p.Sign(c.priv, signed(domain, body))
}

func (c *CA) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.priv != nil {
		c.priv.Release()
		c.priv = nil
	}
}
