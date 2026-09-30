package pki

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	// covers a verifier clock behind the signer's; applied to lower bounds only,
	// so no window is ever extended past its end
	Skew              = 2 * time.Minute
	MaxDescriptorLife = 24 * time.Hour
)

var (
	ErrFormat           = errors.New("pki: malformed encoding")
	ErrVersion          = errors.New("pki: unknown format version")
	ErrSuite            = errors.New("pki: suite mismatch")
	ErrUnknownCA        = errors.New("pki: certificate from an unknown CA")
	ErrCertSignature    = errors.New("pki: bad certificate signature")
	ErrCertTime         = errors.New("pki: certificate outside its validity")
	ErrWrongAddr        = errors.New("pki: certificate issued for another address")
	ErrCertMismatch     = errors.New("pki: certificate belongs to another node")
	ErrDescSignature    = errors.New("pki: bad descriptor signature")
	ErrDescTime         = errors.New("pki: descriptor outside its validity")
	ErrKeySize          = errors.New("pki: wrong key size")
	ErrDuplicate        = errors.New("pki: node repeated in the chain")
	ErrNoCert           = errors.New("pki: no certificate installed")
	ErrNonce            = errors.New("pki: request made for another nonce")
	ErrRoster           = errors.New("pki: name or address differs from the roster")
	ErrRequestSignature = errors.New("pki: bad request signature")
)

type Bundle struct {
	V          int    `json:"v"`
	Suite      string `json:"suite"`
	Cert       []byte `json:"cert"`
	Descriptor []byte `json:"descriptor"`
}

type envelope struct {
	V          int    `json:"v"`
	Suite      string `json:"suite"`
	Cert       string `json:"cert"`
	Descriptor string `json:"descriptor"`
}

func (b Bundle) Marshal() []byte {
	out, err := json.Marshal(envelope{
		V:          b.V,
		Suite:      b.Suite,
		Cert:       base64.StdEncoding.EncodeToString(b.Cert),
		Descriptor: base64.StdEncoding.EncodeToString(b.Descriptor),
	})
	if err != nil {
		panic("pki: encoding an int and three strings cannot fail")
	}
	return out
}

func ParseBundle(raw []byte) (*Bundle, error) {
	var e envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, ErrFormat
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrFormat
	}
	if e.V != Version {
		return nil, ErrVersion
	}
	cert, err := decodeField(e.Cert)
	if err != nil {
		return nil, err
	}
	desc, err := decodeField(e.Descriptor)
	if err != nil {
		return nil, err
	}
	return &Bundle{V: e.V, Suite: e.Suite, Cert: cert, Descriptor: desc}, nil
}

func decodeField(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrFormat
	}
	return b, nil
}

type Policy struct {
	Anchor Anchor
	Skew   time.Duration
	// zero means MaxDescriptorLife, and a longer value is cut down to it
	MaxLife time.Duration
}

func (pol Policy) maxLife() time.Duration {
	if pol.MaxLife <= 0 || pol.MaxLife > MaxDescriptorLife {
		return MaxDescriptorLife
	}
	return pol.MaxLife
}

type Verified struct {
	Addr      string
	Name      string
	Identity  []byte
	LinkPub   []byte
	OnionPub  []byte
	Epoch     uint32
	CertUntil time.Time
	DescUntil time.Time
}

// the order is part of the contract: the suite is settled before any key is
// parsed as a curve point, and every step fails with its own sentinel
func Verify(p jcrypto.CryptoProvider, pol Policy, addr string, bundle []byte, now time.Time) (*Verified, error) {
	if pol.Anchor.Suite != p.Suite() {
		return nil, ErrSuite
	}
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	if b.Suite != p.Suite().String() {
		return nil, ErrSuite
	}

	c, err := ParseCert(b.Cert)
	if err != nil {
		return nil, err
	}
	if c.Suite != p.Suite() {
		return nil, ErrSuite
	}
	if c.CAID != pol.Anchor.ID(p) {
		return nil, ErrUnknownCA
	}
	if !p.Verify(pol.Anchor.Pub, signed(certDomain, c.body()), c.Sig) {
		return nil, ErrCertSignature
	}
	skew := max(pol.Skew, 0)
	if err := certWindow(c, now, skew); err != nil {
		return nil, err
	}
	if c.Addr != addr {
		return nil, ErrWrongAddr
	}

	d, err := ParseDescriptor(b.Descriptor)
	if err != nil {
		return nil, err
	}
	if d.Suite != p.Suite() {
		return nil, ErrSuite
	}
	if !bytes.Equal(d.CertHash[:], p.Hash(b.Cert)) {
		return nil, ErrCertMismatch
	}
	if !p.Verify(c.Identity, signed(descriptorDomain, d.body()), d.Sig) {
		return nil, ErrDescSignature
	}
	if err := descWindow(d, c, now, skew, pol.maxLife()); err != nil {
		return nil, err
	}
	if err := keySizes(p, d); err != nil {
		return nil, err
	}
	return &Verified{
		Addr:      c.Addr,
		Name:      c.Name,
		Identity:  c.Identity,
		LinkPub:   d.LinkPub,
		OnionPub:  d.OnionPub,
		Epoch:     d.Epoch,
		CertUntil: time.Unix(c.NotAfter, 0),
		DescUntil: time.Unix(d.Expires, 0),
	}, nil
}

func VerifyChain(p jcrypto.CryptoProvider, pol Policy, addrs []string, bundles [][]byte, now time.Time) ([]Verified, error) {
	return eachNode(addrs, bundles, func(addr string, bundle []byte) (*Verified, error) {
		return Verify(p, pol, addr, bundle, now)
	})
}

// the baseline for measuring what authentication is worth: the same bundles
// read with no signature, time or address checked
func Unverified(p jcrypto.CryptoProvider, addrs []string, bundles [][]byte) ([]Verified, error) {
	return eachNode(addrs, bundles, func(addr string, bundle []byte) (*Verified, error) {
		b, err := ParseBundle(bundle)
		if err != nil {
			return nil, err
		}
		if b.Suite != p.Suite().String() {
			return nil, ErrSuite
		}
		d, err := ParseDescriptor(b.Descriptor)
		if err != nil {
			return nil, err
		}
		if d.Suite != p.Suite() {
			return nil, ErrSuite
		}
		if err := keySizes(p, d); err != nil {
			return nil, err
		}
		return &Verified{Addr: addr, LinkPub: d.LinkPub, OnionPub: d.OnionPub, Epoch: d.Epoch}, nil
	})
}

func eachNode(addrs []string, bundles [][]byte, read func(string, []byte) (*Verified, error)) ([]Verified, error) {
	if len(addrs) != len(bundles) {
		return nil, fmt.Errorf("pki: %d addresses for %d bundles", len(addrs), len(bundles))
	}
	nodes := make([]Verified, len(addrs))
	for i, addr := range addrs {
		v, err := read(addr, bundles[i])
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", addr, err)
		}
		nodes[i] = *v
	}
	for i := range nodes {
		for j := range i {
			a, b := &nodes[j], &nodes[i]
			if a.Addr == b.Addr || bytes.Equal(a.OnionPub, b.OnionPub) ||
				len(a.Identity) > 0 && bytes.Equal(a.Identity, b.Identity) {
				return nil, fmt.Errorf("nodes %s and %s: %w", a.Addr, b.Addr, ErrDuplicate)
			}
		}
	}
	return nodes, nil
}

func certWindow(c *Cert, now time.Time, skew time.Duration) error {
	if now.Add(skew).Unix() < c.NotBefore || now.Unix() >= c.NotAfter {
		return ErrCertTime
	}
	return nil
}

func descWindow(d *Descriptor, c *Cert, now time.Time, skew, maxLife time.Duration) error {
	switch {
	case d.Expires <= d.Published, d.Expires > c.NotAfter:
		return ErrDescTime
	// the difference of two int64 can overflow, the unsigned one cannot once
	// expires is known to be the larger
	case uint64(d.Expires)-uint64(d.Published) > uint64(maxLife/time.Second):
		return ErrDescTime
	case now.Add(skew).Unix() < d.Published, now.Unix() >= d.Expires:
		return ErrDescTime
	}
	return nil
}

func keySizes(p jcrypto.CryptoProvider, d *Descriptor) error {
	size, err := wire.PublicKeySize(p)
	if err != nil {
		return err
	}
	if len(d.LinkPub) != size || len(d.OnionPub) != size {
		return ErrKeySize
	}
	return nil
}
