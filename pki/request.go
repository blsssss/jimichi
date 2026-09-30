package pki

import (
	"bytes"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/wire"
)

type Request struct {
	Suite    jcrypto.Suite
	Nonce    [NonceSize]byte
	Name     string
	Addr     string
	Identity []byte
	Sig      []byte
}

func (r *Request) body() []byte {
	var w writer
	w.header(r.Suite)
	w.raw(r.Nonce[:])
	w.field([]byte(r.Name))
	w.field([]byte(r.Addr))
	w.field(r.Identity)
	return w.b
}

func (r *Request) Marshal() []byte {
	w := writer{b: r.body()}
	w.field(r.Sig)
	return w.b
}

func ParseRequest(b []byte) (*Request, error) {
	r, err := decodeRequest(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Marshal(), b) {
		return nil, ErrFormat
	}
	return r, nil
}

func decodeRequest(b []byte) (*Request, error) {
	rd := reader{b: b}
	s, err := rd.header()
	if err != nil {
		return nil, err
	}
	r := &Request{Suite: s}
	rd.fixed(r.Nonce[:])
	r.Name = string(rd.field(1, maxName))
	r.Addr = string(rd.field(1, wire.AddrSize))
	r.Identity = rd.field(1, maxKey)
	r.Sig = rd.field(0, maxSig)
	if err := rd.end(); err != nil {
		return nil, err
	}
	if !validName(r.Name) || !validAddr(r.Addr) {
		return nil, ErrFormat
	}
	return r, nil
}

// the nonce proves the request was made for this enrollment and not replayed
// from an earlier one; name and address must be what the operator listed
func (r *Request) Check(p jcrypto.CryptoProvider, nonce [NonceSize]byte, name, addr string) error {
	switch {
	case r.Suite != p.Suite():
		return ErrSuite
	case r.Nonce != nonce:
		return ErrNonce
	case r.Name != name || r.Addr != addr:
		return ErrRoster
	}
	return r.verify(p)
}

func (r *Request) verify(p jcrypto.CryptoProvider) error {
	if !p.Verify(r.Identity, signed(requestDomain, r.body()), r.Sig) {
		return ErrRequestSignature
	}
	return nil
}
