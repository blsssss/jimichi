package pki

import (
	"bytes"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

type Descriptor struct {
	Suite     jcrypto.Suite
	Epoch     uint32
	Published int64
	Expires   int64
	CertHash  [HashSize]byte
	LinkPub   []byte
	OnionPub  []byte
	Sig       []byte
}

func (d *Descriptor) body() []byte {
	var w writer
	w.header(d.Suite)
	w.u32(d.Epoch)
	w.i64(d.Published)
	w.i64(d.Expires)
	w.raw(d.CertHash[:])
	w.field(d.LinkPub)
	w.field(d.OnionPub)
	return w.b
}

func (d *Descriptor) Marshal() []byte {
	w := writer{b: d.body()}
	w.field(d.Sig)
	return w.b
}

func ParseDescriptor(b []byte) (*Descriptor, error) {
	r := reader{b: b}
	s, err := r.header()
	if err != nil {
		return nil, err
	}
	d := &Descriptor{Suite: s}
	d.Epoch = r.u32()
	d.Published = r.i64()
	d.Expires = r.i64()
	r.fixed(d.CertHash[:])
	d.LinkPub = r.field(1, maxKey)
	d.OnionPub = r.field(1, maxKey)
	d.Sig = r.field(0, maxSig)
	if err := r.end(); err != nil {
		return nil, err
	}
	if !bytes.Equal(d.Marshal(), b) {
		return nil, ErrFormat
	}
	return d, nil
}
