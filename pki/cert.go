package pki

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/wire"
)

const (
	Version    = 1
	SerialSize = 16
	IDSize     = 8
	NonceSize  = 16
	HashSize   = 32

	maxName = 32
	// room for the 512-bit GOST curves, twice the largest key and signature in use
	maxKey = 128
	maxSig = 128
)

// the domain goes into the signed message only, so a signature over one kind of
// object never verifies as another even if the bodies happen to coincide
const (
	certDomain       = "jimichi/cert/v1\x00"
	descriptorDomain = "jimichi/descriptor/v1\x00"
	requestDomain    = "jimichi/csr/v1\x00"
)

type Cert struct {
	Suite     jcrypto.Suite
	Serial    [SerialSize]byte
	CAID      [IDSize]byte
	NotBefore int64
	NotAfter  int64
	Name      string
	Addr      string
	Identity  []byte
	Sig       []byte
}

func (c *Cert) body() []byte {
	var w writer
	w.header(c.Suite)
	w.raw(c.Serial[:])
	w.raw(c.CAID[:])
	w.i64(c.NotBefore)
	w.i64(c.NotAfter)
	w.field([]byte(c.Name))
	w.field([]byte(c.Addr))
	w.field(c.Identity)
	return w.b
}

func (c *Cert) Marshal() []byte {
	w := writer{b: c.body()}
	w.field(c.Sig)
	return w.b
}

func ParseCert(b []byte) (*Cert, error) {
	c, err := decodeCert(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.Marshal(), b) {
		return nil, ErrFormat
	}
	return c, nil
}

func decodeCert(b []byte) (*Cert, error) {
	r := reader{b: b}
	s, err := r.header()
	if err != nil {
		return nil, err
	}
	c := &Cert{Suite: s}
	r.fixed(c.Serial[:])
	r.fixed(c.CAID[:])
	c.NotBefore = r.i64()
	c.NotAfter = r.i64()
	c.Name = string(r.field(1, maxName))
	c.Addr = string(r.field(1, wire.AddrSize))
	c.Identity = r.field(1, maxKey)
	c.Sig = r.field(0, maxSig)
	if err := r.end(); err != nil {
		return nil, err
	}
	if !ValidName(c.Name) || !ValidAddr(c.Addr) {
		return nil, ErrFormat
	}
	return c, nil
}

func signed(domain string, body []byte) []byte {
	return append([]byte(domain), body...)
}

func ValidName(s string) bool {
	if len(s) == 0 || len(s) > maxName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// wire drops trailing NULs from the address field, so an address with a NUL,
// a space or a byte outside ASCII could name one node and reach another
func ValidAddr(s string) bool {
	if len(s) == 0 || len(s) > wire.AddrSize {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	host, port, err := net.SplitHostPort(s)
	return err == nil && validHost(host) && validPort(port)
}

// one spelling per host as well: names in lower case without a trailing dot,
// IP literals in their canonical form
func validHost(h string) bool {
	if h == "" || strings.HasSuffix(h, ".") {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Zone() == "" && ip.String() == h
	}
	return strings.ToLower(h) == h && !strings.Contains(h, ":")
}

// one spelling per port, since the client compares addresses byte for byte
func validPort(s string) bool {
	if len(s) == 0 || len(s) > 5 || s[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n <= 65535
}

type writer struct{ b []byte }

func (w *writer) header(s jcrypto.Suite) { w.b = append(w.b, Version, byte(s)) }
func (w *writer) raw(p []byte)           { w.b = append(w.b, p...) }
func (w *writer) u32(v uint32)           { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) i64(v int64)            { w.b = binary.BigEndian.AppendUint64(w.b, uint64(v)) }
func (w *writer) field(p []byte)         { w.b = append(append(w.b, byte(len(p))), p...) }

// a reader stays failed after the first short or oversized field, so a parser
// reads every field and checks once at the end
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) header() (jcrypto.Suite, error) {
	v, s := r.take(1), r.take(1)
	if r.bad {
		return 0, ErrFormat
	}
	if v[0] != Version {
		return 0, ErrVersion
	}
	if !knownSuite(jcrypto.Suite(s[0])) {
		return 0, ErrSuite
	}
	return jcrypto.Suite(s[0]), nil
}

func (r *reader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) i64() int64 {
	if b := r.take(8); b != nil {
		return int64(binary.BigEndian.Uint64(b))
	}
	return 0
}

func (r *reader) field(minLen, maxLen int) []byte {
	n := r.take(1)
	if r.bad {
		return nil
	}
	if int(n[0]) < minLen || int(n[0]) > maxLen {
		r.bad = true
		return nil
	}
	return bytes.Clone(r.take(int(n[0])))
}

func (r *reader) end() error {
	if r.bad || len(r.b) != 0 {
		return ErrFormat
	}
	return nil
}
