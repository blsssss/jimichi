package crypto

import (
	"errors"
	"strings"
)

const (
	ContextSize = 32

	// changes with any change to the transcript layout, to the derivation
	// formulas or to the name or size of an existing purpose; a new purpose
	// leaves it as it is
	labelPrefix = "jimichi/v1/"

	maxNameSize  = 32
	maxParts     = 255
	maxPartSize  = 65535
	transcriptNS = "transcript/"
)

var (
	ErrBadLabel   = errors.New("crypto: bad label")
	ErrBadContext = errors.New("crypto: bad context")
)

// names reserved to the providers: a caller that could derive under them would
// reproduce the output of Agree, MixKey or the transcript prefix
var reservedPurposes = []string{"agree", "mix"}

// "jimichi/v1/<suite>/<purpose>": no zero byte, so a provider can put one
// after it as a separator
func Label(s Suite, purpose string) ([]byte, error) {
	if !knownSuite(s) || !validName(purpose) {
		return nil, ErrBadLabel
	}
	return []byte(labelPrefix + s.String() + "/" + purpose), nil
}

// Label for DeriveKey: it also refuses the reserved purposes
func DeriveLabel(s Suite, purpose string) ([]byte, error) {
	for _, r := range reservedPurposes {
		if purpose == r {
			return nil, ErrBadLabel
		}
	}
	if strings.HasPrefix(purpose, transcriptNS) {
		return nil, ErrBadLabel
	}
	return Label(s, purpose)
}

func knownSuite(s Suite) bool {
	return s == SuiteGOST || s == SuiteC25519
}

// [a-z0-9]+(/[a-z0-9]+)*, at most maxNameSize bytes
func validName(name string) bool {
	if len(name) == 0 || len(name) > maxNameSize {
		return false
	}
	prev := byte('/')
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '/' && prev != '/':
		default:
			return false
		}
		prev = c
	}
	return prev != '/'
}

// the hash of one exchange's transcript under one suite; every key derivation
// takes one, and the providers refuse the zero value
type Context struct {
	suite Suite
	sum   [ContextSize]byte
	set   bool
}

// the parts are copied into the transcript and hashed at once, so a part that
// aliases a cell body cannot change between two derivations
func NewContext(p CryptoProvider, exchange string, parts ...[]byte) (Context, error) {
	if p == nil {
		return Context{}, ErrBadContext
	}
	t, err := TranscriptBytes(p.Suite(), exchange, parts...)
	if err != nil {
		return Context{}, err
	}
	sum := p.Hash(t)
	if len(sum) != ContextSize {
		return Context{}, ErrBadContext
	}
	c := Context{suite: p.Suite(), set: true}
	copy(c.sum[:], sum)
	return c, nil
}

// a copy; public, and usable as a channel binding
func (c Context) Sum() []byte {
	out := make([]byte, ContextSize)
	copy(out, c.sum[:])
	return out
}

func (c Context) Suite() Suite { return c.suite }

func (c Context) Valid() bool { return c.set && knownSuite(c.suite) }

// the byte string NewContext hashes:
//
//	"jimichi/v1/<suite>/transcript/<exchange>" || 00 || u8(n) || n times (u16be(len) || part)
//
// the head has no zero byte, so with the separator, the count and the lengths
// the encoding is injective
func TranscriptBytes(s Suite, exchange string, parts ...[]byte) ([]byte, error) {
	if !knownSuite(s) {
		return nil, ErrBadContext
	}
	if !validName(exchange) {
		return nil, ErrBadLabel
	}
	if len(parts) == 0 || len(parts) > maxParts {
		return nil, ErrBadContext
	}
	head := labelPrefix + s.String() + "/" + transcriptNS + exchange
	size := len(head) + 2
	for _, part := range parts {
		if len(part) == 0 || len(part) > maxPartSize {
			return nil, ErrBadContext
		}
		size += 2 + len(part)
	}
	t := make([]byte, 0, size)
	t = append(t, head...)
	t = append(t, 0x00, byte(len(parts)))
	for _, part := range parts {
		t = append(t, byte(len(part)>>8), byte(len(part)))
		t = append(t, part...)
	}
	return t, nil
}
