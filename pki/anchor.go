package pki

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

type Anchor struct {
	Suite jcrypto.Suite
	Pub   []byte
}

func ParseAnchor(s string) (Anchor, error) {
	name, enc, ok := strings.Cut(s, ":")
	if !ok {
		return Anchor{}, ErrFormat
	}
	suite, ok := suiteByName(name)
	if !ok {
		return Anchor{}, ErrSuite
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || len(pub) == 0 || len(pub) > maxKey {
		return Anchor{}, ErrFormat
	}
	a := Anchor{Suite: suite, Pub: pub}
	// the decoder skips line breaks, so only a round trip proves the one spelling
	if a.String() != s {
		return Anchor{}, ErrFormat
	}
	return a, nil
}

func (a Anchor) String() string {
	return a.Suite.String() + ":" + base64.StdEncoding.EncodeToString(a.Pub)
}

func (a Anchor) ID(p jcrypto.CryptoProvider) [IDSize]byte { return keyID(p, a.Pub) }

func Fingerprint(p jcrypto.CryptoProvider, pub []byte) string {
	id := keyID(p, pub)
	return hex.EncodeToString(id[:])
}

func keyID(p jcrypto.CryptoProvider, pub []byte) [IDSize]byte {
	var id [IDSize]byte
	copy(id[:], p.Hash(pub))
	return id
}

func suiteByName(name string) (jcrypto.Suite, bool) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		if s.String() == name {
			return s, true
		}
	}
	return 0, false
}

func knownSuite(s jcrypto.Suite) bool {
	_, ok := suiteByName(s.String())
	return ok
}
