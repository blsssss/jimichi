// Package suite picks a CryptoProvider by name, so entry points and the
// testbed switch suites by configuration and never import one directly.
package suite

import (
	"fmt"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/crypto/gost"
)

// GOST is the primary suite; c25519 is there to compare against
const Default = jcrypto.SuiteGOST

func Parse(name string) (jcrypto.Suite, error) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		if s.String() == name {
			return s, nil
		}
	}
	return 0, fmt.Errorf("suite: unknown suite %q, want gost or c25519", name)
}

func New(s jcrypto.Suite) (jcrypto.CryptoProvider, error) {
	switch s {
	case jcrypto.SuiteGOST:
		return gost.New(), nil
	case jcrypto.SuiteC25519:
		return c25519.New(), nil
	default:
		return nil, fmt.Errorf("suite: unknown suite %d", s)
	}
}
