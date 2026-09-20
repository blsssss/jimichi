package c25519_test

import (
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/crypto/providertest"
)

func TestProviderConformance(t *testing.T) {
	providertest.Run(t, func() jcrypto.CryptoProvider { return c25519.New() })
}
