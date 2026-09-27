package c25519_test

import (
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/providertest"
)

func TestProviderConformance(t *testing.T) {
	providertest.Run(t, func() jcrypto.CryptoProvider { return c25519.New() })
}
