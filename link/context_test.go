package link

import (
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func seq(from byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = from + byte(i)
	}
	return out
}

// the context the handshake builds, against the hash of the transcript written
// out here with every part as a literal, P being the public key size (32, 64):
//
//	"jimichi/v1/<suite>/transcript/link" || 00 || 05 || 0001 02 || 0001 01
//	  || u16be(P) 00..(P-1) || u16be(P) 40..(40+P-1) || u16be(P) 80..(80+P-1)
//	"jimichi/v1/<suite>/transcript/link" || 00 || 04 || 0001 02 || 0001 00
//	  || u16be(P) 00..(P-1) || u16be(P) 40..(40+P-1)
//
// 143 and 109 bytes on c25519, 237 and 171 on GOST. The sums are SHA-256
// (sha256sum over the bytes) and Streebog-256 in the byte order of RFC 6986;
// they are the vectors G2 and G3 of crypto/providertest, computed there
// without this code
func TestHandshakeContextKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		suite         jcrypto.Suite
		pub           int
		authenticated string
		anonymous     string
	}{
		{
			jcrypto.SuiteC25519, 32,
			"70b1a866bbce04b1e398435c381fe1cb1e9160a8d7e54a86efe2763c51353fd1",
			"412a81d7b53b40da47fab9eade99cd91d6b4c56b40d2a2d7e0c5d85a88fb9381",
		},
		{
			jcrypto.SuiteGOST, 64,
			"27f9517518d0f810964dc8caa1f85fd088216ec3a1b4140482a27ea8f1339ce0",
			"9d44cf104c23a21dc4d25daf8383d800307304309eea1ee7b651d2c00da3afe2",
		},
	} {
		p, err := suite.New(tc.suite)
		if err != nil {
			t.Fatal(err)
		}
		initiator, responder, static := seq(0x00, tc.pub), seq(0x40, tc.pub), seq(0x80, tc.pub)
		for _, mode := range []struct {
			name string
			mode byte
			want string
		}{
			{"authenticated", 0x01, tc.authenticated},
			{"anonymous", 0x00, tc.anonymous},
		} {
			ctx, err := handshakeContext(p, mode.mode, initiator, responder, static)
			if err != nil {
				t.Fatalf("%v %s: %v", tc.suite, mode.name, err)
			}
			if got := hex.EncodeToString(ctx.Sum()); got != mode.want {
				t.Errorf("%v %s: context %s, want %s", tc.suite, mode.name, got, mode.want)
			}
		}
	}
}
