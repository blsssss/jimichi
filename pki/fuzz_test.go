package pki

import (
	"bytes"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

type seeds struct{ certs, descriptors, requests [][]byte }

func seedCorpus(f *testing.F) seeds {
	f.Helper()
	var s seeds
	for _, st := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(st)
		if err != nil {
			f.Fatal(err)
		}
		n := newEnv(f, p).node(f, "relay-1")
		b, err := ParseBundle(n.bundle(f, t0, time.Hour))
		if err != nil {
			f.Fatal(err)
		}
		req, err := n.id.Request(randomNonce(f))
		if err != nil {
			f.Fatal(err)
		}
		s.certs = append(s.certs, b.Cert)
		s.descriptors = append(s.descriptors, b.Descriptor)
		s.requests = append(s.requests, req)
	}
	return s
}

// decode is the parser without its closing canonical check, so a field the codec
// reads and writes differently shows up here as a mismatch rather than hiding
// behind a rejection; parse must then accept exactly what decode accepts
func fuzzRoundTrip(f *testing.F, corpus [][]byte, decode func([]byte) ([]byte, error), parse func([]byte) error) {
	for _, c := range corpus {
		f.Add(c)
	}
	f.Add([]byte{})
	f.Add([]byte{Version, byte(jcrypto.SuiteC25519)})
	f.Fuzz(func(t *testing.T, b []byte) {
		out, decErr := decode(b)
		parseErr := parse(b)
		if decErr != nil {
			if parseErr == nil {
				t.Fatalf("%x is rejected by decode (%v) and accepted by parse", b, decErr)
			}
			return
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("%x decodes and re-marshals to %x", b, out)
		}
		if parseErr != nil {
			t.Fatalf("%x decodes and round-trips but parse rejects it: %v", b, parseErr)
		}
	})
}

func FuzzParseCert(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).certs, func(b []byte) ([]byte, error) {
		c, err := decodeCert(b)
		if err != nil {
			return nil, err
		}
		return c.Marshal(), nil
	}, func(b []byte) error {
		_, err := ParseCert(b)
		return err
	})
}

func FuzzParseDescriptor(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).descriptors, func(b []byte) ([]byte, error) {
		d, err := decodeDescriptor(b)
		if err != nil {
			return nil, err
		}
		return d.Marshal(), nil
	}, func(b []byte) error {
		_, err := ParseDescriptor(b)
		return err
	})
}

func FuzzParseRequest(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).requests, func(b []byte) ([]byte, error) {
		r, err := decodeRequest(b)
		if err != nil {
			return nil, err
		}
		return r.Marshal(), nil
	}, func(b []byte) error {
		_, err := ParseRequest(b)
		return err
	})
}
