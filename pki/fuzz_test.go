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

func fuzzRoundTrip(f *testing.F, corpus [][]byte, parse func([]byte) ([]byte, error)) {
	for _, c := range corpus {
		f.Add(c)
	}
	f.Add([]byte{})
	f.Add([]byte{Version, byte(jcrypto.SuiteC25519)})
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := parse(b)
		if err == nil && !bytes.Equal(out, b) {
			t.Fatalf("%x parses and re-marshals to %x", b, out)
		}
	})
}

func FuzzParseCert(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).certs, func(b []byte) ([]byte, error) {
		c, err := ParseCert(b)
		if err != nil {
			return nil, err
		}
		return c.Marshal(), nil
	})
}

func FuzzParseDescriptor(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).descriptors, func(b []byte) ([]byte, error) {
		d, err := ParseDescriptor(b)
		if err != nil {
			return nil, err
		}
		return d.Marshal(), nil
	})
}

func FuzzParseRequest(f *testing.F) {
	fuzzRoundTrip(f, seedCorpus(f).requests, func(b []byte) ([]byte, error) {
		r, err := ParseRequest(b)
		if err != nil {
			return nil, err
		}
		return r.Marshal(), nil
	})
}
