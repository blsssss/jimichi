package main

import (
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

// hands out keys as usual and remembers every buffer, so a test can see
// whether they were released
type recordingProvider struct {
	jcrypto.CryptoProvider
	mu   sync.Mutex
	keys []*secmem.Buffer
}

func (p *recordingProvider) record(b *secmem.Buffer) {
	p.mu.Lock()
	p.keys = append(p.keys, b)
	p.mu.Unlock()
}

func (p *recordingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	if err == nil {
		p.record(priv)
	}
	return priv, pub, err
}

func (p *recordingProvider) GenerateSigning() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateSigning()
	if err == nil {
		p.record(priv)
	}
	return priv, pub, err
}

func TestFailedStartReleasesTheKeys(t *testing.T) {
	inner, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	for _, c := range []struct {
		name  string
		addrs [3]string
	}{
		{"cells port taken", [3]string{taken.Addr().String(), "127.0.0.1:0", "127.0.0.1:0"}},
		{"info port taken", [3]string{"127.0.0.1:0", taken.Addr().String(), "127.0.0.1:0"}},
		{"admin port taken", [3]string{"127.0.0.1:0", "127.0.0.1:0", taken.Addr().String()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := &recordingProvider{CryptoProvider: inner}
			var out logBuffer
			cfg := config{
				listen: c.addrs[0], info: c.addrs[1], stats: c.addrs[2],
				auth: true, name: testName, advertise: testAddr, descriptorTTL: time.Hour,
			}
			err := serveNode(p, cfg, log.New(&out, "", 0), make(chan os.Signal))
			if err == nil || !strings.Contains(err.Error(), "listen") {
				t.Fatalf("serveNode = %v, want a listen error", err)
			}
			if len(p.keys) != 3 {
				t.Fatalf("%d keys made, want the static key, the identity key and the one of the key pair check", len(p.keys))
			}
			for i, k := range p.keys {
				if k.Bytes() != nil {
					t.Fatalf("key %d was not released after the failed start", i)
				}
			}
			log := out.String()
			if !strings.Contains(log, "identity_hash=") || strings.Contains(log, "relay listening") {
				t.Fatalf("log of a failed start: %q, want the identity line and no listening line", log)
			}
		})
	}
}
