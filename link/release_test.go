package link_test

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/link"
)

type trackingProvider struct {
	jcrypto.CryptoProvider
	mu   sync.Mutex
	bufs []*secmem.Buffer
}

func (p *trackingProvider) keep(b *secmem.Buffer) *secmem.Buffer {
	if b != nil {
		p.mu.Lock()
		p.bufs = append(p.bufs, b)
		p.mu.Unlock()
	}
	return b
}

func (p *trackingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(priv), pub, err
}

func (p *trackingProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, peerPub, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.MixKey(chain, secret, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	return p.keep(b), err
}

func (p *trackingProvider) counts() (made, live int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.bufs {
		if b.Bytes() != nil {
			live++
		}
	}
	return len(p.bufs), live
}

// a relay shakes hands once per link, so a secret left behind costs a locked
// page per link; the frame keys live on inside the AEADs only
func TestHandshakeReleasesEverySecret(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		// the size probes of the suite run before anything is counted
		hello, _ := link.InitiatorHandshakeSize(p)
		priv, pub := keyPair(t, p)
		var static []byte
		// an ephemeral key, the agreements and two frame keys; the authenticated
		// mode adds the static agreement and the chained key
		whole, cut := 4, 1
		if auth {
			static = pub
			whole, cut = 6, 2
		}
		expect := func(t *testing.T, name string, tp *trackingProvider, want int) {
			t.Helper()
			if made, live := tp.counts(); made != want || live != 0 {
				t.Fatalf("%s: %d buffers made, %d still held; want %d and 0", name, made, live, want)
			}
		}

		t.Run("a finished handshake", func(t *testing.T) {
			dialer, accepter := &trackingProvider{CryptoProvider: p}, &trackingProvider{CryptoProvider: p}
			a, b := net.Pipe()
			accepted := make(chan *link.Conn, 1)
			go func() {
				srv, err := link.Accept(b, accepter, priv, pub)
				if err != nil {
					t.Errorf("Accept: %v", err)
				}
				accepted <- srv
			}()
			client, err := link.Dial(a, dialer, static)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			server := <-accepted
			if server == nil {
				t.FailNow()
			}
			expect(t, "the initiator", dialer, whole)
			expect(t, "the responder", accepter, whole)
			_ = client.Close()
			_ = server.Close()
		})

		// an all-zero key is refused inside the agreement on both suites; in the
		// authenticated mode the initiator has the static agreement in hand by then
		t.Run("the responder sends a key the agreement refuses", func(t *testing.T) {
			dialer := &trackingProvider{CryptoProvider: p}
			a, b := net.Pipe()
			go func() {
				_, _ = io.ReadFull(b, make([]byte, hello))
				_, _ = b.Write(make([]byte, len(pub)))
			}()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := link.Dial(a, dialer, static); !errors.Is(err, link.ErrHandshake) {
				t.Fatalf("Dial = %v, want %v", err, link.ErrHandshake)
			}
			expect(t, "the initiator", dialer, cut)
			_ = a.Close()
			_ = b.Close()
		})

		// what a responder under another transcript looks like to the initiator:
		// every key is derived, and then the confirmation does not open
		t.Run("the confirmation frame does not open", func(t *testing.T) {
			dialer := &trackingProvider{CryptoProvider: p}
			frame, _ := link.FrameSize(p)
			ephPriv, ephPub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			ephPriv.Release()
			a, b := net.Pipe()
			go func() {
				_, _ = io.ReadFull(b, make([]byte, hello))
				_, _ = b.Write(append(ephPub, make([]byte, frame)...))
			}()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := link.Dial(a, dialer, static); !errors.Is(err, link.ErrHandshake) {
				t.Fatalf("Dial = %v, want %v", err, link.ErrHandshake)
			}
			expect(t, "the initiator", dialer, whole)
			_ = a.Close()
			_ = b.Close()
		})

		t.Run("the initiator sends a key the agreement refuses", func(t *testing.T) {
			accepter := &trackingProvider{CryptoProvider: p}
			a, b := net.Pipe()
			zero := make([]byte, hello)
			if auth {
				zero[0] = 1
			}
			go func() {
				_, _ = a.Write(zero)
				_, _ = io.ReadFull(a, make([]byte, len(pub)))
			}()
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := link.Accept(b, accepter, priv, pub); !errors.Is(err, link.ErrHandshake) {
				t.Fatalf("Accept = %v, want %v", err, link.ErrHandshake)
			}
			expect(t, "the responder", accepter, 1)
			_ = a.Close()
			_ = b.Close()
		})
	})
}
