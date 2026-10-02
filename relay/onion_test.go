package relay_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

var bothSuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func onEverySuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range bothSuites {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			run(t, p)
		})
	}
}

type ringKey struct {
	priv *secmem.Buffer
	pub  []byte
}

func (k ringKey) released() bool { return k.priv.Bytes() == nil }

func newRing(t *testing.T, p jcrypto.CryptoProvider, cache int) (*relay.OnionRing, ringKey) {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := relay.NewOnionRing(p, priv, pub, cache)
	if err != nil {
		t.Fatalf("NewOnionRing: %v", err)
	}
	t.Cleanup(ring.Close)
	return ring, ringKey{priv, pub}
}

func rotate(t *testing.T, p jcrypto.CryptoProvider, ring *relay.OnionRing) ringKey {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate(priv, pub); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	return ringKey{priv, pub}
}

var setupLinks atomic.Uint64

// a setup cell whose only layer is sealed to pub, as a client holding a
// descriptor with that onion key builds it
func setupFor(t *testing.T, p jcrypto.CryptoProvider, pub []byte) *wire.Cell {
	t.Helper()
	setup, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: pub, Link: setupLinks.Add(1)}})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	for _, k := range setup.CellKeys {
		k.Release()
	}
	return setup.Cell
}

func opens(t *testing.T, p jcrypto.CryptoProvider, ring *relay.OnionRing, cell *wire.Cell) error {
	t.Helper()
	layer, err := ring.Open(p, cell)
	if err != nil {
		return err
	}
	layer.CellKey.Release()
	return nil
}

func TestOnionKeyOpensThroughGraceAndNotAfterRetire(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ring, old := newRing(t, p, 0)
		if epoch, pub := ring.Current(); epoch != 0 || string(pub) != string(old.pub) {
			t.Fatalf("a new ring is at epoch %d with another key", epoch)
		}
		recorded := setupFor(t, p, old.pub)
		if err := opens(t, p, ring, setupFor(t, p, old.pub)); err != nil {
			t.Fatalf("a setup for the only key: %v", err)
		}

		fresh := rotate(t, p, ring)
		if epoch, pub := ring.Current(); epoch != 1 || string(pub) != string(fresh.pub) {
			t.Fatalf("after a rotation the ring is at epoch %d, want 1 with the new key", epoch)
		}
		if err := opens(t, p, ring, recorded); err != nil {
			t.Fatalf("a setup for epoch 0 during grace: %v", err)
		}
		if err := opens(t, p, ring, setupFor(t, p, fresh.pub)); err != nil {
			t.Fatalf("a setup for epoch 1 during grace: %v", err)
		}
		if old.released() {
			t.Fatal("the rotation released the key it replaced")
		}

		ring.Retire()
		if !old.released() {
			t.Fatal("Retire left the previous key in memory")
		}
		if err := opens(t, p, ring, setupFor(t, p, old.pub)); !errors.Is(err, jcrypto.ErrOpen) {
			t.Fatalf("a setup for epoch 0 after Retire = %v, want %v", err, jcrypto.ErrOpen)
		}
		if err := opens(t, p, ring, setupFor(t, p, fresh.pub)); err != nil {
			t.Fatalf("a setup for epoch 1 after Retire: %v", err)
		}
		ring.Retire()
		if fresh.released() {
			t.Fatal("a second Retire released the current key")
		}
	})
}

func TestSetupReplayIsRefusedByTheKeyThatOpenedIt(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ring, old := newRing(t, p, 0)
		before := setupFor(t, p, old.pub)
		if err := opens(t, p, ring, before); err != nil {
			t.Fatal(err)
		}
		if err := opens(t, p, ring, before); !errors.Is(err, wire.ErrSetupReplay) {
			t.Fatalf("a copy under the only key = %v, want %v", err, wire.ErrSetupReplay)
		}

		fresh := rotate(t, p, ring)
		if err := opens(t, p, ring, before); !errors.Is(err, wire.ErrSetupReplay) {
			t.Fatalf("a copy of a setup opened before the rotation = %v, want %v", err, wire.ErrSetupReplay)
		}
		during := setupFor(t, p, old.pub)
		after := setupFor(t, p, fresh.pub)
		for name, cell := range map[string]*wire.Cell{"previous": during, "current": after} {
			if err := opens(t, p, ring, cell); err != nil {
				t.Fatalf("a setup for the %s key: %v", name, err)
			}
			if err := opens(t, p, ring, cell); !errors.Is(err, wire.ErrSetupReplay) {
				t.Fatalf("a copy of a setup for the %s key = %v, want %v", name, err, wire.ErrSetupReplay)
			}
		}

		ring.Retire()
		if err := opens(t, p, ring, during); !errors.Is(err, jcrypto.ErrOpen) {
			t.Fatalf("a copy after its key was retired = %v, want %v", err, jcrypto.ErrOpen)
		}
		if err := opens(t, p, ring, after); !errors.Is(err, wire.ErrSetupReplay) {
			t.Fatalf("a copy under the current key after Retire = %v, want %v", err, wire.ErrSetupReplay)
		}
	})
}

// a full cache turns setups away only under the key it belongs to
func TestFullTagCacheEndsWithItsKey(t *testing.T) {
	p := c25519.New()
	ring, old := newRing(t, p, 1)
	if err := opens(t, p, ring, setupFor(t, p, old.pub)); err != nil {
		t.Fatal(err)
	}
	if err := opens(t, p, ring, setupFor(t, p, old.pub)); !errors.Is(err, wire.ErrSetupCacheFull) {
		t.Fatalf("a setup past the cache = %v, want %v", err, wire.ErrSetupCacheFull)
	}

	fresh := rotate(t, p, ring)
	if err := opens(t, p, ring, setupFor(t, p, fresh.pub)); err != nil {
		t.Fatalf("a setup for the new key while the old cache is full: %v", err)
	}
	if err := opens(t, p, ring, setupFor(t, p, old.pub)); !errors.Is(err, wire.ErrSetupCacheFull) {
		t.Fatalf("a setup for the previous key past its cache = %v, want %v", err, wire.ErrSetupCacheFull)
	}
	if err := opens(t, p, ring, setupFor(t, p, fresh.pub)); !errors.Is(err, wire.ErrSetupCacheFull) {
		t.Fatalf("a second setup for the new key past its cache = %v, want %v", err, wire.ErrSetupCacheFull)
	}
}

// counts what a setup costs the node: agreements and layers it tried to open
type workProvider struct {
	jcrypto.CryptoProvider
	agreed, tried atomic.Int64
}

func (w *workProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	w.agreed.Add(1)
	return w.CryptoProvider.Agree(priv, peerPub, ctx)
}

func (w *workProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := w.CryptoProvider.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	return &workAEAD{AEAD: a, w: w}, nil
}

type workAEAD struct {
	jcrypto.AEAD
	w *workProvider
}

func (a *workAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	a.w.tried.Add(1)
	return a.AEAD.Open(dst, nonce, ciphertext, ad)
}

func (w *workProvider) take() [2]int64 {
	return [2]int64{w.agreed.Swap(0), w.tried.Swap(0)}
}

// with two live keys a setup costs two agreements and two attempts whichever
// key it was built for, so its timing does not give the epoch away
func TestSetupCostsTheSameWhicheverKeyOpens(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		ring, old := newRing(t, p, 0)
		w := &workProvider{CryptoProvider: p}
		_, stranger, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}

		if err := opens(t, w, ring, setupFor(t, p, old.pub)); err != nil {
			t.Fatal(err)
		}
		if got := w.take(); got != [2]int64{1, 1} {
			t.Fatalf("one live key: %v agreements and attempts, want 1 and 1", got)
		}

		fresh := rotate(t, p, ring)
		for _, c := range []struct {
			name string
			pub  []byte
			ok   bool
		}{
			{"the previous key", old.pub, true},
			{"the current key", fresh.pub, true},
			{"neither key", stranger, false},
		} {
			err := opens(t, w, ring, setupFor(t, p, c.pub))
			if (err == nil) != c.ok {
				t.Fatalf("a setup for %s: %v", c.name, err)
			}
			if got := w.take(); got != [2]int64{2, 2} {
				t.Fatalf("two live keys, a setup for %s: %v agreements and attempts, want 2 and 2", c.name, got)
			}
		}
		replayed := setupFor(t, p, fresh.pub)
		_ = opens(t, w, ring, replayed)
		w.take()
		if err := opens(t, w, ring, replayed); !errors.Is(err, wire.ErrSetupReplay) {
			t.Fatalf("a copy = %v, want %v", err, wire.ErrSetupReplay)
		}
		if got := w.take(); got != [2]int64{2, 2} {
			t.Fatalf("two live keys, a copy: %v agreements and attempts, want 2 and 2", got)
		}

		ring.Retire()
		if err := opens(t, w, ring, setupFor(t, p, fresh.pub)); err != nil {
			t.Fatal(err)
		}
		if got := w.take(); got != [2]int64{1, 1} {
			t.Fatalf("after Retire: %v agreements and attempts, want 1 and 1", got)
		}
	})
}

// holds the first agreement of a setup until the test lets it go
type gateProvider struct {
	jcrypto.CryptoProvider
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
	return g.CryptoProvider.Agree(priv, peerPub, ctx)
}

func TestNoKeyIsReleasedUnderASetup(t *testing.T) {
	for _, c := range []struct {
		name    string
		release func(*relay.OnionRing)
	}{
		{"Retire", (*relay.OnionRing).Retire},
		{"Close", (*relay.OnionRing).Close},
		{"Rotate", func(ring *relay.OnionRing) {
			priv, pub, err := c25519.New().GenerateEphemeral()
			if err == nil {
				_, err = ring.Rotate(priv, pub)
			}
			if err != nil {
				t.Errorf("Rotate: %v", err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := c25519.New()
			ring, old := newRing(t, p, 0)
			rotate(t, p, ring)
			cell := setupFor(t, p, old.pub)

			gate := &gateProvider{CryptoProvider: p, entered: make(chan struct{}), release: make(chan struct{})}
			opened := make(chan error, 1)
			go func() {
				layer, err := ring.Open(gate, cell)
				if err == nil {
					layer.CellKey.Release()
				}
				opened <- err
			}()
			<-gate.entered

			released := make(chan struct{})
			go func() {
				c.release(ring)
				close(released)
			}()
			select {
			case <-released:
				t.Fatalf("%s returned while a setup was being opened", c.name)
			case <-time.After(100 * time.Millisecond):
			}
			if old.released() {
				t.Fatalf("%s released the previous key under a setup", c.name)
			}

			close(gate.release)
			select {
			case err := <-opened:
				if err != nil {
					t.Fatalf("the setup that began before %s: %v", c.name, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the setup never finished")
			}
			select {
			case <-released:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s never returned", c.name)
			}
			if !old.released() {
				t.Fatalf("%s left the previous key in memory", c.name)
			}
		})
	}
}

func TestSetupsRunAcrossRotations(t *testing.T) {
	p := c25519.New()
	ring, first := newRing(t, p, 0)
	var mu sync.Mutex
	pubs := [][]byte{first.pub}
	keys := []ringKey{first}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var opened atomic.Int64
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				mu.Lock()
				pub := pubs[len(pubs)-1]
				mu.Unlock()
				setup, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: pub, Link: setupLinks.Add(1)}})
				if err != nil {
					t.Error(err)
					return
				}
				setup.CellKeys[0].Release()
				if layer, err := ring.Open(p, setup.Cell); err == nil {
					layer.CellKey.Release()
					opened.Add(1)
				}
			}
		}()
	}
	for range 20 {
		k := rotate(t, p, ring)
		mu.Lock()
		pubs = append(pubs, k.pub)
		mu.Unlock()
		keys = append(keys, k)
		time.Sleep(2 * time.Millisecond)
		ring.Retire()
		_, _ = ring.Current()
	}
	close(stop)
	wg.Wait()
	ring.Close()

	if opened.Load() == 0 {
		t.Fatal("no setup opened across the rotations")
	}
	for i, k := range keys {
		if !k.released() {
			t.Fatalf("the key of epoch %d outlived the ring", i)
		}
	}
}

// remembers every secret buffer the provider hands out
type trackingProvider struct {
	jcrypto.CryptoProvider
	mu   sync.Mutex
	bufs []*secmem.Buffer
}

func (p *trackingProvider) track(b *secmem.Buffer, err error) (*secmem.Buffer, error) {
	if err == nil {
		p.mu.Lock()
		p.bufs = append(p.bufs, b)
		p.mu.Unlock()
	}
	return b, err
}

func (p *trackingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	_, _ = p.track(priv, err)
	return priv, pub, err
}

func (p *trackingProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	return p.track(p.CryptoProvider.Agree(priv, peerPub, ctx))
}

func (p *trackingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	return p.track(p.CryptoProvider.MixKey(chain, secret, ctx))
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	return p.track(p.CryptoProvider.DeriveKey(secret, purpose, ctx, size))
}

func (p *trackingProvider) live() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.bufs {
		if b.Bytes() != nil {
			n++
		}
	}
	return n
}

func TestRingReleasesEveryBuffer(t *testing.T) {
	onEverySuite(t, func(t *testing.T, inner jcrypto.CryptoProvider) {
		p := &trackingProvider{CryptoProvider: inner}
		ring, k0 := newRing(t, p, 2)
		_, stranger, err := inner.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		attempts := func(pubs ...[]byte) {
			t.Helper()
			for _, pub := range pubs {
				cell := setupFor(t, inner, pub)
				_ = opens(t, p, ring, cell)
				_ = opens(t, p, ring, cell)
			}
		}

		attempts(k0.pub, stranger)
		if got := p.live(); got != 1 {
			t.Fatalf("%d buffers live after setups under one key, want the key alone", got)
		}
		k1 := rotate(t, p, ring)
		// opened, a copy, not opened, and past the cache of two tags
		attempts(k0.pub, k1.pub, stranger, k1.pub, k1.pub)
		if got := p.live(); got != 2 || k0.released() || k1.released() {
			t.Fatalf("%d buffers live during grace, want the two keys", got)
		}

		k2 := rotate(t, p, ring)
		if !k0.released() || k1.released() || k2.released() {
			t.Fatal("a second rotation must release the key before the previous one, and no other")
		}
		ring.Retire()
		if !k1.released() || k2.released() {
			t.Fatal("Retire must release the previous key and keep the current one")
		}
		attempts(k2.pub, k1.pub)
		if got := p.live(); got != 1 {
			t.Fatalf("%d buffers live after Retire, want the current key alone", got)
		}

		rotate(t, p, ring)
		ring.Close()
		if got := p.live(); got != 0 {
			t.Fatalf("%d buffers live after Close", got)
		}
		if _, err := ring.Open(p, setupFor(t, inner, k2.pub)); err == nil {
			t.Fatal("a closed ring opened a setup")
		}
		late, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer late.Release()
		if _, err := ring.Rotate(late, pub); err == nil {
			t.Fatal("a closed ring took a key")
		}
		if late.Bytes() == nil {
			t.Fatal("a refused Rotate released the caller's key")
		}
		if got := p.live(); got != 1 {
			t.Fatalf("%d buffers live after attempts on a closed ring, want the refused key alone", got)
		}
		ring.Close()
	})
}

func TestRingRefusesABadKey(t *testing.T) {
	p := c25519.New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	for name, c := range map[string]struct {
		priv  *secmem.Buffer
		pub   []byte
		cache int
	}{
		"no private key":       {nil, pub, 0},
		"short public key":     {priv, pub[1:], 0},
		"negative cache":       {priv, pub, -1},
		"cache over the bound": {priv, pub, relay.MaxSetupCache + 1},
	} {
		if _, err := relay.NewOnionRing(p, c.priv, c.pub, c.cache); err == nil {
			t.Errorf("NewOnionRing accepted %s", name)
		}
	}
	if priv.Bytes() == nil {
		t.Fatal("a refused NewOnionRing released the caller's key")
	}

	ring, first := newRing(t, p, 0)
	other, otherPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	for name, c := range map[string]ringKey{
		"no private key":   {nil, otherPub},
		"short public key": {other, otherPub[1:]},
		"the current key":  {other, first.pub},
	} {
		if _, err := ring.Rotate(c.priv, c.pub); !errors.Is(err, relay.ErrOnionKey) {
			t.Errorf("Rotate with %s = %v, want %v", name, err, relay.ErrOnionKey)
		}
	}
	if epoch, _ := ring.Current(); epoch != 0 || other.Bytes() == nil {
		t.Fatalf("refused rotations moved the ring to epoch %d or released the caller's key", epoch)
	}
}

// without a ring of its own a relay opens setups with the link key and leaves
// that key to whoever made it
func TestRelayWithoutARingKeepsTheLinkKeyWithItsOwner(t *testing.T) {
	p := c25519.New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: pub})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if priv.Bytes() == nil {
		t.Fatal("Close released the link key, which the relay does not own")
	}
	ctx, err := jcrypto.NewContext(p, "test", []byte("still usable"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := p.Agree(priv, pub, ctx)
	if err != nil {
		t.Fatalf("the link key after Close: %v", err)
	}
	secret.Release()
}

// the public half goes into the transcripts of the link and, without a ring,
// of the setup: a relay that does not know it would confirm no authenticated
// link and open no setup
func TestRelayNeedsItsPublicKey(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer priv.Release()
		for name, bad := range map[string][]byte{
			"no public key":      nil,
			"a short public key": pub[1:],
			"a long public key":  append(append([]byte{}, pub...), 0),
		} {
			r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: bad})
			if !errors.Is(err, relay.ErrStaticPubSize) {
				if r != nil {
					r.Close()
				}
				t.Errorf("relay.New with %s: %v, want ErrStaticPubSize", name, err)
			}
		}
		other, otherPub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		other.Release()
		for name, bad := range map[string][]byte{
			"the public key of another pair":   otherPub,
			"a key that the agreement refuses": make([]byte, len(pub)),
		} {
			r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: bad})
			if !errors.Is(err, relay.ErrStaticPair) {
				if r != nil {
					r.Close()
				}
				t.Errorf("relay.New with %s: %v, want ErrStaticPair", name, err)
			}
		}
		r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, StaticPub: pub})
		if err != nil {
			t.Fatalf("relay.New with the key pair: %v", err)
		}
		r.Close()
	})
}

type rotating struct {
	*node
	ring  *relay.OnionRing
	onion []byte
}

func startRotating(t *testing.T, p jcrypto.CryptoProvider, deliver relay.Deliver) *rotating {
	t.Helper()
	ring, key := newRing(t, p, 0)
	return &rotating{node: startRelay(t, p, relay.Config{Deliver: deliver, Onion: ring}), ring: ring, onion: key.pub}
}

// the chain as a client reads it from the descriptors in service right now
func described(nodes ...*rotating) []client.Node {
	out := make([]client.Node, len(nodes))
	for i, n := range nodes {
		_, onion := n.ring.Current()
		out[i] = client.Node{Addr: n.addr, StaticPub: onion, LinkPub: n.pub}
	}
	return out
}

func echoes(t *testing.T, p jcrypto.CryptoProvider, chain []client.Node) bool {
	t.Helper()
	cl, err := client.Dial(client.Config{Provider: p, Chain: chain})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	_ = cl.Send([]byte("ping"))
	select {
	case reply, open := <-cl.Replies():
		return open && string(reply) == "ping"
	case <-time.After(5 * time.Second):
		t.Fatal("the circuit neither answered nor closed")
		return false
	}
}

// a client holding descriptors from before a rotation builds its circuit
// during grace and is refused after it; the link keys never change
func TestChainAcrossAnOnionRotation(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		exit := startRotating(t, p, func(_ uint64, payload []byte) []byte { return payload })
		middle := startRotating(t, p, nil)
		entry := startRotating(t, p, nil)
		nodes := []*rotating{entry, middle, exit}

		old := described(nodes...)
		if !echoes(t, p, old) {
			t.Fatal("no round trip before any rotation")
		}
		for _, n := range nodes {
			rotate(t, p, n.ring)
		}
		fresh := described(nodes...)
		for i := range nodes {
			if string(fresh[i].StaticPub) == string(old[i].StaticPub) || string(fresh[i].LinkPub) != string(old[i].LinkPub) {
				t.Fatalf("node %d: a rotation must change the onion key and keep the link key", i)
			}
		}
		if !echoes(t, p, old) {
			t.Fatal("a client holding the old descriptors built no circuit during grace")
		}
		if !echoes(t, p, fresh) {
			t.Fatal("a client holding the new descriptors built no circuit during grace")
		}

		// one retired key anywhere on the way ends the setup there
		for i, n := range nodes {
			n.ring.Retire()
			mixed := append([]client.Node(nil), fresh...)
			mixed[i].StaticPub = old[i].StaticPub
			if echoes(t, p, mixed) {
				t.Fatalf("node %d opened a setup for its retired onion key", i)
			}
		}
		if echoes(t, p, old) {
			t.Fatal("a circuit was built from the old descriptors after grace")
		}
		if !echoes(t, p, fresh) {
			t.Fatal("a client holding the new descriptors built no circuit after grace")
		}
	})
}
