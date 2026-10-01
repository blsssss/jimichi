package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

// gives the node an onion key of its own that is due for rotation every period
func (f *fixture) rotating(t *testing.T, every time.Duration) *relay.OnionRing {
	t.Helper()
	priv, pub, err := f.p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := relay.NewOnionRing(f.p, priv, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.n.mu.Lock()
	f.n.link = f.pub
	f.n.onion = newOnionKeys(ring, every, f.n.ttl, false, f.clock.Now())
	f.n.mu.Unlock()
	t.Cleanup(f.n.closeOnion)
	return ring
}

// what time.Now returns once the wall clock has moved by d against the running
// time: after the host slept, or after the clock was set. A reading with both
// parts cannot be built through the time package, so the wall field is moved
// in place: with a monotonic reading it holds a flag bit, 33 bits of seconds
// and 30 bits of nanoseconds. The checks at the end fail if that ever changes
func shiftWall(t *testing.T, at time.Time, d time.Duration) time.Time {
	t.Helper()
	if d%time.Second != 0 {
		t.Fatalf("shiftWall by %v: whole seconds only", d)
	}
	out := at
	wall := (*uint64)(unsafe.Pointer(&out))
	*wall += uint64(int64(d/time.Second)) << 30
	if got := out.Sub(at); got != 0 {
		t.Fatalf("the shifted reading is %v of running time away", got)
	}
	if got := out.Round(0).Sub(at.Round(0)); got != d {
		t.Fatalf("the wall clock moved by %v, want %v", got, d)
	}
	return out
}

// the wall clock jumps by d while the running time stays where it is
func (c *clock) jump(t *testing.T, d time.Duration) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = shiftWall(t, c.now, d)
}

// a node whose clock gives readings like time.Now: wall and running time
func newRunningFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	return newNode(t, p, newCA(t, p), &clock{now: time.Now()}, testName)
}

var setupLinks atomic.Uint64

// whether the node still opens the setup of a client that took onion from a
// descriptor
func opensFor(t *testing.T, p jcrypto.CryptoProvider, ring *relay.OnionRing, onion []byte) bool {
	t.Helper()
	setup, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: onion, Link: setupLinks.Add(1)}})
	if err != nil {
		t.Fatal(err)
	}
	setup.CellKeys[0].Release()
	layer, err := ring.Open(p, setup.Cell)
	if err != nil {
		return false
	}
	layer.CellKey.Release()
	return true
}

// the bundle in service, read without a request to the node
func (f *fixture) inService(t *testing.T) ([]byte, *pki.Verified) {
	t.Helper()
	b, ok := f.n.descriptor()
	if !ok {
		t.Fatal("no descriptor in service")
	}
	v, err := pki.Verify(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, f.n.addr, b, f.clock.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return b, v
}

func (f *fixture) verifyAt(bundle []byte, at time.Time) error {
	_, err := pki.Verify(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, f.n.addr, bundle, at)
	return err
}

func TestRotationPublishesTheNextEpochAtOnce(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			f := newFixture(t, s)
			ring := f.rotating(t, time.Hour)
			f.enroll(t, t0.Add(72*time.Hour))

			_, first := f.inService(t)
			_, onion := ring.Current()
			if first.Epoch != 0 || !bytes.Equal(first.OnionPub, onion) || !bytes.Equal(first.LinkPub, f.pub) || bytes.Equal(first.OnionPub, first.LinkPub) {
				t.Fatalf("the first descriptor: epoch %d, want 0 with an onion key of its own next to the link key", first.Epoch)
			}
			if got := f.stats(t); !strings.Contains(got, `"onion_epoch":0`) {
				t.Fatalf("stats before a rotation: %s", got)
			}

			// the last descriptor of the first key, signed half an hour before
			// the rotation
			f.clock.advance(30 * time.Minute)
			f.n.refreshIfDue()
			f.n.rotateIfDue()
			old, last := f.inService(t)
			if last.Epoch != 0 || !last.DescUntil.Equal(t0.Add(90*time.Minute)) {
				t.Fatalf("before the period is over: epoch %d until %v", last.Epoch, last.DescUntil)
			}
			f.clock.advance(30*time.Minute - time.Second)
			f.n.rotateIfDue()
			if b, _ := f.inService(t); !bytes.Equal(b, old) {
				t.Fatal("the node rotated a second before its period was over")
			}

			f.clock.advance(time.Second)
			requests := f.n.descriptorRequests.Load()
			f.n.rotateIfDue()
			_, next := f.inService(t)
			_, onion = ring.Current()
			if next.Epoch != 1 || !bytes.Equal(next.OnionPub, onion) || bytes.Equal(next.OnionPub, first.OnionPub) {
				t.Fatalf("after the rotation the descriptor in service has epoch %d, want 1 with the new onion key", next.Epoch)
			}
			if !bytes.Equal(next.LinkPub, f.pub) {
				t.Fatal("the rotation changed the link key")
			}
			if !next.DescUntil.Equal(t0.Add(2 * time.Hour)) {
				t.Fatalf("the new descriptor runs until %v, want a full lifetime from the rotation", next.DescUntil)
			}
			if f.n.descriptorRequests.Load() != requests {
				t.Fatal("the new descriptor waited for a request")
			}
			if got := f.stats(t); !strings.Contains(got, `"onion_epoch":1`) {
				t.Fatalf("stats after a rotation: %s", got)
			}
			var lines []string
			for _, line := range strings.Split(f.log.String(), "\n") {
				if strings.Contains(line, "onion") {
					lines = append(lines, line)
				}
			}
			if len(lines) != 1 || lines[0] != "onion key rotated epoch=1" {
				t.Fatalf("the log of one rotation: %q, want the epoch and nothing else", lines)
			}

			// the bundle of the first key stays valid for whoever holds it, and
			// the node opens what they build with it
			if err := f.verifyAt(old, f.clock.Now()); err != nil {
				t.Fatalf("the previous bundle right after the rotation: %v", err)
			}
			if !opensFor(t, f.p, ring, first.OnionPub) || !opensFor(t, f.p, ring, next.OnionPub) {
				t.Fatal("after the rotation the node must open setups for both keys")
			}
			f.clock.advance(30*time.Minute - time.Second)
			if err := f.verifyAt(old, f.clock.Now()); err != nil {
				t.Fatalf("the previous bundle a second before it expires: %v", err)
			}
			f.clock.advance(time.Second)
			if err := f.verifyAt(old, f.clock.Now()); !errors.Is(err, pki.ErrDescTime) {
				t.Fatalf("the previous bundle at its expiry = %v, want %v", err, pki.ErrDescTime)
			}

			// a signing by the timer names the current key whatever the identity
			// was told before
			f.n.id.SetKeys(f.pub, first.OnionPub, 0)
			f.n.refreshIfDue()
			if _, v := f.inService(t); v.Epoch != 1 || !bytes.Equal(v.OnionPub, next.OnionPub) {
				t.Fatalf("a re-signing after the rotation names epoch %d", v.Epoch)
			}
		})
	}
}

// the replaced key goes by the wall clock, the descriptor lifetime and the
// clock allowance after the rotation, and the next rotation waits for that
func TestReplacedKeyIsReleasedAfterGrace(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ring := f.rotating(t, time.Hour)
	f.enroll(t, t0.Add(72*time.Hour))
	_, k0 := ring.Current()

	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	_, k1 := ring.Current()

	// the period is over again, the grace of the first key is not
	f.clock.advance(time.Hour + pki.Skew - time.Second)
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 {
		t.Fatalf("epoch %d while the replaced key is still held, want 1: the rotation waits for the release", epoch)
	}
	if !opensFor(t, f.p, ring, k0) {
		t.Fatal("the replaced key was released a second before the end of its grace")
	}

	f.clock.advance(time.Second)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k0) {
		t.Fatal("the replaced key still opens setups at the end of its grace")
	}
	epoch, k2 := ring.Current()
	if epoch != 2 {
		t.Fatalf("epoch %d once the replaced key is released, want the rotation that waited", epoch)
	}
	if !opensFor(t, f.p, ring, k1) || !opensFor(t, f.p, ring, k2) {
		t.Fatal("the node must open setups for the key before the current one and for the current one")
	}
	if _, v := f.inService(t); v.Epoch != 2 || !bytes.Equal(v.OnionPub, k2) {
		t.Fatalf("the descriptor in service names epoch %d, want 2", v.Epoch)
	}
	if n := strings.Count(f.log.String(), "onion key rotated"); n != 2 {
		t.Fatalf("%d rotations in the log, want 2", n)
	}
}

// with a period longer than the grace the release is a step of its own, long
// before the next rotation
func TestReplacedKeyIsReleasedBetweenRotations(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ring := f.rotating(t, 3*time.Hour)
	f.enroll(t, t0.Add(72*time.Hour))
	_, k0 := ring.Current()
	f.clock.advance(3 * time.Hour)
	f.n.rotateIfDue()
	_, k1 := ring.Current()

	f.clock.advance(time.Hour + pki.Skew - time.Second)
	f.n.rotateIfDue()
	if !opensFor(t, f.p, ring, k0) {
		t.Fatal("the replaced key was released a second before the end of its grace")
	}
	f.clock.advance(time.Second)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k0) {
		t.Fatal("the replaced key still opens setups at the end of its grace")
	}
	if epoch, pub := ring.Current(); epoch != 1 || !bytes.Equal(pub, k1) || !opensFor(t, f.p, ring, k1) {
		t.Fatalf("epoch %d after the release, want the current key untouched", epoch)
	}

	f.clock.advance(2*time.Hour - pki.Skew - time.Second)
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 {
		t.Fatalf("epoch %d a second before the period is over", epoch)
	}
	f.clock.advance(time.Second)
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 2 || !opensFor(t, f.p, ring, k1) {
		t.Fatalf("epoch %d a period after the last rotation, want 2 with the replaced key held", epoch)
	}
}

// the timer stands still while the host sleeps; the first look at the wall
// clock afterwards releases what is overdue and rotates once
func TestRotationAfterTheHostSlept(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ring := f.rotating(t, time.Hour)
	f.enroll(t, t0.Add(72*time.Hour))
	_, k0 := ring.Current()
	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	_, k1 := ring.Current()

	f.clock.advance(10 * time.Hour)
	if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
		t.Fatalf("GET /descriptor after the sleep and before the timer = %d, want 503: the bundle expired", code)
	}
	// the signing timer may fire first: it signs for the key that is current
	f.n.refreshIfDue()
	if _, v := f.inService(t); v.Epoch != 1 || !bytes.Equal(v.OnionPub, k1) {
		t.Fatalf("the signing timer named epoch %d before the rotation, want the current one", v.Epoch)
	}
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k0) {
		t.Fatal("the key whose grace ended during the sleep was not released")
	}
	epoch, k2 := ring.Current()
	if epoch != 2 {
		t.Fatalf("epoch %d after the sleep, want one rotation", epoch)
	}
	if !opensFor(t, f.p, ring, k1) {
		t.Fatal("the key replaced after the sleep must stay for its grace: a descriptor naming it was just in service")
	}
	if _, v := f.inService(t); v.Epoch != 2 || !bytes.Equal(v.OnionPub, k2) {
		t.Fatalf("the descriptor in service names epoch %d, want 2", v.Epoch)
	}
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 2 {
		t.Fatalf("a second look at the clock rotated again, epoch %d", epoch)
	}
}

// a roster node that cannot fetch again keeps the bundle of the replaced key
// until it expires and serves it in its mirror; whoever verifies it, also with
// a clock behind by the whole allowance, finds the key still held
func TestMirroredBundleOfTheReplacedKeyStaysUsable(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			c := newCluster(t, s, "relay-1", "relay-2", "relay-3")
			n1, n2, n3 := c.nodes[0], c.nodes[1], c.nodes[2]
			ring := n2.rotating(t, time.Hour)
			c.enroll(t, t0.Add(72*time.Hour))
			cache := n1.takeRoster(t, c.roster())
			_, k0 := ring.Current()
			step := func(d time.Duration) {
				t.Helper()
				c.clock.advance(d)
				n1.n.refreshIfDue()
				n3.n.refreshIfDue()
				cache.refresh()
			}
			mirrored := func() []byte {
				t.Helper()
				code, raw := n1.descriptors(t)
				if code != http.StatusOK {
					t.Fatalf("GET /descriptors = %d %s", code, raw)
				}
				entries, err := pki.ParseMirror(raw)
				if err != nil || len(entries) != 3 || entries[1].Addr != n2.n.addr {
					t.Fatalf("ParseMirror: %v", err)
				}
				return entries[1].Bundle
			}

			step(0)
			c.clock.advance(30 * time.Minute)
			n2.n.refreshIfDue()
			step(0)
			// the worst case: relay-2 signs for its first key, relay-1 fetches
			// that bundle, and relay-2 rotates right after
			c.clock.advance(30 * time.Minute)
			n2.n.refreshIfDue()
			step(0)
			n2.n.rotateIfDue()
			rotated := c.clock.Now()
			if _, v := n2.inService(t); v.Epoch != 1 {
				t.Fatalf("relay-2 serves epoch %d after its rotation", v.Epoch)
			}
			c.route(n2.n.addr, "")

			step(30 * time.Minute)
			step(30*time.Minute - time.Second)
			held := mirrored()
			v, err := pki.Verify(c.p, pki.Policy{Anchor: c.ca.Anchor(), Skew: pki.Skew}, n2.n.addr, held, c.clock.Now())
			if err != nil {
				t.Fatalf("the mirrored bundle a second before it expires: %v", err)
			}
			if v.Epoch != 0 || !bytes.Equal(v.OnionPub, k0) || !v.DescUntil.Equal(rotated.Add(time.Hour)) {
				t.Fatalf("relay-1 mirrors epoch %d until %v, want the bundle signed for the replaced key at the rotation", v.Epoch, v.DescUntil)
			}
			n2.n.rotateIfDue()
			if !opensFor(t, c.p, ring, k0) {
				t.Fatal("relay-2 refuses the key of a bundle its peer still serves as valid")
			}

			step(time.Second)
			if listed := n1.mirrored(t); len(listed) == 0 || slices.Contains(listed, n2.n.addr) {
				t.Fatalf("GET /descriptors once the held bundle expired lists %v, want the mirror without relay-2", listed)
			}
			if err := n2.verifyAt(held, c.clock.Now()); !errors.Is(err, pki.ErrDescTime) {
				t.Fatalf("the held bundle at its expiry = %v, want %v", err, pki.ErrDescTime)
			}

			// a verifier whose clock is behind by the allowance accepts the
			// bundle for that much longer
			c.clock.advance(pki.Skew - time.Second)
			if err := n2.verifyAt(held, c.clock.Now().Add(-pki.Skew)); err != nil {
				t.Fatalf("a verifier behind by the allowance, a second before the grace ends: %v", err)
			}
			n2.n.rotateIfDue()
			if !opensFor(t, c.p, ring, k0) {
				t.Fatal("relay-2 released the replaced key while a verifier within the clock allowance still accepts its bundle")
			}

			c.clock.advance(time.Second)
			if err := n2.verifyAt(held, c.clock.Now().Add(-pki.Skew)); !errors.Is(err, pki.ErrDescTime) {
				t.Fatalf("a verifier behind by the allowance at the end of the grace = %v, want %v", err, pki.ErrDescTime)
			}
			n2.n.rotateIfDue()
			if opensFor(t, c.p, ring, k0) {
				t.Fatal("relay-2 holds the replaced key after its grace")
			}
		})
	}
}

func TestUnsignedNodePublishesTheRotatedKey(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	_, link, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{p: p, pub: link, clock: &clock{now: t0}, log: &logBuffer{}}
	f.n = &node{p: p, addr: testAddr, ttl: time.Hour, now: f.clock.Now, logger: log.New(f.log, "", 0)}
	ring := f.rotating(t, time.Hour)
	_, k0 := ring.Current()
	if f.n.unsigned, err = pki.Unsigned(p, link, k0); err != nil {
		t.Fatal(err)
	}
	f.n.setPeers(nil, unverifiedPeer(p))
	f.serve(t)
	read := func() pki.Verified {
		t.Helper()
		code, bundle := f.descriptor(t)
		if code != http.StatusOK {
			t.Fatalf("GET /descriptor = %d", code)
		}
		nodes, err := pki.Unverified(p, []string{testAddr}, [][]byte{bundle})
		if err != nil {
			t.Fatal(err)
		}
		_, raw := f.descriptors(t)
		entries, err := pki.ParseMirror(raw)
		if err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Bundle, bundle) {
			t.Fatalf("the mirror does not carry the descriptor in service: %v", err)
		}
		return nodes[0]
	}

	if v := read(); v.Epoch != 0 || !bytes.Equal(v.OnionPub, k0) {
		t.Fatalf("before a rotation: epoch %d", v.Epoch)
	}
	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	_, k1 := ring.Current()
	if v := read(); v.Epoch != 1 || !bytes.Equal(v.OnionPub, k1) || !bytes.Equal(v.LinkPub, link) {
		t.Fatalf("after a rotation: epoch %d, want 1 with the new onion key and the same link key", v.Epoch)
	}
	if got := f.stats(t); !strings.Contains(got, `"onion_epoch":1`) {
		t.Fatalf("stats: %s", got)
	}
}

func TestRotationRefusesAKeyThatIsNotLocked(t *testing.T) {
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Policy{Zero: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secmem.SetPolicy(before) })

	f := newFixture(t, jcrypto.SuiteC25519)
	inner := f.p
	p := &recordingProvider{CryptoProvider: inner}
	f.n.p = p
	ring := f.rotating(t, time.Hour)
	f.n.mu.Lock()
	f.n.onion.lock = true
	f.n.mu.Unlock()
	f.enroll(t, t0.Add(72*time.Hour))
	f.clock.advance(30 * time.Minute)
	f.n.refreshIfDue()
	served, _ := f.inService(t)

	f.clock.advance(30 * time.Minute)
	for range 3 {
		f.n.rotateIfDue()
	}
	if epoch, _ := ring.Current(); epoch != 0 {
		t.Fatalf("epoch %d: the node took a key that is not locked", epoch)
	}
	if b, _ := f.inService(t); !bytes.Equal(b, served) {
		t.Fatal("a refused rotation changed the descriptor in service")
	}
	if len(p.keys) != 3 {
		t.Fatalf("%d keys made over three attempts", len(p.keys))
	}
	for i, k := range p.keys {
		if k.Bytes() != nil {
			t.Fatalf("the refused key %d was not released", i)
		}
	}
	if n := strings.Count(f.log.String(), "onion key rotation: "+errOnionUnlocked.Error()); n != 1 {
		t.Fatalf("the refusal was logged %d times, want once: %q", n, f.log.String())
	}
	if got := f.stats(t); !strings.Contains(got, `"onion_rotate_failed":3`) {
		t.Fatalf("stats after three refused keys: %s", got)
	}

	f.n.mu.Lock()
	f.n.onion.lock = false
	f.n.mu.Unlock()
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 {
		t.Fatalf("epoch %d once a key could be taken, want 1", epoch)
	}
}

func TestRotateFlags(t *testing.T) {
	for _, c := range []struct {
		name        string
		rotate, ttl time.Duration
		ok          bool
	}{
		{"off, the default of the binary", 0, time.Hour, true},
		{"the testbed manifests", time.Hour, time.Hour, true},
		{"longer than the descriptor lifetime", 6 * time.Hour, time.Hour, true},
		{"the shortest of both", time.Minute, time.Minute, true},
		{"shorter than the descriptor lifetime", 59 * time.Minute, time.Hour, false},
		{"a second under", time.Hour - time.Second, time.Hour, false},
		{"negative", -time.Hour, time.Hour, false},
	} {
		if err := checkRotateFlags(c.rotate, c.ttl); (err == nil) != c.ok {
			t.Errorf("%s: checkRotateFlags(%v, %v) = %v, want ok %v", c.name, c.rotate, c.ttl, err, c.ok)
		}
	}
	got := newOnionKeys(nil, time.Hour, 30*time.Minute, false, t0)
	defer got.letGo()
	if got.grace != 30*time.Minute+pki.Skew || got.rotateAt.wall != t0.Add(time.Hour).UnixNano() || got.retireAt.pending() {
		t.Fatalf("newOnionKeys: grace %v, first rotation at %v", got.grace, time.Unix(0, got.rotateAt.wall))
	}
}

// the readings of time.Now compare by the running time, which stands still
// while the host sleeps: a deadline has to look at the wall clock as well
func TestHostSleepDoesNotExtendTheLifeOfAKey(t *testing.T) {
	f := newRunningFixture(t)
	if f.clock.Now().Round(0) == f.clock.Now() {
		t.Fatal("the clock of this test must carry a monotonic reading, as time.Now does")
	}
	ring := f.rotating(t, time.Hour)
	f.enroll(t, f.clock.Now().Add(72*time.Hour))
	_, k0 := ring.Current()
	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	epoch, k1 := ring.Current()
	if epoch != 1 {
		t.Fatalf("epoch %d after one period of running time, want 1", epoch)
	}

	f.clock.jump(t, 10*time.Hour)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k0) {
		t.Fatal("the key whose grace ended while the host slept is still held: the release went by the running time alone")
	}
	epoch, k2 := ring.Current()
	if epoch != 2 {
		t.Fatalf("epoch %d after the sleep, want the one rotation that was due by the wall clock", epoch)
	}
	if _, v := f.inService(t); v.Epoch != 2 || !bytes.Equal(v.OnionPub, k2) {
		t.Fatalf("the descriptor in service names epoch %d, want 2", v.Epoch)
	}

	f.clock.advance(time.Hour + pki.Skew - time.Second)
	f.n.rotateIfDue()
	if !opensFor(t, f.p, ring, k1) {
		t.Fatal("the key replaced on waking was released before its grace ended")
	}
	f.clock.advance(time.Second)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k1) {
		t.Fatal("the key replaced on waking outlived its grace")
	}
}

// a wall clock set back must not keep a key either: the running time ends the
// grace and the period
func TestClockSetBackDoesNotExtendTheLifeOfAKey(t *testing.T) {
	f := newRunningFixture(t)
	ring := f.rotating(t, time.Hour)
	f.enroll(t, f.clock.Now().Add(72*time.Hour))
	_, k0 := ring.Current()
	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	_, k1 := ring.Current()

	f.clock.jump(t, -30*time.Minute)
	f.clock.advance(time.Hour + pki.Skew - time.Second)
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 || !opensFor(t, f.p, ring, k0) {
		t.Fatalf("epoch %d a second before the grace ends by the running time, want 1 with the replaced key held", epoch)
	}
	f.clock.advance(time.Second)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k0) {
		t.Fatal("the replaced key outlived its grace because the wall clock was set back")
	}
	epoch, k2 := ring.Current()
	if epoch != 2 || !opensFor(t, f.p, ring, k1) {
		t.Fatalf("epoch %d once the period is over by the running time, want 2 with the replaced key held", epoch)
	}
	if _, v := f.inService(t); v.Epoch != 2 || !bytes.Equal(v.OnionPub, k2) {
		t.Fatalf("the descriptor in service names epoch %d, want 2", v.Epoch)
	}

	// a clock set forwards ends the grace early, which costs a refused setup
	// and no secrecy
	f.clock.jump(t, 2*time.Hour)
	f.n.rotateIfDue()
	if opensFor(t, f.p, ring, k1) {
		t.Fatal("the replaced key was held past its grace by the wall clock")
	}
}

func TestDeadlinePassesByEitherClock(t *testing.T) {
	start := time.Now()
	d := after(start, time.Minute)
	if !d.pending() || (deadline{}).pending() {
		t.Fatal("pending must tell a deadline from none")
	}
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"at once", start, false},
		{"a second early by both clocks", start.Add(time.Minute - time.Second), false},
		{"on time by both clocks", start.Add(time.Minute), true},
		{"by the wall clock alone", shiftWall(t, start, time.Minute), true},
		{"a second early by the wall clock alone", shiftWall(t, start, time.Minute-time.Second), false},
		{"by the running time alone", shiftWall(t, start.Add(time.Minute), -time.Hour), true},
		{"a second early by the running time, the wall clock behind", shiftWall(t, start.Add(time.Minute-time.Second), -time.Hour), false},
		{"a reading without running time, on time", start.Round(0).Add(time.Minute), true},
		{"a reading without running time, early", start.Round(0).Add(time.Minute - time.Second), false},
	} {
		if got := d.passed(c.now); got != c.want {
			t.Errorf("%s: passed = %v, want %v", c.name, got, c.want)
		}
	}
}

// the loop the node runs, not a call from the test, makes the rotation
func TestKeepOnionRotatesWhenThePeriodIsOver(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	ring := f.rotating(t, time.Hour)
	f.enroll(t, t0.Add(72*time.Hour))
	f.clock.advance(time.Hour)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		f.n.keepOnion(stop)
		close(done)
	}()
	limit := time.Now().Add(5 * time.Second)
	for {
		epoch, onion := ring.Current()
		if b, ok := f.n.descriptor(); ok && epoch == 1 {
			v, err := pki.Verify(f.p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew}, f.n.addr, b, f.clock.Now())
			if err == nil && v.Epoch == 1 && bytes.Equal(v.OnionPub, onion) {
				break
			}
		}
		if time.Now().After(limit) {
			t.Fatalf("the loop made no rotation: epoch %d, log %q", epoch, f.log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the loop did not end with its stop channel")
	}
}

func TestRotatingNodeGivesTheRelayItsRing(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	if rc := relayConfig(f.p, nil, config{auth: true}, f.n); rc.Onion != nil {
		t.Fatal("a node without rotation must leave the relay its link key as the onion key")
	}
	ring := f.rotating(t, time.Hour)
	if rc := relayConfig(f.p, nil, config{auth: true}, f.n); rc.Onion != ring {
		t.Fatal("the relay of a rotating node does not get the ring the node rotates")
	}
}

var listening = regexp.MustCompile(`relay listening on (\S+), info on (\S+),`)

// the binary as it starts: its own loop rotates, its info port serves the new
// key and its relay opens setups with that key and not with the link key
func TestNodeRotatesAndOpensSetupsWithItsNewKey(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{now: time.Now()}
	cfg := config{
		listen: "127.0.0.1:0", info: "127.0.0.1:0", stats: "127.0.0.1:0", echo: true,
		descriptorTTL: time.Hour, onionRotate: time.Hour, now: clk.Now,
	}
	var out logBuffer
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serveNode(p, cfg, log.New(&out, "", 0), stop) }()
	defer func() {
		stop <- os.Interrupt
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serveNode = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the node did not stop")
		}
	}()
	logged := func(what string, found func(string) bool) {
		t.Helper()
		limit := time.Now().Add(5 * time.Second)
		for !found(out.String()) {
			if time.Now().After(limit) {
				t.Fatalf("%s: %q", what, out.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	logged("the node did not start", listening.MatchString)
	addrs := listening.FindStringSubmatch(out.String())
	cells, info := addrs[1], addrs[2]
	read := func() pki.Verified {
		t.Helper()
		code, bundle := call(t, http.MethodGet, "http://"+info+"/descriptor", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /descriptor = %d", code)
		}
		nodes, err := pki.Unverified(p, []string{cells}, [][]byte{bundle})
		if err != nil {
			t.Fatal(err)
		}
		return nodes[0]
	}
	echoes := func(onion []byte, link []byte) bool {
		t.Helper()
		cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{{Addr: cells, StaticPub: onion, LinkPub: link}}})
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

	first := read()
	if first.Epoch != 0 || bytes.Equal(first.OnionPub, first.LinkPub) {
		t.Fatalf("a rotating node starts at epoch %d, want 0 with an onion key of its own", first.Epoch)
	}
	if strings.Contains(out.String(), "WARNING") {
		t.Fatalf("a rotating node warned at start: %q", out.String())
	}
	clk.advance(time.Hour)
	logged("the node did not rotate", func(log string) bool { return strings.Contains(log, "onion key rotated epoch=1\n") })
	var next pki.Verified
	for wait := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if next = read(); next.Epoch == 1 {
			break
		}
		if time.Now().After(wait) {
			t.Fatal("the node rotated and kept serving the descriptor of its replaced key")
		}
	}
	if bytes.Equal(next.OnionPub, first.OnionPub) || !bytes.Equal(next.LinkPub, first.LinkPub) {
		t.Fatal("the rotation must change the onion key and keep the link key")
	}
	if !echoes(next.OnionPub, next.LinkPub) {
		t.Fatal("the relay does not open a setup for the key its node publishes")
	}
	if !echoes(first.OnionPub, next.LinkPub) {
		t.Fatal("the relay does not open a setup for the replaced key during its grace")
	}
	if echoes(next.LinkPub, next.LinkPub) {
		t.Fatal("the relay opened a setup with its link key")
	}
}

func TestBaselineNodeWarnsAtStart(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	var out logBuffer
	cfg := config{listen: taken.Addr().String(), info: "127.0.0.1:0", stats: "127.0.0.1:0", descriptorTTL: time.Hour}
	if err := serveNode(p, cfg, log.New(&out, "", 0), make(chan os.Signal)); err == nil {
		t.Fatal("serveNode started on a taken port")
	}
	if n := strings.Count(out.String(), "WARNING: -onion-rotate=0"); n != 1 {
		t.Fatalf("%d warnings for a node without rotation, want one: %q", n, out.String())
	}
}

// a rotation needs no certificate: the keys change all the same, and the first
// descriptor signed afterwards names the key that is current then
func TestRotationWithoutAValidCertificate(t *testing.T) {
	t.Run("no certificate", func(t *testing.T) {
		f := newFixture(t, jcrypto.SuiteC25519)
		ring := f.rotating(t, time.Hour)
		f.clock.advance(time.Hour)
		f.n.rotateIfDue()
		epoch, onion := ring.Current()
		if epoch != 1 {
			t.Fatalf("epoch %d without a certificate, want 1", epoch)
		}
		if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
			t.Fatalf("GET /descriptor without a certificate = %d, want 503", code)
		}
		if strings.Contains(f.log.String(), "descriptor after the rotation") {
			t.Fatalf("a rotation without a certificate logged a failed signing: %q", f.log.String())
		}
		f.enroll(t, f.clock.Now().Add(72*time.Hour))
		if _, v := f.inService(t); v.Epoch != 1 || !bytes.Equal(v.OnionPub, onion) {
			t.Fatalf("the first descriptor names epoch %d, want the key current at the signing", v.Epoch)
		}
	})
	t.Run("expired certificate", func(t *testing.T) {
		f := newFixture(t, jcrypto.SuiteC25519)
		ring := f.rotating(t, time.Hour)
		f.enroll(t, t0.Add(90*time.Minute))
		_, k0 := ring.Current()
		f.clock.advance(time.Hour)
		f.n.rotateIfDue()
		if _, v := f.inService(t); v.Epoch != 1 || !v.DescUntil.Equal(t0.Add(90*time.Minute)) {
			t.Fatalf("epoch %d until %v, want 1 until the certificate ends", v.Epoch, v.DescUntil)
		}

		f.clock.advance(time.Hour + pki.Skew)
		f.n.rotateIfDue()
		if epoch, _ := ring.Current(); epoch != 2 || opensFor(t, f.p, ring, k0) {
			t.Fatalf("epoch %d with the certificate expired, want 2 and the first key released", epoch)
		}
		if code, _ := f.descriptor(t); code != http.StatusServiceUnavailable {
			t.Fatalf("GET /descriptor with the certificate expired = %d, want 503", code)
		}
		if strings.Contains(f.log.String(), "descriptor after the rotation") {
			t.Fatalf("a rotation under an expired certificate logged a failed signing: %q", f.log.String())
		}
		if got := f.stats(t); !strings.Contains(got, `"cert":"expired"`) || !strings.Contains(got, `"onion_epoch":2`) {
			t.Fatalf("stats: %s", got)
		}
	})
}

// finds room for a key only when asked
type tightProvider struct {
	jcrypto.CryptoProvider
	room func() bool
}

func (p *tightProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	if !p.room() {
		return nil, nil, errors.New("no room for a key")
	}
	return p.CryptoProvider.GenerateEphemeral()
}

func TestRotationGivesItsHeldPageToTheNewKey(t *testing.T) {
	f := newFixture(t, jcrypto.SuiteC25519)
	inner := f.p
	ring := f.rotating(t, time.Hour)
	f.enroll(t, t0.Add(72*time.Hour))
	held := f.n.onion.reserve
	if held == nil || held.Bytes() == nil {
		t.Fatal("a rotating node holds no page for its next key")
	}

	f.n.p = &tightProvider{CryptoProvider: inner, room: func() bool { return held.Bytes() == nil }}
	f.clock.advance(time.Hour)
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 {
		t.Fatalf("epoch %d: the held page was not given back before the key was made: %q", epoch, f.log.String())
	}
	again := f.n.onion.reserve
	if again == nil || again == held || again.Bytes() == nil {
		t.Fatal("no page is held for the rotation after this one")
	}
	if got := f.stats(t); !strings.Contains(got, `"onion_rotate_failed":0`) {
		t.Fatalf("stats after a rotation: %s", got)
	}

	f.n.p = &tightProvider{CryptoProvider: inner, room: func() bool { return false }}
	f.clock.advance(time.Hour + pki.Skew)
	f.n.rotateIfDue()
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 1 {
		t.Fatalf("epoch %d after two failed attempts, want 1", epoch)
	}
	if got := f.stats(t); !strings.Contains(got, `"onion_rotate_failed":2`) || !strings.Contains(got, `"onion_epoch":1`) {
		t.Fatalf("stats after two failed attempts: %s", got)
	}
	if n := strings.Count(f.log.String(), "onion key rotation: no room for a key"); n != 1 {
		t.Fatalf("the failure was logged %d times, want once: %q", n, f.log.String())
	}
	last := f.n.onion.reserve
	if last == nil || last.Bytes() == nil {
		t.Fatal("a failed attempt left no page for the next one")
	}

	f.n.p = inner
	f.n.rotateIfDue()
	if epoch, _ := ring.Current(); epoch != 2 {
		t.Fatalf("epoch %d once a key could be made, want 2", epoch)
	}
	kept := f.n.onion.reserve
	f.n.closeOnion()
	if kept.Bytes() != nil || f.n.onion.reserve != nil {
		t.Fatal("the held page outlived the node's onion keys")
	}
	f.clock.advance(3 * time.Hour)
	f.n.rotateIfDue()
	if f.n.onion.reserve != nil || strings.Count(f.log.String(), "onion key rotated") != 2 {
		t.Fatal("a node that closed its onion keys went on rotating")
	}
}

// a rotating node makes one key more, the first onion key, and lets go of it
// like the others when it stops
func TestRotatingNodeReleasesItsKeys(t *testing.T) {
	inner, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{
		listen: "127.0.0.1:0", info: "127.0.0.1:0", stats: "127.0.0.1:0",
		auth: true, name: testName, advertise: testAddr, descriptorTTL: time.Hour, onionRotate: time.Hour,
	}
	// the first size query of a suite makes a key pair of its own
	if _, err := wire.PublicKeySize(inner); err != nil {
		t.Fatal(err)
	}
	p := &recordingProvider{CryptoProvider: inner}
	var out logBuffer
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serveNode(p, cfg, log.New(&out, "", 0), stop) }()
	limit := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "relay listening") {
		if time.Now().After(limit) {
			t.Fatalf("the node did not start: %q", out.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "onion_rotate=1h0m0s") {
		t.Fatalf("the startup line does not name the rotation period: %q", out.String())
	}
	stop <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveNode = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node did not stop")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) != 3 {
		t.Fatalf("%d keys made, want the static, the onion and the identity key", len(p.keys))
	}
	for i, k := range p.keys {
		if k.Bytes() != nil {
			t.Fatalf("key %d was not released when the node stopped", i)
		}
	}
}
