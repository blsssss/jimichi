package main

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

// how often the node looks at its clocks for a rotation or a release that is
// due; the ticker itself stands still while the host sleeps and fires again
// within this long of waking
const onionCheckEvery = time.Second

var errOnionUnlocked = errors.New("key memory is not locked")

// a moment that has come once the wall clock or the running time says so,
// whichever is first. time.Now carries both readings and two such values
// compare by the running time alone, which stands still while the host sleeps
// on Linux; the wall clock alone could be set back. Either way a key would
// outlive its period, while a moment taken too early only costs a refused
// setup
type deadline struct {
	// unix nanoseconds, which carry no monotonic reading
	wall int64
	// keeps the monotonic reading of the clock it was taken from
	run time.Time
}

func after(now time.Time, d time.Duration) deadline {
	return deadline{wall: now.Add(d).UnixNano(), run: now.Add(d)}
}

func (d deadline) pending() bool { return !d.run.IsZero() }

func (d deadline) passed(now time.Time) bool {
	return now.UnixNano() >= d.wall || !now.Before(d.run)
}

// the onion keys of a node that rotates them; guarded by the node's mu
type onionKeys struct {
	ring  *relay.OnionRing
	every time.Duration
	// how long a replaced key still opens setups: by then every descriptor that
	// names it has expired, also for a verifier whose clock is behind and in the
	// mirrors of the other nodes
	grace time.Duration
	// refuse a new key whose memory could not be locked
	lock     bool
	rotateAt deadline
	// not pending while no replaced key is held
	retireAt deadline
	// pages given back right before the next key is made, so the key and its
	// pair check find room when the locked memory is used up. Taken when memory
	// allows: after each rotation and, if that found no room, once the replaced
	// key is released; nothing keeps another allocation from taking the room
	// before that
	reserve *secmem.Buffer
	closed  bool
	// the last failure, so one that repeats every second is one line
	failed string
	// attempts that left the published key in place, one a second while a
	// rotation is overdue
	failures atomic.Uint64
}

func checkRotateFlags(rotate, ttl time.Duration) error {
	switch {
	case rotate == 0:
		return nil
	case rotate < 0:
		return fmt.Errorf("-onion-rotate %v: must not be negative; 0 keeps one onion key", rotate)
	case rotate < ttl:
		return fmt.Errorf("-onion-rotate %v: must not be shorter than -descriptor-ttl %v", rotate, ttl)
	}
	return nil
}

func newOnionKeys(ring *relay.OnionRing, every, ttl time.Duration, lock bool, now time.Time) *onionKeys {
	o := &onionKeys{ring: ring, every: every, grace: ttl + pki.Skew, lock: lock, rotateAt: after(now, every)}
	o.hold()
	return o
}

// the new key, the one-time key of its pair check and the two secrets the check
// compares
const rotationPages = 4

// best effort: without the pages the next key is made all the same
func (o *onionKeys) hold() {
	if b, err := secmem.New(rotationPages * os.Getpagesize()); err == nil {
		o.reserve = b
	}
}

func (o *onionKeys) letGo() {
	if o.reserve != nil {
		o.reserve.Release()
		o.reserve = nil
	}
}

func (n *node) closeOnion() {
	n.mu.Lock()
	n.onion.closed = true
	n.onion.letGo()
	n.mu.Unlock()
	n.onion.ring.Close()
}

func (n *node) onionEpoch() uint32 {
	if n.onion == nil {
		return 0
	}
	epoch, _ := n.onion.ring.Current()
	return epoch
}

func (n *node) onionFailures() uint64 {
	if n.onion == nil {
		return 0
	}
	return n.onion.failures.Load()
}

func (n *node) keepOnion(stop <-chan struct{}) {
	t := time.NewTicker(onionCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			n.rotateIfDue()
		case <-stop:
			return
		}
	}
}

func (n *node) rotateIfDue() {
	n.mu.Lock()
	defer n.mu.Unlock()
	o := n.onion
	if o.closed {
		return
	}
	now := n.now()
	// the release comes first, so a host that slept through both moments does
	// not carry the replaced key into another period
	if o.retireAt.pending() && o.retireAt.passed(now) {
		o.ring.Retire()
		o.retireAt = deadline{}
		if o.reserve == nil {
			o.hold()
		}
	}
	// the ring holds two keys: a rotation that came before the release would
	// free the replaced key while descriptors naming it are still accepted
	if !o.rotateAt.passed(now) || o.retireAt.pending() {
		return
	}
	epoch, err := n.rotate()
	if err != nil {
		o.failures.Add(1)
		if cause := err.Error(); cause != o.failed {
			o.failed = cause
			n.logger.Printf("onion key rotation: %v", err)
		}
		return
	}
	o.failed = ""
	o.rotateAt = after(now, o.every)
	o.retireAt = after(now, o.grace)
	n.logger.Printf("onion key rotated epoch=%d", epoch)
	// at once and not on the next tick of the signing timer: until then the
	// node would hand out a descriptor for a key that is on its way out
	if err := n.publishOnion(now); err != nil {
		n.logger.Printf("descriptor after the rotation: %v", err)
	}
}

func (n *node) rotate() (uint32, error) {
	o := n.onion
	o.letGo()
	defer o.hold()
	priv, pub, err := n.p.GenerateEphemeral()
	if err != nil {
		return 0, err
	}
	if o.lock && !priv.Locked() {
		priv.Release()
		return 0, errOnionUnlocked
	}
	epoch, err := o.ring.Rotate(priv, pub)
	if err != nil {
		priv.Release()
		return 0, err
	}
	return epoch, nil
}

// callers hold mu
func (n *node) publishOnion(now time.Time) error {
	if n.id != nil {
		// without a valid certificate there is nothing to sign under; the first
		// signing takes the keys from the ring as every signing does
		if n.certState() != certValid {
			return nil
		}
		return n.sign(now)
	}
	epoch, pub := n.onion.ring.Current()
	b, err := pki.UnsignedEpoch(n.p, n.link, pub, epoch)
	if err != nil {
		return err
	}
	n.out.Store(&served{bundle: b})
	if c := n.peers.Load(); c != nil {
		c.publish()
	}
	return nil
}
