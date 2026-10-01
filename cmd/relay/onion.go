package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

// how often the node compares the wall clock with the moments below: the timer
// runs on the monotonic clock, which stands still while the host sleeps
const onionCheckEvery = time.Second

var errOnionUnlocked = errors.New("key memory is not locked")

// the onion keys of a node that rotates them; guarded by the node's mu
type onionKeys struct {
	ring  *relay.OnionRing
	every time.Duration
	// how long a replaced key still opens setups: by then every descriptor that
	// names it has expired, also for a verifier whose clock is behind and in the
	// mirrors of the other nodes
	grace time.Duration
	// refuse a new key whose memory could not be locked
	lock bool
	// wall-clock moments; retireAt is zero while no replaced key is held
	rotateAt time.Time
	retireAt time.Time
	// the last failure, so one that repeats every second is one line
	failed string
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
	return &onionKeys{ring: ring, every: every, grace: ttl + pki.Skew, lock: lock, rotateAt: now.Add(every)}
}

func (n *node) onionEpoch() uint32 {
	if n.onion == nil {
		return 0
	}
	epoch, _ := n.onion.ring.Current()
	return epoch
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
	now := n.now()
	// the release comes first and by the wall clock alone, so a host that slept
	// through both moments does not carry the replaced key into another period
	if !o.retireAt.IsZero() && !now.Before(o.retireAt) {
		o.ring.Retire()
		o.retireAt = time.Time{}
	}
	// the ring holds two keys: a rotation that came before the release would
	// free the replaced key while descriptors naming it are still accepted
	if now.Before(o.rotateAt) || !o.retireAt.IsZero() {
		return
	}
	epoch, err := n.rotate()
	if err != nil {
		if cause := err.Error(); cause != o.failed {
			o.failed = cause
			n.logger.Printf("onion key rotation: %v", err)
		}
		return
	}
	o.failed = ""
	o.rotateAt = now.Add(o.every)
	o.retireAt = now.Add(o.grace)
	n.logger.Printf("onion key rotated epoch=%d", epoch)
	// at once and not on the next tick of the signing timer: until then the
	// node would hand out a descriptor for a key that is on its way out
	if err := n.publishOnion(now); err != nil {
		n.logger.Printf("descriptor after the rotation: %v", err)
	}
}

func (n *node) rotate() (uint32, error) {
	priv, pub, err := n.p.GenerateEphemeral()
	if err != nil {
		return 0, err
	}
	if n.onion.lock && !priv.Locked() {
		priv.Release()
		return 0, errOnionUnlocked
	}
	epoch, err := n.onion.ring.Rotate(priv, pub)
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
