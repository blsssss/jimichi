//go:build linux

package main

import (
	"log"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/relay"
)

// bounds the locked memory of this process until the test ends. Only the soft
// limit moves, and it can be raised back without a capability
func boundMemlock(t *testing.T, limit uint64) {
	t.Helper()
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
		t.Fatal(err)
	}
	lim := unix.Rlimit{Cur: min(limit, was.Max), Max: was.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &was); err != nil {
			t.Errorf("RLIMIT_MEMLOCK not restored: %v", err)
		}
	})
}

func protectedPolicy(t *testing.T) {
	t.Helper()
	before := secmem.CurrentPolicy()
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secmem.SetPolicy(before) })
}

// takes every page that can still be locked, as the circuits of a busy node
// do, and gives them back when the test ends; a process that may lock without
// the bound, with CAP_IPC_LOCK, has nothing to measure
func useUpLockedMemory(t *testing.T, bound uint64) int {
	t.Helper()
	var taken []*secmem.Buffer
	t.Cleanup(func() {
		for _, b := range taken {
			b.Release()
		}
	})
	for uint64(len(taken)) <= bound/uint64(os.Getpagesize()) {
		b, err := secmem.New(1)
		if err != nil {
			return len(taken)
		}
		taken = append(taken, b)
	}
	t.Skip("locked memory is not bounded by RLIMIT_MEMLOCK here")
	return 0
}

// with locked memory used up to the last page, the pages a rotating node holds
// make room for the next key and its pair check, and the release of the
// replaced key takes them again when the rotation could not
func TestHeldPagesCoverARotationWithLockedMemoryUsedUp(t *testing.T) {
	const bound = 1 << 20
	protectedPolicy(t)
	boundMemlock(t, bound)
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			linkPriv, link, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			linkPriv.Release()
			priv, pub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			if !priv.Locked() {
				t.Fatal("the onion key is not locked")
			}
			ring, err := relay.NewOnionRing(p, priv, pub, 0)
			if err != nil {
				t.Fatal(err)
			}
			clk := &clock{now: t0}
			var out logBuffer
			n := &node{p: p, link: link, ttl: time.Hour, now: clk.Now, logger: log.New(&out, "", 0)}
			n.onion = newOnionKeys(ring, 3*time.Hour, time.Hour, true, clk.Now())
			t.Cleanup(n.closeOnion)
			if n.onion.reserve == nil {
				t.Fatal("no pages held before the locked memory is used up")
			}
			rotated := func(want uint32, when string) {
				t.Helper()
				if epoch, _ := ring.Current(); epoch != want || n.onion.failures.Load() != 0 {
					t.Fatalf("%s: epoch %d, want %d: %q", when, epoch, want, out.String())
				}
			}

			if useUpLockedMemory(t, bound) == 0 {
				t.Fatal("the bound left no page to take: the test measures nothing")
			}
			clk.advance(3 * time.Hour)
			n.rotateIfDue()
			rotated(1, "the first rotation with no page left")

			clk.advance(n.onion.grace)
			n.rotateIfDue()
			rotated(1, "the release of the replaced key")
			if n.onion.reserve == nil {
				t.Fatal("the release of the replaced key took no pages for the next rotation")
			}

			useUpLockedMemory(t, bound)
			clk.advance(3*time.Hour - n.onion.grace)
			n.rotateIfDue()
			rotated(2, "the rotation after the release, with no page left again")
		})
	}
}
