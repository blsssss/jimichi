package relay

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
)

// one hop of a circuit and the client side that matches it
func oneHop(t *testing.T, p jcrypto.CryptoProvider, link uint64) (*wire.Hop, *wire.Circuit) {
	t.Helper()
	key, err := secmem.New(p.KeySize())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Release)
	for i := range key.Bytes() {
		key.Bytes()[i] = byte(i + 1)
	}
	off := wire.Offsets{12345, 67890}
	hop, err := wire.NewHop(p, key, off, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hop.Close)
	circuit, err := wire.NewCircuit(p, []*secmem.Buffer{key}, []wire.Offsets{off}, []uint64{link})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(circuit.Close)
	return hop, circuit
}

// both ends of a link over a pipe
func linkPair(t *testing.T, p jcrypto.CryptoProvider) (dialled, accepted *link.Conn) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan *link.Conn, 1)
	go func() {
		c, err := link.Accept(b, p, nil, nil)
		if err != nil {
			done <- nil
			return
		}
		done <- c
	}()
	dialled, err := link.Dial(a, p, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if accepted = <-done; accepted == nil {
		t.Fatal("Accept failed")
	}
	t.Cleanup(func() {
		_ = dialled.Close()
		_ = accepted.Close()
	})
	return dialled, accepted
}

// a reply too long for a cell goes back as cover under its own number and is
// counted as dropped
func TestOversizedReplyLeavesAsCover(t *testing.T) {
	p := c25519.New()
	hop, client := oneHop(t, p, 5)
	pc, _, _ := pacedPipe(t, time.Hour, 4)
	r := &Relay{}
	c := &circuit{hop: hop, inbound: 5, bwd: pc}
	if err := r.reply(c, make([]byte, wire.CellSize)); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if d := r.stats.Snapshot().Dropped; d != 1 {
		t.Fatalf("%d replies counted as dropped, want 1", d)
	}
	q := <-pc.queue
	h, _ := q.cell.Header()
	if n := client.ReplyNumber(h.Counter); n != 0 {
		t.Fatalf("the cover went back as reply %d, want 0", n)
	}
	if _, cover, err := client.OpenExit(q.cell, wire.Backward); err != nil || !cover {
		t.Fatalf("the reply in its place: cover %v, err %v", cover, err)
	}
}

// any other sealing failure closes the circuit rather than send a second cell
// under the same number; with the counter used up the cover reply fails too,
// so the circuit closes as well
func TestReplySealFailureClosesTheCircuit(t *testing.T) {
	p := c25519.New()
	hop, _ := oneHop(t, p, 5)
	pc, _, _ := pacedPipe(t, time.Hour, 4)
	r := &Relay{}
	for _, payload := range [][]byte{[]byte("reply"), nil} {
		c := &circuit{hop: hop, inbound: 5, bwd: pc, replies: 1 << 60}
		if err := r.reply(c, payload); !errors.Is(err, errBroken) {
			t.Fatalf("reply %q at the exhausted counter: %v, want the circuit closed", payload, err)
		}
	}
	if len(pc.queue) != 0 || r.stats.Snapshot().Dropped != 0 {
		t.Fatal("a reply left or was counted as dropped after its seal failed")
	}
}

// a forward cell the relay cannot write on ends the circuit, and the relay
// counts it with the circuits it closed; a link it closed itself is part of a
// teardown already under way and is not counted again
func TestFailedForwardWriteBreaksTheCircuit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closer func(next, peer *link.Conn)
		broken bool
	}{
		{"the next node closed the link", func(_, peer *link.Conn) { _ = peer.Close() }, true},
		{"this node closed the link", func(next, _ *link.Conn) { _ = next.Close() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := c25519.New()
			priv, pub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			defer priv.Release()
			r, err := New(Config{Provider: p, StaticPriv: priv, StaticPub: pub})
			if err != nil {
				t.Fatal(err)
			}
			hop, client := oneHop(t, p, 7)
			_, from := linkPair(t, p)
			next, peer := linkPair(t, p)
			tc.closer(next, peer)
			c := &circuit{hop: hop, in: from, next: next, nextID: 9, inbound: 7, done: make(chan struct{})}
			r.circuits[7] = c
			r.owners[from] = 7

			cell, err := client.Seal(0, []byte("onwards"))
			if err != nil {
				t.Fatal(err)
			}
			err = r.route(cell, from, netip.Addr{})
			if got := errors.Is(err, errBroken); got != tc.broken || err == nil {
				t.Fatalf("route: %v; counted as broken %v, want %v", err, got, tc.broken)
			}
		})
	}
}

// both ends of a link over loopback TCP, where a link closed here and one
// closed by the peer fail a write with different errors
func tcpLinkPair(t *testing.T, p jcrypto.CryptoProvider) (dialled, accepted *link.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan *link.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		c, err := link.Accept(raw, p, nil, nil)
		if err != nil {
			_ = raw.Close()
			done <- nil
			return
		}
		done <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialled, err = link.Dial(raw, p, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if accepted = <-done; accepted == nil {
		t.Fatal("Accept failed")
	}
	t.Cleanup(func() {
		_ = dialled.Close()
		_ = accepted.Close()
	})
	return dialled, accepted
}

// a paced link that breaks under the pacer counts as a circuit the node
// closed; the pacer of a link the node closed itself counts nothing
func TestFailedPacedWriteBreaksTheCircuit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closer func(out, peer *link.Conn)
		broken uint64
	}{
		{"the neighbour closed the link", func(_, peer *link.Conn) { _ = peer.Close() }, 1},
		{"this node closed the link", func(out, _ *link.Conn) { _ = out.Close() }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := c25519.New()
			out, peer := tcpLinkPair(t, p)
			stats := &Stats{}
			pc := newPacer(out, 5*time.Millisecond, 4, stats)
			defer pc.close()
			tc.closer(out, peer)
			select {
			case <-pc.done:
			case <-time.After(3 * time.Second):
				t.Fatal("the pacer kept writing on a closed link")
			}
			if b := stats.Snapshot().Broken; b != tc.broken {
				t.Fatalf("the pacer counted %d broken circuits, want %d", b, tc.broken)
			}
		})
	}
}

// a backward cell the relay cannot write towards the client ends the circuit,
// counted as broken
func TestFailedBackwardWriteBreaksTheCircuit(t *testing.T) {
	p := c25519.New()
	r := &Relay{}
	hop, _ := oneHop(t, p, 7)
	next, nextPeer := linkPair(t, p)
	in, inPeer := linkPair(t, p)
	_ = inPeer.Close()
	c := &circuit{hop: hop, in: in, next: next, inbound: 7, done: make(chan struct{})}
	go r.backward(c)

	cell, err := wire.NewCell(wire.Header{Kind: wire.KindData, Counter: 40}, make([]byte, wire.BodySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := nextPeer.WriteCell(cell); err != nil {
		t.Fatalf("backward cell: %v", err)
	}
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay kept the circuit after a failed write back")
	}
	if b := r.stats.Snapshot().Broken; b != 1 {
		t.Fatalf("%d broken circuits counted, want 1", b)
	}
}

// the exit's reply that cannot be written back ends the circuit the same way
func TestFailedReplyWriteBreaksTheCircuit(t *testing.T) {
	p := c25519.New()
	r := &Relay{}
	hop, _ := oneHop(t, p, 7)
	in, inPeer := linkPair(t, p)
	_ = inPeer.Close()
	c := &circuit{hop: hop, in: in, inbound: 7}
	if err := r.reply(c, nil); !errors.Is(err, errBroken) {
		t.Fatalf("reply on a link the previous node closed: %v, want the circuit counted as broken", err)
	}
}
