package relay

import (
	"errors"
	"net"
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
		c, err := link.Accept(b, p, nil)
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
// counts it with the circuits it closed
func TestFailedForwardWriteBreaksTheCircuit(t *testing.T) {
	p := c25519.New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	r, err := New(Config{Provider: p, StaticPriv: priv})
	if err != nil {
		t.Fatal(err)
	}
	hop, client := oneHop(t, p, 7)
	_, from := linkPair(t, p)
	next, _ := linkPair(t, p)
	_ = next.Close()
	c := &circuit{hop: hop, in: from, next: next, nextID: 9, inbound: 7, done: make(chan struct{})}
	r.circuits[7] = c
	r.owners[from] = 7

	cell, err := client.Seal(0, []byte("onwards"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.route(cell, from); !errors.Is(err, errBroken) {
		t.Fatalf("route over a closed next link: %v, want the circuit counted as broken", err)
	}
}
