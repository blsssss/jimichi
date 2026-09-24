package relay_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/blsssss/jimichi/client"
	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/relay"
	"github.com/blsssss/jimichi/wire"
)

type node struct {
	addr string
	pub  []byte
	r    *relay.Relay
}

func startNode(t *testing.T, p jcrypto.CryptoProvider, deliver relay.Deliver) *node {
	t.Helper()

	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	t.Cleanup(priv.Release)

	r, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, Deliver: deliver})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = r.Serve(ln) }()
	t.Cleanup(func() {
		r.Close()
		_ = ln.Close()
	})

	return &node{addr: ln.Addr().String(), pub: pub, r: r}
}

func chainOf(nodes ...*node) []client.Node {
	out := make([]client.Node, len(nodes))
	for i, n := range nodes {
		out[i] = client.Node{Addr: n.addr, StaticPub: n.pub}
	}
	return out
}

func TestMessageTraversesThreeRelays(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)

	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	msg := []byte("three hops and nothing on disk")
	if err := cl.Send(msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-delivered:
		if !bytes.Equal(got, msg) {
			t.Fatalf("delivered %q, want %q", got, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never reached the exit")
	}
}

// a cover cell must reach the exit like any other cell and must not surface as
// a message: that is what makes the two indistinguishable in transit
func TestCoverCellsAreNotDelivered(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)

	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	for i := 0; i < 5; i++ {
		if err := cl.SendCover(); err != nil {
			t.Fatalf("SendCover: %v", err)
		}
	}
	if err := cl.Send([]byte("real")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-delivered:
		if string(got) != "real" {
			t.Fatalf("first delivered message is %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never reached the exit")
	}

	select {
	case extra := <-delivered:
		t.Fatalf("cover traffic surfaced as a message: %q", extra)
	case <-time.After(200 * time.Millisecond):
	}

	accepted, forwarded, deliveredCount, _ := exit.r.Stats().Snapshot()
	if accepted < 6 {
		t.Fatalf("exit saw %d cells, want at least 6", accepted)
	}
	if forwarded != 0 {
		t.Fatalf("exit forwarded %d cells", forwarded)
	}
	if deliveredCount < 6 {
		t.Fatalf("exit opened %d cells, want at least 6", deliveredCount)
	}
}

// a replayed cell must not reach the exit twice: the test drives the wire
// format directly so it can send the same bytes again
func TestRelayRejectsReplay(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)

	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	entry := startNode(t, p, nil)

	links := []uint64{11, 22}
	setup, err := wire.BuildSetup(p, []wire.SetupHop{
		{StaticPub: entry.pub, Link: links[0], NextAddr: exit.addr, NextCircuit: links[1]},
		{StaticPub: exit.pub, Link: links[1]},
	})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	defer func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}()

	circuit, err := wire.NewCircuit(p, setup.CellKeys, links)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	defer circuit.Close()

	raw, err := net.Dial("tcp", entry.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := link.Dial(raw, p, entry.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteCell(setup.Cell); err != nil {
		t.Fatalf("write setup: %v", err)
	}

	cell, err := circuit.Seal(wire.KindPayload, 1, []byte("once"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// the link layer re-encrypts each copy, so only the relay's replay window
	// stands between the duplicate and the exit
	for i := 0; i < 2; i++ {
		if err := conn.WriteCell(cell); err != nil {
			t.Fatalf("write cell: %v", err)
		}
	}

	select {
	case got := <-delivered:
		if string(got) != "once" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never reached the exit")
	}

	select {
	case again := <-delivered:
		t.Fatalf("replayed cell was delivered: %q", again)
	case <-time.After(300 * time.Millisecond):
	}

	if _, _, _, dropped := entry.r.Stats().Snapshot(); dropped == 0 {
		t.Fatal("entry did not count the replay as dropped")
	}
}

// the reply travels back through the same chain: every relay adds a layer and
// only the client can strip them all
func TestReplyReturnsThroughChain(t *testing.T) {
	p := c25519.New()

	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		return append([]byte("echo:"), payload...)
	})
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	if err := cl.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case reply := <-cl.Replies():
		if string(reply) != "echo:ping" {
			t.Fatalf("reply %q", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply came back")
	}
}

// when a relay of the chain goes away the client must learn it: a circuit that
// dies silently would swallow every message sent after it
func TestClientSeesDeadCircuit(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
	entry := startNode(t, p, nil)

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	entry.r.Close()

	select {
	case _, open := <-cl.Replies():
		if open {
			t.Fatal("got a reply from a chain whose entry is gone")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client never noticed that its circuit died")
	}
}
