package relay_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/relay"
	"github.com/jimichi-org/jimichi/wire"
)

type node struct {
	addr string
	pub  []byte
	r    *relay.Relay
}

func startNode(t *testing.T, p jcrypto.CryptoProvider, deliver relay.Deliver) *node {
	t.Helper()
	return startRelay(t, p, relay.Config{Deliver: deliver})
}

func startRelay(t *testing.T, p jcrypto.CryptoProvider, cfg relay.Config) *node {
	t.Helper()

	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	t.Cleanup(priv.Release)

	cfg.Provider, cfg.StaticPriv = p, priv
	r, err := relay.New(cfg)
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

	s := exit.r.Stats().Snapshot()
	if s.Accepted < 6 {
		t.Fatalf("exit saw %d cells, want at least 6", s.Accepted)
	}
	if s.Forwarded != 0 {
		t.Fatalf("exit forwarded %d cells", s.Forwarded)
	}
	if s.Delivered < 6 {
		t.Fatalf("exit opened %d cells, want at least 6", s.Delivered)
	}
	// without a period the node forwards at once and adds nothing of its own
	if s.Padding != 0 {
		t.Fatalf("unpaced exit sent %d padding frames", s.Padding)
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

// when any relay of the chain goes away the client must learn it: a circuit that
// dies silently would swallow every message sent after it
func TestClientSeesDeadCircuit(t *testing.T) {
	for dead, name := range []string{"entry", "middle", "exit"} {
		t.Run(name, func(t *testing.T) {
			p := c25519.New()
			exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
			middle := startNode(t, p, nil)
			entry := startNode(t, p, nil)
			nodes := []*node{entry, middle, exit}

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(nodes...)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()

			if err := cl.Send([]byte("ping")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case <-cl.Replies():
			case <-time.After(3 * time.Second):
				t.Fatal("no reply before the break")
			}

			nodes[dead].r.Close()

			select {
			case _, open := <-cl.Replies():
				if open {
					t.Fatal("got a reply from a broken chain")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the client never noticed that its circuit died")
			}
		})
	}
}

// a next hop that accepts and then stays silent must not keep Close, and with it
// the zeroing of every key, waiting for a handshake that never comes
func TestCloseWithSilentNextHop(t *testing.T) {
	p := c25519.New()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := silent.Accept(); err == nil {
			accepted <- conn
		}
	}()

	_, silentPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	entry := startNode(t, p, nil)
	cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{
		{Addr: entry.addr, StaticPub: entry.pub},
		{Addr: silent.Addr().String(), StaticPub: silentPub},
	}})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("entry never dialled the next hop")
	}

	closed := make(chan struct{})
	go func() {
		entry.r.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close is stuck behind a silent next hop")
	}
}

// a repeated setup must neither replace the circuit nor open a second link
// onwards: the replaced circuit's keys would never be released
func TestDuplicateSetupIsRefused(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})

	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}})

	links := []uint64{31, 42}
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
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links)
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

	for i := 0; i < 2; i++ {
		if err := conn.WriteCell(setup.Cell); err != nil {
			t.Fatalf("write setup: %v", err)
		}
	}
	cell, err := circuit.Seal(0, []byte("still here"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := conn.WriteCell(cell); err != nil {
		t.Fatalf("write cell: %v", err)
	}

	select {
	case got := <-delivered:
		if string(got) != "still here" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first circuit stopped working")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("entry dialled the next hop %d times", n)
	}
	if entry.r.Stats().Snapshot().Dropped == 0 {
		t.Fatal("the repeated setup was not counted as dropped")
	}
}

// with every node on its own clock the chain still carries messages both ways,
// and the links between nodes stay busy while the client is silent
func TestPacedChainDeliversAndReplies(t *testing.T) {
	p := c25519.New()
	period := 5 * time.Millisecond
	delivered := make(chan []byte, 4)

	exit := startRelay(t, p, relay.Config{Period: period, Deliver: func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return append([]byte("echo:"), payload...)
	}})
	middle := startRelay(t, p, relay.Config{Period: period})
	entry := startRelay(t, p, relay.Config{Period: period})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	for i := 0; i < 3; i++ {
		if err := cl.SendCover(); err != nil {
			t.Fatalf("SendCover: %v", err)
		}
	}
	if err := cl.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-delivered:
		if string(got) != "ping" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never reached the exit")
	}
	select {
	case reply := <-cl.Replies():
		if string(reply) != "echo:ping" {
			t.Fatalf("reply %q", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply came back")
	}

	time.Sleep(10 * period)
	for name, n := range map[string]*node{"entry": entry, "middle": middle, "exit": exit} {
		if s := n.r.Stats().Snapshot(); s.Padding == 0 {
			t.Fatalf("%s sent no padding while idle: %+v", name, s)
		}
	}
	if s := exit.r.Stats().Snapshot(); s.Delivered < 4 {
		t.Fatalf("exit opened %d cells, want 4", s.Delivered)
	}
}

// a node sends nothing back on a link until the circuit is complete on its
// side: a pacer started before extend would write to a peer that may never
// read, and the failed setup would have to wait for it
func TestPacedNodeIsSilentWhileExtending(t *testing.T) {
	p := c25519.New()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	_, silentPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	entry := startRelay(t, p, relay.Config{Period: 5 * time.Millisecond})

	setup, err := wire.BuildSetup(p, []wire.SetupHop{
		{StaticPub: entry.pub, Link: 71, NextAddr: silent.Addr().String(), NextCircuit: 72},
		{StaticPub: silentPub, Link: 72},
	})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	defer func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}()

	raw, err := net.Dial("tcp", entry.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	conn, err := link.Dial(raw, p, entry.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if err := conn.WriteCell(setup.Cell); err != nil {
		t.Fatalf("write setup: %v", err)
	}

	// 60 periods while the next hop never answers its handshake
	_ = raw.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := raw.Read(buf); n > 0 || err == nil {
		t.Fatal("the node wrote to the previous hop before its circuit was complete")
	}
}

// a second circuit on a link that already carries one is refused even with a
// fresh id: its pacer would double the frames on the link and count circuits
func TestSecondCircuitOnOneLinkIsRefused(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}})

	build := func(in, out uint64) (*wire.SetupResult, *wire.Circuit) {
		setup, err := wire.BuildSetup(p, []wire.SetupHop{
			{StaticPub: entry.pub, Link: in, NextAddr: exit.addr, NextCircuit: out},
			{StaticPub: exit.pub, Link: out},
		})
		if err != nil {
			t.Fatalf("BuildSetup: %v", err)
		}
		t.Cleanup(func() {
			for _, k := range setup.CellKeys {
				k.Release()
			}
		})
		c, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, []uint64{in, out})
		if err != nil {
			t.Fatalf("NewCircuit: %v", err)
		}
		t.Cleanup(c.Close)
		return setup, c
	}
	first, circuit := build(31, 42)
	second, _ := build(51, 62)

	raw, err := net.Dial("tcp", entry.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := link.Dial(raw, p, entry.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	defer conn.Close()
	for _, s := range []*wire.SetupResult{first, second} {
		if err := conn.WriteCell(s.Cell); err != nil {
			t.Fatalf("write setup: %v", err)
		}
	}
	cell, err := circuit.Seal(0, []byte("first only"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := conn.WriteCell(cell); err != nil {
		t.Fatalf("write cell: %v", err)
	}

	select {
	case got := <-delivered:
		if string(got) != "first only" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first circuit stopped working")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("entry dialled the next hop %d times, want 1", n)
	}
	if entry.r.Stats().Snapshot().Dropped == 0 {
		t.Fatal("the second setup was not counted as dropped")
	}
}

func TestQueueSizeIsBounded(t *testing.T) {
	p := c25519.New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	for _, n := range []int{-1, 4097} {
		if _, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, QueueCells: n}); err == nil {
			t.Fatalf("relay.New accepted a queue of %d cells", n)
		}
	}
}

// a setup that cannot reach the next node must not leave the client sending
// into a circuit that was never built
func TestClientLearnsFailedSetup(t *testing.T) {
	p := c25519.New()
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gone.Addr().String()
	_ = gone.Close()
	_, gonePub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}

	entry := startNode(t, p, nil)
	cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{
		{Addr: entry.addr, StaticPub: entry.pub},
		{Addr: addr, StaticPub: gonePub},
	}})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	select {
	case _, open := <-cl.Replies():
		if open {
			t.Fatal("a reply came through a circuit that was never built")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client was not told that its setup failed")
	}
}

// what the entry sees on the way back: frames on the client's link after the
// handshake, which is every reply the exit sent
type backCounter struct {
	net.Conn
	mu    sync.Mutex
	bytes int
}

func (b *backCounter) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	b.mu.Lock()
	b.bytes += n
	b.mu.Unlock()
	return n, err
}

func (b *backCounter) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytes
}

// a flow of cover only and a flow with one real message among the same number
// of cells must look the same on the way back: one reply per cell either way
func TestRepliesDoNotRevealPayload(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)
	frame, _ := link.FrameSize(p)

	run := func(real bool) int {
		var seen *backCounter
		cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit),
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				seen = &backCounter{Conn: conn}
				return seen, nil
			}})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		for i := 0; i < 4; i++ {
			if err := cl.SendCover(); err != nil {
				t.Fatalf("SendCover: %v", err)
			}
		}
		if real {
			if err := cl.Send([]byte("the one real message")); err != nil {
				t.Fatalf("Send: %v", err)
			}
		} else if err := cl.SendCover(); err != nil {
			t.Fatalf("SendCover: %v", err)
		}
		answer, _ := link.ResponderHandshakeSize(p)
		want := answer + 5*frame
		deadline := time.Now().Add(3 * time.Second)
		for seen.total() < want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		return (seen.total() - answer) / frame
	}

	cover, withMessage := run(false), run(true)
	if cover != 5 || withMessage != 5 {
		t.Fatalf("replies seen at the client: %d for cover only, %d with a message; want 5 and 5", cover, withMessage)
	}
}

// a cell with a far counter and a body that does not open is dropped before its
// counter counts: it neither ends the circuit nor takes the turn of the genuine
// cell after it
func TestForgedFarCounterDoesNotBlockTheCircuit(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	links := []uint64{81, 82}
	setup, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: exit.pub, Link: links[0]}})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	defer func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}()
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links[:1])
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	defer circuit.Close()

	raw, err := net.Dial("tcp", exit.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := link.Dial(raw, p, exit.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	defer conn.Close()
	if err := conn.WriteCell(setup.Cell); err != nil {
		t.Fatalf("setup: %v", err)
	}

	forged, err := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: links[0], Counter: 1 << 40}, make([]byte, wire.BodySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteCell(forged); err != nil {
		t.Fatalf("forged: %v", err)
	}
	genuine, err := circuit.Seal(0, []byte("still counted"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := conn.WriteCell(genuine); err != nil {
		t.Fatalf("genuine: %v", err)
	}
	select {
	case got := <-delivered:
		if string(got) != "still counted" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a forged far counter kept the genuine cell from the exit")
	}
}

// the same at a relay that forwards: it peels before it checks the counter, so
// a forged far counter on its inbound link must not end the circuit either
func TestForgedFarCounterAtAForwardingRelay(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})
	entry := startNode(t, p, nil)
	links := []uint64{91, 92}
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
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links)
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
		t.Fatalf("setup: %v", err)
	}
	forged, err := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: links[0], Counter: 1 << 40}, make([]byte, wire.BodySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteCell(forged); err != nil {
		t.Fatalf("forged: %v", err)
	}
	genuine, err := circuit.Seal(0, []byte("through the middle"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := conn.WriteCell(genuine); err != nil {
		t.Fatalf("genuine: %v", err)
	}
	select {
	case got := <-delivered:
		if string(got) != "through the middle" {
			t.Fatalf("delivered %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a forged far counter at the entry kept the genuine cell from the exit")
	}
}

// the chain runs unchanged on either suite: GOST brings 64-byte public keys to
// the setup layers and 16-byte MGM nonces to every cell
func TestChainOnEverySuite(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
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
			if err := cl.SendCover(); err != nil {
				t.Fatalf("SendCover: %v", err)
			}
			if err := cl.Send([]byte("ping")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case reply := <-cl.Replies():
				if string(reply) != "echo:ping" {
					t.Fatalf("reply %q", reply)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no reply came back")
			}
			if cl.MaxPayload() != 444 {
				t.Fatalf("payload limit %d, want 444", cl.MaxPayload())
			}
		})
	}
}

// the longest chain one setup cell carries, four hops on c25519 and three on
// GOST, makes a round trip, and one hop more is refused before anything is
// dialled. Every hop takes a 16-byte tag from the 494-byte body and the
// length takes two more: 428 bytes of payload on four hops, 444 on three
func TestLongestChainOfEverySuite(t *testing.T) {
	for _, c := range []struct {
		suite   jcrypto.Suite
		payload int
	}{{jcrypto.SuiteC25519, 428}, {jcrypto.SuiteGOST, 444}} {
		t.Run(c.suite.String(), func(t *testing.T) {
			p, err := suite.New(c.suite)
			if err != nil {
				t.Fatal(err)
			}
			hops, err := wire.MaxLayers(p)
			if err != nil {
				t.Fatal(err)
			}
			nodes := make([]*node, hops+1)
			for i := range nodes {
				nodes[i] = startNode(t, p, func(_ uint64, payload []byte) []byte {
					return append([]byte("echo:"), payload...)
				})
			}

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(nodes[:hops]...)})
			if err != nil {
				t.Fatalf("Dial through %d hops: %v", hops, err)
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
			case <-time.After(5 * time.Second):
				t.Fatalf("no reply came back through %d hops", hops)
			}
			if cl.MaxPayload() != c.payload {
				t.Fatalf("payload limit %d on %d hops, want %d", cl.MaxPayload(), hops, c.payload)
			}
			// the setup cell and the message reached every hop, the exit alone delivered
			for i, n := range nodes[:hops] {
				s := n.r.Stats().Snapshot()
				if exit := i == hops-1; s.Accepted != 2 || (s.Delivered == 1) != exit {
					t.Fatalf("hop %d of %d: accepted %d cells, delivered %d", i, hops, s.Accepted, s.Delivered)
				}
			}

			if _, err := client.Dial(client.Config{Provider: p, Chain: chainOf(nodes...)}); !errors.Is(err, wire.ErrSetupSize) {
				t.Fatalf("Dial through %d hops: %v, want ErrSetupSize", hops+1, err)
			}
			for i, n := range nodes {
				if s := n.r.Stats().Snapshot(); s.Accepted > 2 {
					t.Fatalf("hop %d took %d cells, the refused chain reached it", i, s.Accepted)
				}
			}
		})
	}
}

// reports when the relay lets go of the link, which it does only after the
// circuit has left its tables
type closeSignal struct {
	net.Conn
	closed func()
}

func (c *closeSignal) Close() error {
	c.closed()
	return c.Conn.Close()
}

// a copy of a setup must not rebuild its circuit once the first one is gone:
// the circuit id is free again by then, so only the setup itself can tell
func TestSetupReplayAfterTeardownIsRefused(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return nil
	})

	var dials atomic.Int32
	var once sync.Once
	released := make(chan struct{})
	entry := startRelay(t, p, relay.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &closeSignal{Conn: conn, closed: func() { once.Do(func() { close(released) }) }}, nil
	}})

	links := []uint64{57, 68}
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
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	defer circuit.Close()

	dialEntry := func() (*link.Conn, net.Conn) {
		t.Helper()
		raw, err := net.Dial("tcp", entry.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn, err := link.Dial(raw, p, entry.pub)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		return conn, raw
	}

	first, _ := dialEntry()
	if err := first.WriteCell(setup.Cell); err != nil {
		t.Fatalf("write setup: %v", err)
	}
	cell, err := circuit.Seal(0, []byte("original"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := first.WriteCell(cell); err != nil {
		t.Fatalf("write cell: %v", err)
	}
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("the original circuit carried nothing")
	}

	_ = first.Close()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("the entry kept the circuit after its link closed")
	}

	second, raw := dialEntry()
	defer second.Close()
	if err := second.WriteCell(setup.Cell); err != nil {
		t.Fatalf("write replayed setup: %v", err)
	}
	// the recorded data cell follows, as it would in a replay; the entry may
	// already have closed the link, so a failed write is fine
	_ = second.WriteCell(cell)
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	var got wire.Cell
	if err := second.ReadCell(&got); err == nil {
		t.Fatal("the entry answered on a link whose setup was a replay")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the entry kept the link of a replayed setup open")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the replay made the entry dial the exit again, %d dials", n)
	}
	select {
	case got := <-delivered:
		t.Fatalf("the exit delivered %q after the replay", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// forgetting a tag would reopen the replay it guards against, so a full cache
// turns new circuits away instead
func TestFullSetupCacheRefusesNewCircuits(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
	entry := startRelay(t, p, relay.Config{SetupCache: 1})

	first, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer first.Close()
	if err := first.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case <-first.Replies():
	case <-time.After(3 * time.Second):
		t.Fatal("no reply on the circuit that fits the cache")
	}

	second, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer second.Close()
	_ = second.Send([]byte("ping"))
	select {
	case _, open := <-second.Replies():
		if open {
			t.Fatal("a reply came through a circuit past the cache")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a circuit past the cache was not refused")
	}
}

func TestSetupCacheSizeIsBounded(t *testing.T) {
	p := c25519.New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	for _, size := range []int{-1, relay.MaxSetupCache + 1} {
		if _, err := relay.New(relay.Config{Provider: p, StaticPriv: priv, SetupCache: size}); err == nil {
			t.Fatalf("relay.New accepted a setup cache of %d", size)
		}
	}
}

// the realistic replay comes from behind the entry: a hostile entry, or whoever
// sits on the anonymous link to the middle, holds the forwarded setup in clear
func TestForwardedSetupReplayIsRefusedByTheMiddle(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, nil)

	var dials atomic.Int32
	var once sync.Once
	released := make(chan struct{})
	middle := startRelay(t, p, relay.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &closeSignal{Conn: conn, closed: func() { once.Do(func() { close(released) }) }}, nil
	}})

	entryPriv, entryPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer entryPriv.Release()

	links := []uint64{71, 72, 73}
	setup, err := wire.BuildSetup(p, []wire.SetupHop{
		{StaticPub: entryPub, Link: links[0], NextAddr: middle.addr, NextCircuit: links[1]},
		{StaticPub: middle.pub, Link: links[1], NextAddr: exit.addr, NextCircuit: links[2]},
		{StaticPub: exit.pub, Link: links[2]},
	})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	defer func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}()
	layer, err := wire.OpenSetup(p, entryPriv, setup.Cell)
	if err != nil {
		t.Fatalf("OpenSetup: %v", err)
	}
	layer.CellKey.Release()
	forwarded, err := wire.ForwardSetup(layer, 0)
	if err != nil {
		t.Fatalf("ForwardSetup: %v", err)
	}

	dialMiddle := func() (*link.Conn, net.Conn) {
		t.Helper()
		raw, err := net.Dial("tcp", middle.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn, err := link.Dial(raw, p, nil)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		return conn, raw
	}

	first, _ := dialMiddle()
	if err := first.WriteCell(forwarded); err != nil {
		t.Fatalf("write setup: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for dials.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dials.Load() != 1 {
		t.Fatal("the middle never extended the original circuit")
	}
	_ = first.Close()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("the middle kept the circuit after its link closed")
	}

	second, raw := dialMiddle()
	defer second.Close()
	if err := second.WriteCell(forwarded); err != nil {
		t.Fatalf("write replayed setup: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	var got wire.Cell
	if err := second.ReadCell(&got); err == nil {
		t.Fatal("the middle answered on a link whose setup was a replay")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the middle kept the link of a replayed setup open")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the replay made the middle dial the exit again, %d dials", n)
	}
}

// setups sent on a link that already carries a circuit are refused before they
// reach the cache, so one connection cannot use up the room of every other
func TestSetupsOnATakenLinkDoNotFillTheCache(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
	entry := startRelay(t, p, relay.Config{SetupCache: 2})

	raw, err := net.Dial("tcp", entry.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := link.Dial(raw, p, entry.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 8; i++ {
		setup, err := wire.BuildSetup(p, []wire.SetupHop{{StaticPub: entry.pub, Link: uint64(90 + i)}})
		if err != nil {
			t.Fatalf("BuildSetup: %v", err)
		}
		for _, k := range setup.CellKeys {
			k.Release()
		}
		if err := conn.WriteCell(setup.Cell); err != nil {
			t.Fatalf("setup %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for entry.r.Stats().Snapshot().Accepted < 8 {
		if time.Now().After(deadline) {
			t.Fatal("the entry did not read every setup on the taken link")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	if err := cl.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case _, open := <-cl.Replies():
		if !open {
			t.Fatal("setups on one taken link used up the cache")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply after setups on a taken link")
	}
}

// a setup is burned the moment its layer opens: one that failed further on, here
// because the next hop was unreachable, must not build a circuit when it comes
// back later on a fresh link
func TestFailedSetupCannotComeBack(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, nil)

	var dials atomic.Int32
	middle := startRelay(t, p, relay.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return nil, errors.New("next hop unreachable")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}})

	entryPriv, entryPub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer entryPriv.Release()
	links := []uint64{101, 102, 103}
	setup, err := wire.BuildSetup(p, []wire.SetupHop{
		{StaticPub: entryPub, Link: links[0], NextAddr: middle.addr, NextCircuit: links[1]},
		{StaticPub: middle.pub, Link: links[1], NextAddr: exit.addr, NextCircuit: links[2]},
		{StaticPub: exit.pub, Link: links[2]},
	})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	defer func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	}()
	layer, err := wire.OpenSetup(p, entryPriv, setup.Cell)
	if err != nil {
		t.Fatalf("OpenSetup: %v", err)
	}
	layer.CellKey.Release()
	forwarded, err := wire.ForwardSetup(layer, 0)
	if err != nil {
		t.Fatalf("ForwardSetup: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		raw, err := net.Dial("tcp", middle.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn, err := link.Dial(raw, p, nil)
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		if err := conn.WriteCell(forwarded); err != nil {
			t.Fatalf("attempt %d: write setup: %v", attempt, err)
		}
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		var got wire.Cell
		err = conn.ReadCell(&got)
		_ = conn.Close()
		if err == nil {
			t.Fatalf("attempt %d: the middle answered a setup it could not extend", attempt)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("attempt %d: the middle kept the link open", attempt)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the setup that failed once made the middle dial %d times", n)
	}
}

// ends the encryption of the anonymous link between two relays on both sides,
// so the test sees every cell header the way the two relays do and can put
// cells of its own on the way back
type linkTap struct {
	p jcrypto.CryptoProvider
	// forward data cells the tap swallows before it passes any on
	drop    int
	mu      sync.Mutex
	fwd     []uint64
	bwd     []uint64
	lastFwd wire.Cell
	ends    chan [2]*link.Conn
}

func newLinkTap(p jcrypto.CryptoProvider) *linkTap {
	return &linkTap{p: p, ends: make(chan [2]*link.Conn, 1)}
}

func (lt *linkTap) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	up, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	near, far := net.Pipe()
	go lt.run(far, up)
	return near, nil
}

func (lt *linkTap) run(far, up net.Conn) {
	in, err := link.Accept(far, lt.p, nil)
	if err != nil {
		_ = far.Close()
		_ = up.Close()
		return
	}
	out, err := link.Dial(up, lt.p, nil)
	if err != nil {
		_ = in.Close()
		_ = up.Close()
		return
	}
	select {
	case lt.ends <- [2]*link.Conn{in, out}:
	default:
	}
	go func() {
		defer out.Close()
		dropped := 0
		for {
			var c wire.Cell
			if in.ReadCell(&c) != nil {
				return
			}
			if h, err := c.Header(); err == nil && h.Kind == wire.KindData && dropped < lt.drop {
				dropped++
				continue
			}
			lt.note(&c, &lt.fwd)
			if h, err := c.Header(); err == nil && h.Kind == wire.KindData {
				lt.mu.Lock()
				lt.lastFwd = c
				lt.mu.Unlock()
			}
			if out.WriteCell(&c) != nil {
				return
			}
		}
	}()
	defer in.Close()
	for {
		var c wire.Cell
		if out.ReadCell(&c) != nil {
			return
		}
		lt.note(&c, &lt.bwd)
		if in.WriteCell(&c) != nil {
			return
		}
	}
}

func (lt *linkTap) note(c *wire.Cell, to *[]uint64) {
	h, err := c.Header()
	if err != nil || h.Kind != wire.KindData {
		return
	}
	lt.mu.Lock()
	*to = append(*to, h.Counter)
	lt.mu.Unlock()
}

func (lt *linkTap) seen() (fwd, bwd []uint64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return append([]uint64(nil), lt.fwd...), append([]uint64(nil), lt.bwd...)
}

// one cell carries a different counter on every link, in both directions, while
// each link still sees its own values one after another
func TestEveryLinkCarriesItsOwnCounter(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteGOST, jcrypto.SuiteC25519} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			first, second := newLinkTap(p), newLinkTap(p)
			exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
				return append([]byte("echo:"), payload...)
			})
			middle := startRelay(t, p, relay.Config{Dial: second.dial})
			entry := startRelay(t, p, relay.Config{Dial: first.dial})

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()

			const cells = 5
			for i := 0; i < cells; i++ {
				msg := string(rune('a' + i))
				if err := cl.Send([]byte(msg)); err != nil {
					t.Fatalf("Send: %v", err)
				}
				select {
				case reply := <-cl.Replies():
					if string(reply) != "echo:"+msg {
						t.Fatalf("reply %q, want %q", reply, "echo:"+msg)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("no reply to cell %d", i)
				}
			}

			one, oneBack := first.seen()
			two, twoBack := second.seen()
			for name, values := range map[string][]uint64{
				"entry to middle": one, "middle to exit": two,
				"middle to entry": oneBack, "exit to middle": twoBack,
			} {
				if len(values) != cells {
					t.Fatalf("%s: %d data cells, want %d", name, len(values), cells)
				}
				for k, v := range values {
					if v != (values[0]+uint64(k))%(1<<62) {
						t.Fatalf("%s: counters %v do not follow one another", name, values)
					}
				}
			}
			// the client's own link carries its base counters 0..cells-1
			sent := make([]uint64, cells)
			for i := range sent {
				sent[i] = uint64(i)
			}
			for _, pair := range [][2][]uint64{{sent, one}, {sent, two}, {one, two}, {oneBack, twoBack}} {
				for _, a := range pair[0] {
					for _, b := range pair[1] {
						if a == b {
							t.Fatalf("counter %d appears on two links: %v and %v", a, pair[0], pair[1])
						}
					}
				}
			}
		})
	}
}

// the two ends of the tapped link: towards the relay that dialled and towards
// the one it dialled
func (lt *linkTap) links(t *testing.T) (in, out *link.Conn) {
	t.Helper()
	select {
	case ends := <-lt.ends:
		lt.ends <- ends
		return ends[0], ends[1]
	case <-time.After(3 * time.Second):
		t.Fatal("the relay never dialled through the tap")
		return nil, nil
	}
}

// counts the ciphers a relay holds, so a test sees that a closed circuit left
// none of its keys behind: the hop key and the keys of both its links
type countingProvider struct {
	jcrypto.CryptoProvider
	live atomic.Int64
}

func (p *countingProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	a, err := p.CryptoProvider.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	p.live.Add(1)
	return &countedAEAD{AEAD: a, p: p}, nil
}

type countedAEAD struct {
	jcrypto.AEAD
	p    *countingProvider
	once sync.Once
}

func (a *countedAEAD) Destroy() {
	a.once.Do(func() { a.p.live.Add(-1) })
	a.AEAD.Destroy()
}

func (p *countingProvider) expectNone(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for p.live.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the relay still holds %d ciphers after the circuit closed", p.live.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func expectBroken(t *testing.T, n *node, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for n.r.Stats().Snapshot().Broken < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := n.r.Stats().Snapshot().Broken; got != want {
		t.Fatalf("the relay closed %d circuits as broken, want %d", got, want)
	}
}

// reads what is left on a link and requires the far end to close it
func expectClosed(t *testing.T, conn *link.Conn, raw net.Conn) (cells []wire.Cell) {
	t.Helper()
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var c wire.Cell
		err := conn.ReadCell(&c)
		if err == nil {
			cells = append(cells, c)
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("the link stayed open")
		}
		return cells
	}
}

// the circuit is over for the client: its reply channel closes
func expectEnd(t *testing.T, cl *client.Client) {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, open := <-cl.Replies():
			if !open {
				return
			}
		case <-timeout:
			t.Fatal("the circuit did not end")
		}
	}
}

// a client that speaks the wire format itself, so a test can send any counter
type rawClient struct {
	circuit *wire.Circuit
	conn    *link.Conn
	raw     net.Conn
}

func dialRaw(t *testing.T, p jcrypto.CryptoProvider, entry *node, next string, nextPub []byte, links []uint64) *rawClient {
	t.Helper()
	setup, err := wire.BuildSetup(p, []wire.SetupHop{
		{StaticPub: entry.pub, Link: links[0], NextAddr: next, NextCircuit: links[1]},
		{StaticPub: nextPub, Link: links[1]},
	})
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	t.Cleanup(func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	})
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, links)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	t.Cleanup(circuit.Close)
	raw, err := net.Dial("tcp", entry.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := link.Dial(raw, p, entry.pub)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteCell(setup.Cell); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return &rawClient{circuit: circuit, conn: conn, raw: raw}
}

func (rc *rawClient) send(t *testing.T, counter uint64, payload string) *wire.Cell {
	t.Helper()
	cell, err := rc.circuit.Seal(counter, []byte(payload))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := rc.conn.WriteCell(cell); err != nil {
		t.Fatalf("write: %v", err)
	}
	return cell
}

// a copy, a gap or a step back on the way out ends the circuit at the relay
// that sees it: nothing after the break reaches the exit, and the relay lets go
// of every key the circuit held
func TestForwardCellOutOfTurnEndsTheCircuit(t *testing.T) {
	for _, tc := range []struct {
		name string
		// the last counter breaks the order, the ones before it are fine
		order []uint64
	}{
		{"copy", []uint64{0, 0}},
		{"gap", []uint64{0, 2}},
		{"step back", []uint64{0, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := c25519.New()
			delivered := make(chan []byte, 4)
			exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
				delivered <- append([]byte(nil), payload...)
				return nil
			})
			counted := &countingProvider{CryptoProvider: c25519.New()}
			entry := startRelay(t, counted, relay.Config{})

			rc := dialRaw(t, p, entry, exit.addr, exit.pub, []uint64{11, 22})
			last := len(tc.order) - 1
			// the cells in turn arrive before the break is sent: a circuit that
			// closes may take cells still in flight on its links with it
			for i, c := range tc.order[:last] {
				rc.send(t, c, string(rune('a'+i)))
				select {
				case got := <-delivered:
					if want := string(rune('a' + i)); string(got) != want {
						t.Fatalf("delivered %q, want %q", got, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("cell %d never reached the exit", i)
				}
			}
			rc.send(t, tc.order[last], "break")
			expectClosed(t, rc.conn, rc.raw)
			expectBroken(t, entry, 1)
			counted.expectNone(t)
			select {
			case got := <-delivered:
				t.Fatalf("the exit got %q after the break", got)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

// a copy of a sealed cell put on the link between two relays opens at the next
// one and ends the circuit there instead of reaching the exit twice
func TestForwardCopyBetweenRelaysEndsTheCircuit(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 4)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- append([]byte(nil), payload...)
		return payload
	})
	middle := startNode(t, p, nil)
	tap := newLinkTap(p)
	entry := startRelay(t, p, relay.Config{Dial: tap.dial})
	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	if err := cl.Send([]byte("once")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	expectReplies(t, cl, "once")
	_, out := tap.links(t)
	tap.mu.Lock()
	copied := tap.lastFwd
	tap.mu.Unlock()
	if err := out.WriteCell(&copied); err != nil {
		t.Fatalf("copy: %v", err)
	}
	expectEnd(t, cl)
	expectBroken(t, middle, 1)
	if got := len(delivered); got != 1 {
		t.Fatalf("the exit delivered %d cells, want 1", got)
	}
}

// plays the exit by the test's own hand: it opens the setup the way a relay
// would, then puts on the way back exactly the cells the test gives it
type scriptedExit struct {
	addr string
	pub  []byte
	got  chan *scripted
}

type scripted struct {
	conn    *link.Conn
	raw     net.Conn
	hop     *wire.Hop
	inbound uint64
}

func startScriptedExit(t *testing.T, p jcrypto.CryptoProvider) *scriptedExit {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e := &scriptedExit{addr: ln.Addr().String(), pub: pub, got: make(chan *scripted, 1)}
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		conn, err := link.Accept(raw, p, nil)
		if err != nil {
			_ = raw.Close()
			return
		}
		var cell wire.Cell
		if err := conn.ReadCell(&cell); err != nil {
			_ = conn.Close()
			return
		}
		hdr, err := cell.Header()
		if err != nil {
			_ = conn.Close()
			return
		}
		layer, err := wire.OpenSetup(p, priv, &cell)
		if err != nil {
			_ = conn.Close()
			return
		}
		hop, err := wire.NewHop(p, layer.CellKey, layer.Offsets, int(hdr.Counter))
		layer.CellKey.Release()
		if err != nil {
			_ = conn.Close()
			return
		}
		e.got <- &scripted{conn: conn, raw: raw, hop: hop, inbound: hdr.Circuit}
	}()
	return e
}

func (e *scriptedExit) node() client.Node { return client.Node{Addr: e.addr, StaticPub: e.pub} }

func (e *scriptedExit) circuit(t *testing.T) *scripted {
	t.Helper()
	select {
	case s := <-e.got:
		t.Cleanup(func() {
			_ = s.conn.Close()
			s.hop.Close()
		})
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("the setup never reached the scripted exit")
		return nil
	}
}

func (s *scripted) reply(t *testing.T, counter uint64, payload string) *wire.Cell {
	t.Helper()
	cell, err := s.hop.SealReply(s.inbound, counter, []byte(payload))
	if err != nil {
		t.Fatalf("SealReply: %v", err)
	}
	return cell
}

// a cell with the header of the reply numbered counter and a body nobody sealed
func (s *scripted) forged(t *testing.T, kind wire.Kind, counter uint64) *wire.Cell {
	t.Helper()
	h, _ := s.reply(t, counter, "").Header()
	cell, err := wire.NewCell(wire.Header{Kind: kind, Circuit: s.inbound, Counter: h.Counter}, make([]byte, wire.BodySize))
	if err != nil {
		t.Fatal(err)
	}
	return cell
}

// waits for n forward cells, so the test knows the client has written them
func (s *scripted) read(t *testing.T, n int) {
	t.Helper()
	_ = s.raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer func() { _ = s.raw.SetReadDeadline(time.Time{}) }()
	for i := 0; i < n; i++ {
		var c wire.Cell
		if err := s.conn.ReadCell(&c); err != nil {
			t.Fatalf("forward cell %d: %v", i, err)
		}
	}
}

func (s *scripted) send(t *testing.T, cells ...*wire.Cell) {
	t.Helper()
	for _, c := range cells {
		if err := s.conn.WriteCell(c); err != nil {
			t.Fatalf("scripted exit: %v", err)
		}
	}
}

// these replies and no others, in this order
func expectReplies(t *testing.T, cl *client.Client, want ...string) {
	t.Helper()
	for _, w := range want {
		select {
		case got, open := <-cl.Replies():
			if !open {
				t.Fatalf("the circuit closed while %q was due", w)
			}
			if string(got) != w {
				t.Fatalf("reply %q, want %q", got, w)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("reply %q never came back", w)
		}
	}
	select {
	case got, open := <-cl.Replies():
		if open {
			t.Fatalf("an extra reply %q came back", got)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// a relay cannot open what comes back, so any break in the header of a backward
// cell ends the circuit: a copy, a gap, a step back, a far counter or another
// kind; the client gets what came before the break and nothing after it
func TestBackwardCellOutOfTurnEndsTheCircuit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cells func(t *testing.T, s *scripted) []*wire.Cell
	}{
		{"copy", func(t *testing.T, s *scripted) []*wire.Cell {
			first := s.reply(t, 0, "a")
			return []*wire.Cell{first, first}
		}},
		{"gap", func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "a"), s.reply(t, 2, "c")}
		}},
		{"step back", func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 1, "a"), s.reply(t, 0, "b")}
		}},
		{"far", func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "a"), s.forged(t, wire.KindData, 1<<40), s.reply(t, 1, "b")}
		}},
		{"another kind", func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "a"), s.forged(t, wire.KindControl, 1), s.reply(t, 1, "b")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := c25519.New()
			counted := &countingProvider{CryptoProvider: c25519.New()}
			entry := startRelay(t, counted, relay.Config{})
			exit := startScriptedExit(t, p)
			rc := dialRaw(t, p, entry, exit.addr, exit.pub, []uint64{31, 32})
			s := exit.circuit(t)

			s.send(t, tc.cells(t, s)...)
			cells := expectClosed(t, rc.conn, rc.raw)
			if len(cells) != 1 {
				t.Fatalf("%d cells reached the client, want only the one before the break", len(cells))
			}
			if h, _ := cells[0].Header(); h.Kind != wire.KindData {
				t.Fatalf("a %s cell reached the client", h.Kind)
			}
			if got, _, err := rc.circuit.OpenExit(&cells[0], wire.Backward); err != nil || string(got) != "a" {
				t.Fatalf("the cell before the break: %q, %v", got, err)
			}
			expectBroken(t, entry, 1)
			counted.expectNone(t)
			var c wire.Cell
			_ = s.raw.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err := s.conn.ReadCell(&c); err == nil {
				t.Fatal("the entry sent the exit a cell")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the entry kept its link to the exit open")
			}
		})
	}
}

// the same for a cell put on the link between two relays: the entry closes the
// circuit rather than pass on a counter out of turn
func TestBackwardCellBetweenRelaysEndsTheCircuit(t *testing.T) {
	p := c25519.New()
	tap := newLinkTap(p)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		return append([]byte("echo:"), payload...)
	})
	middle := startNode(t, p, nil)
	entry := startRelay(t, p, relay.Config{Dial: tap.dial})
	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	if err := cl.Send([]byte("one")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	expectReplies(t, cl, "echo:one")
	_, back := tap.seen()
	if len(back) != 1 {
		t.Fatalf("%d backward cells on the tapped link, want 1", len(back))
	}
	forged, err := wire.NewCell(wire.Header{Kind: wire.KindData, Counter: (back[0] + 1<<40) % (1 << 62)}, make([]byte, wire.BodySize))
	if err != nil {
		t.Fatal(err)
	}
	in, _ := tap.links(t)
	if err := in.WriteCell(forged); err != nil {
		t.Fatalf("forged: %v", err)
	}
	expectEnd(t, cl)
	expectBroken(t, entry, 1)
}

// a relay never loses a cell of a circuit: a cell that finds its queue full
// ends the circuit, on the way out, on the way back and at the exit's reply
func TestFullQueueEndsTheCircuit(t *testing.T) {
	t.Run("forward", func(t *testing.T) {
		p := c25519.New()
		exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
		counted := &countingProvider{CryptoProvider: c25519.New()}
		// an hour-long period never ticks during the test, so the one slot stays taken
		entry := startRelay(t, counted, relay.Config{Period: time.Hour, QueueCells: 1})
		cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		for i := 0; i < 3; i++ {
			_ = cl.Send([]byte("ping"))
		}
		expectEnd(t, cl)
		expectBroken(t, entry, 1)
		counted.expectNone(t)
	})
	t.Run("backward", func(t *testing.T) {
		p := c25519.New()
		counted := &countingProvider{CryptoProvider: c25519.New()}
		entry := startRelay(t, counted, relay.Config{Period: time.Hour, QueueCells: 1})
		exit := startScriptedExit(t, p)
		cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{chainOf(entry)[0], exit.node()}})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		s := exit.circuit(t)
		s.send(t, s.reply(t, 0, "a"), s.reply(t, 1, "b"))
		expectEnd(t, cl)
		expectBroken(t, entry, 1)
		counted.expectNone(t)
	})
	t.Run("exit reply", func(t *testing.T) {
		p := c25519.New()
		exit := startRelay(t, p, relay.Config{
			Period:     time.Hour,
			QueueCells: 1,
			Deliver:    func(_ uint64, payload []byte) []byte { return payload },
		})
		middle := startNode(t, p, nil)
		entry := startNode(t, p, nil)
		cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		for i := 0; i < 5; i++ {
			_ = cl.Send([]byte("ping"))
		}
		expectEnd(t, cl)
		expectBroken(t, exit, 1)
		// the second cell was delivered before its reply found no room
		if s := exit.r.Stats().Snapshot(); s.Delivered != 2 {
			t.Fatalf("exit delivered %d cells, want 2", s.Delivered)
		}
	})
}

// the client knows the number of every reply and how many cells it wrote, so a
// reply out of turn, one that does not open or one more than cells written ends
// the circuit on its side too
func TestClientEndsTheCircuitOnABadReply(t *testing.T) {
	for _, tc := range []struct {
		name string
		// cells the client writes before the exit answers
		written int
		cells   func(t *testing.T, s *scripted) []*wire.Cell
	}{
		{"out of turn", 2, func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 1, "early")}
		}},
		{"does not open", 2, func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "fine"), s.forged(t, wire.KindData, 1)}
		}},
		{"more replies than cells", 1, func(t *testing.T, s *scripted) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "fine"), s.reply(t, 1, "extra")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := c25519.New()
			entry := startNode(t, p, nil)
			exit := startScriptedExit(t, p)
			cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{chainOf(entry)[0], exit.node()}})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()
			s := exit.circuit(t)
			for i := 0; i < tc.written; i++ {
				if err := cl.Send([]byte("ping")); err != nil {
					t.Fatalf("Send: %v", err)
				}
			}
			s.read(t, tc.written)
			s.send(t, tc.cells(t, s)...)
			timeout := time.After(3 * time.Second)
			for open := true; open; {
				select {
				case got, ok := <-cl.Replies():
					if ok && string(got) != "fine" {
						t.Fatalf("the client passed on %q", got)
					}
					open = ok
				case <-timeout:
					t.Fatal("the client kept the circuit")
				}
			}
			if !cl.Broken() {
				t.Fatal("the client did not report the circuit as broken")
			}
		})
	}
}

// cells leave in the order of their counters however the jitter falls, so
// concurrent sends never break the succession a relay requires
func TestConcurrentSendsLeaveInTurn(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte { return payload })
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)
	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit), Jitter: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	const cells = 64
	var wg sync.WaitGroup
	for i := 0; i < cells; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cl.Send([]byte("ping"))
		}()
	}
	wg.Wait()
	timeout := time.After(5 * time.Second)
	for got := 0; got < cells; got++ {
		select {
		case _, open := <-cl.Replies():
			if !open {
				t.Fatalf("the circuit ended after %d replies", got)
			}
		case <-timeout:
			t.Fatalf("%d replies of %d", got, cells)
		}
	}
	for name, n := range map[string]*node{"entry": entry, "middle": middle, "exit": exit} {
		if b := n.r.Stats().Snapshot().Broken; b != 0 {
			t.Fatalf("%s closed %d circuits", name, b)
		}
	}
}

// the testbed's own setting, a node period 5% shorter than the client's, runs
// a paced chain for thousands of cells without a single circuit closing
func TestPacedChainRunsThousandsOfCells(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a paced chain for seconds")
	}
	p := c25519.New()
	rate := 5 * time.Millisecond
	period := rate * 95 / 100
	echo := func(_ uint64, payload []byte) []byte { return payload }
	exit := startRelay(t, p, relay.Config{Period: period, Deliver: echo})
	middle := startRelay(t, p, relay.Config{Period: period})
	entry := startRelay(t, p, relay.Config{Period: period})
	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit), Mode: client.ConstantRate, Rate: rate})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()

	const cells = 2000
	replies := 0
	deadline := time.Now().Add(40 * time.Second)
	for exit.r.Stats().Snapshot().Delivered < cells {
		if time.Now().After(deadline) {
			t.Fatalf("exit delivered %d cells of %d in time", exit.r.Stats().Snapshot().Delivered, cells)
		}
		if err := cl.Send([]byte("ping")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		select {
		case _, open := <-cl.Replies():
			if !open {
				t.Fatalf("the circuit ended after %d cells", exit.r.Stats().Snapshot().Delivered)
			}
			replies++
		case <-time.After(20 * rate):
		}
	}
	for name, n := range map[string]*node{"entry": entry, "middle": middle, "exit": exit} {
		if b := n.r.Stats().Snapshot().Broken; b != 0 {
			t.Fatalf("%s closed %d circuits", name, b)
		}
	}
	if cl.Broken() || replies == 0 {
		t.Fatalf("client broken %v after %d replies", cl.Broken(), replies)
	}
}

// every relay but the exit seeds on the first cell it sees, so cells lost at
// the start of a circuit would pass unnoticed there; the exit knows the value
// the first cell must carry and closes the circuit instead
func TestLostFirstCellsEndTheCircuitAtTheExit(t *testing.T) {
	for _, k := range []int{1, 3} {
		t.Run(strconv.Itoa(k), func(t *testing.T) {
			p := c25519.New()
			delivered := make(chan []byte, 8)
			exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
				delivered <- append([]byte(nil), payload...)
				return payload
			})
			middle := startNode(t, p, nil)
			tap := newLinkTap(p)
			tap.drop = k
			entry := startRelay(t, p, relay.Config{Dial: tap.dial})
			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()
			for i := 0; i <= k; i++ {
				_ = cl.Send([]byte("ping"))
			}
			expectEnd(t, cl)
			expectBroken(t, exit, 1)
			if n := len(delivered); n != 0 {
				t.Fatalf("the exit delivered %d cells of a circuit that lost its first", n)
			}
			for name, n := range map[string]*node{"entry": entry, "middle": middle} {
				if b := n.r.Stats().Snapshot().Broken; b != 0 {
					t.Fatalf("%s closed the circuit, the exit should have", name)
				}
			}
		})
	}
}

// a reply the exit cannot seal, here one too long for a cell, goes back as
// cover under its own number: the replies after it stay in turn and the
// circuit carries on
func TestReplyThatDoesNotSealLeavesAsCover(t *testing.T) {
	p := c25519.New()
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		if string(payload) == "big" {
			return make([]byte, wire.CellSize)
		}
		return payload
	})
	middle := startNode(t, p, nil)
	entry := startNode(t, p, nil)
	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	for _, m := range []string{"one", "big", "two"} {
		if err := cl.Send([]byte(m)); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	expectReplies(t, cl, "one", "two")
	for name, n := range map[string]*node{"entry": entry, "middle": middle, "exit": exit} {
		if b := n.r.Stats().Snapshot().Broken; b != 0 {
			t.Fatalf("%s closed the circuit", name)
		}
	}
	if cl.Broken() {
		t.Fatal("the client closed the circuit")
	}
	if d := exit.r.Stats().Snapshot().Dropped; d != 1 {
		t.Fatalf("the exit counted %d replies it could not seal, want 1", d)
	}
}
