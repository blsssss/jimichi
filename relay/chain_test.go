package relay_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
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
		t.Fatalf("write setup: %v", err)
	}

	cell, err := circuit.Seal(1, []byte("once"))
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

	if entry.r.Stats().Snapshot().Dropped == 0 {
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

// the exit opened the cell whether or not its reply found room in the queue
func TestExitCountsDeliveryWhenReplyIsDropped(t *testing.T) {
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
		if err := cl.Send([]byte("ping")); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for exit.r.Stats().Snapshot().Delivered < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s := exit.r.Stats().Snapshot()
	// the first reply may already be on its way or waiting in the one slot
	if s.Delivered != 5 || s.Dropped < 3 {
		t.Fatalf("delivered %d, dropped %d; want 5 delivered and at least 3 replies dropped", s.Delivered, s.Dropped)
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
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
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
		hello, _ := link.InitiatorHandshakeSize(p)
		want := (hello - 1) + 5*frame
		deadline := time.Now().Add(3 * time.Second)
		for seen.total() < want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		return (seen.total() - (hello - 1)) / frame
	}

	cover, withMessage := run(false), run(true)
	if cover != 5 || withMessage != 5 {
		t.Fatalf("replies seen at the client: %d for cover only, %d with a message; want 5 and 5", cover, withMessage)
	}
}

// a cell with a far counter and a body that does not open must not move the
// window: the genuine cell after it still gets through
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
	genuine, err := circuit.Seal(1, []byte("still counted"))
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
		t.Fatal("a forged far counter pushed the genuine cell out of the window")
	}
}

// the same at a relay that forwards: the middle peels before it commits, so a
// forged far counter on its inbound link must not stall the circuit either
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
	genuine, err := circuit.Seal(1, []byte("through the middle"))
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
		t.Fatal("a forged far counter at the entry pushed the genuine cell out of its window")
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
	p   jcrypto.CryptoProvider
	mu  sync.Mutex
	fwd []uint64
	bwd []uint64
	in  chan *link.Conn
}

func newLinkTap(p jcrypto.CryptoProvider) *linkTap {
	return &linkTap{p: p, in: make(chan *link.Conn, 1)}
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
	case lt.in <- in:
	default:
	}
	go func() {
		defer out.Close()
		for {
			var c wire.Cell
			if in.ReadCell(&c) != nil {
				return
			}
			lt.note(&c, &lt.fwd)
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
