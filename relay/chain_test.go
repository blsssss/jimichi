package relay_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
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
		c, err := wire.NewCircuit(p, setup.CellKeys, []uint64{in, out})
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
	circuit, err := wire.NewCircuit(p, setup.CellKeys, links[:1])
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
