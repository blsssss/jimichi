package relay_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/relay"
)

func peersOf(nodes ...*node) func(string) ([]byte, bool) {
	keys := make(map[string][]byte, len(nodes))
	for _, n := range nodes {
		keys[n.addr] = n.pub
	}
	return func(addr string) ([]byte, bool) {
		key, ok := keys[addr]
		return key, ok
	}
}

func countDials(n *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

func TestExtendOutsidePeersIsRefusedWithoutADial(t *testing.T) {
	p := c25519.New()
	known := startNode(t, p, nil)
	outside := startNode(t, p, nil)
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{Peers: peersOf(known), Dial: countDials(&dials)})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, outside)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	expectEnd(t, cl)

	if n := dials.Load(); n != 0 {
		t.Fatalf("the relay dialled %d times for an address outside its peers", n)
	}
	// the refused setup is a dropped cell as well, like any setup that fails
	if got := entry.r.Stats().Snapshot(); got.RefusedExtend != 1 || got.Dropped != 1 {
		t.Fatalf("refused extends = %d, dropped = %d, want 1 and 1", got.RefusedExtend, got.Dropped)
	}
	if got := outside.r.Stats().Snapshot().Accepted; got != 0 {
		t.Fatalf("the node outside the peers accepted %d cells", got)
	}
}

// an empty key would turn the link anonymous, so it is no key at all
func TestPeerWithoutAKeyIsRefused(t *testing.T) {
	p := c25519.New()
	next := startNode(t, p, nil)
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{
		Peers: func(string) ([]byte, bool) { return nil, true },
		Dial:  countDials(&dials),
	})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, next)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	expectEnd(t, cl)

	if dials.Load() != 0 || entry.r.Stats().Snapshot().RefusedExtend != 1 {
		t.Fatalf("dials = %d, refused extends = %d, want 0 and 1", dials.Load(), entry.r.Stats().Snapshot().RefusedExtend)
	}
}

// the next node holds another key than the one its peer was given: it derives
// other frame keys, cannot read the setup and the circuit ends
func TestExtendWithAWrongLinkKeyEndsTheCircuit(t *testing.T) {
	p := c25519.New()
	delivered := make(chan []byte, 1)
	exit := startNode(t, p, func(_ uint64, payload []byte) []byte {
		delivered <- payload
		return nil
	})
	priv, other, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	var dials atomic.Int32
	entry := startRelay(t, p, relay.Config{
		Peers: func(addr string) ([]byte, bool) { return other, addr == exit.addr },
		Dial:  countDials(&dials),
	})

	cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, exit)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cl.Close()
	_ = cl.Send([]byte("for the holder of the key only"))
	expectEnd(t, cl)

	if n := dials.Load(); n != 1 {
		t.Fatalf("the relay dialled %d times, want 1", n)
	}
	if got := exit.r.Stats().Snapshot().Accepted; got != 0 {
		t.Fatalf("a node without the expected link key accepted %d cells", got)
	}
	select {
	case <-delivered:
		t.Fatal("a message was delivered over a link with the wrong key")
	default:
	}
	if got := entry.r.Stats().Snapshot().RefusedExtend; got != 0 {
		t.Fatalf("refused extends = %d, a known address is not a refusal", got)
	}
}

func TestChainWithPeersDeliversOnEverySuite(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			exit := startRelay(t, p, relay.Config{
				Deliver: func(_ uint64, payload []byte) []byte { return append([]byte("echo:"), payload...) },
				Peers:   peersOf(),
			})
			middle := startRelay(t, p, relay.Config{Peers: peersOf(exit)})
			entry := startRelay(t, p, relay.Config{Peers: peersOf(middle)})

			cl, err := client.Dial(client.Config{Provider: p, Chain: chainOf(entry, middle, exit)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cl.Close()
			if err := cl.Send([]byte("ping")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case reply, open := <-cl.Replies():
				if !open || string(reply) != "echo:ping" {
					t.Fatalf("reply %q, open %v", reply, open)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no reply came back")
			}
			for i, n := range []*node{entry, middle, exit} {
				if got := n.r.Stats().Snapshot().RefusedExtend; got != 0 {
					t.Fatalf("hop %d refused %d extends", i, got)
				}
			}
		})
	}
}
