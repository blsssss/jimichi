package client

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
)

const replyHops = 3

var replySuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func replyProvider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// the node side of a circuit, from the entry to the exit: hops[i] holds the
// layer of node i and ids[i] is the circuit identifier on the link into it
type backChain struct {
	hops []*wire.Hop
	ids  []uint64
}

func (b *backChain) close() {
	for _, h := range b.hops {
		h.Close()
	}
}

// the way a circuit carries a reply: the exit seals it and every node towards
// the client adds its layer
func (b *backChain) wrap(t *testing.T, cell *wire.Cell, err error) *wire.Cell {
	t.Helper()
	if err != nil {
		t.Fatalf("seal a reply: %v", err)
	}
	for i := len(b.hops) - 2; i >= 0; i-- {
		if cell, err = b.hops[i].Wrap(cell, b.ids[i]); err != nil {
			t.Fatalf("wrap at node %d: %v", i, err)
		}
	}
	return cell
}

func (b *backChain) reply(t *testing.T, number uint64, payload string) *wire.Cell {
	t.Helper()
	last := len(b.hops) - 1
	cell, err := b.hops[last].SealReply(b.ids[last], number, []byte(payload))
	return b.wrap(t, cell, err)
}

func (b *backChain) cover(t *testing.T, number uint64) *wire.Cell {
	t.Helper()
	last := len(b.hops) - 1
	cell, err := b.hops[last].SealCoverReply(b.ids[last], number)
	return b.wrap(t, cell, err)
}

// a cell nobody sealed under the header of the reply with this number
func (b *backChain) unsealed(t *testing.T, number uint64) *wire.Cell {
	t.Helper()
	var cell wire.Cell
	copy(cell[:], b.reply(t, number, "")[:wire.CellSize-wire.BodySize])
	return &cell
}

func flipped(cell *wire.Cell, at int, mask byte) *wire.Cell {
	out := *cell
	out[at] ^= mask
	return &out
}

func otherCircuit(cell *wire.Cell) *wire.Cell {
	out := *cell
	h, _ := out.Header()
	out.SetCircuit(h.Circuit + 1)
	return &out
}

// a client that has written sent cells and the nodes of its circuit, with no
// link between them: open is given the cells by hand
func builtCircuit(t *testing.T, p jcrypto.CryptoProvider, sent uint64) (*Client, *backChain) {
	t.Helper()
	ids := make([]uint64, replyHops)
	chain := make([]wire.SetupHop, replyHops)
	for i := range chain {
		id, err := randomCircuitID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		chain[i] = wire.SetupHop{StaticPub: pub, Link: id}
	}
	for i := 0; i+1 < replyHops; i++ {
		chain[i].NextAddr = fmt.Sprintf("node-%d:9000", i+1)
		chain[i].NextCircuit = ids[i+1]
	}
	setup, err := wire.BuildSetup(p, chain)
	if err != nil {
		t.Fatalf("BuildSetup: %v", err)
	}
	t.Cleanup(func() {
		for _, k := range setup.CellKeys {
			k.Release()
		}
	})
	circuit, err := wire.NewCircuit(p, setup.CellKeys, setup.Offsets, ids)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	t.Cleanup(circuit.Close)
	back := &backChain{ids: ids}
	t.Cleanup(back.close)
	for i, key := range setup.CellKeys {
		hop, err := wire.NewHop(p, key, setup.Offsets[i], i)
		if err != nil {
			t.Fatalf("NewHop %d: %v", i, err)
		}
		back.hops = append(back.hops, hop)
	}
	c := &Client{circuit: circuit, inbound: ids[0]}
	c.sent.Store(sent)
	return c, back
}

// a reply is taken only in turn and only for a cell the client wrote; anything
// else is refused under the class of the first check it fails, a cover reply
// exactly like a payload one
func TestOpenTakesAReplyOnlyInTurn(t *testing.T) {
	for _, s := range replySuites {
		t.Run(s.String(), func(t *testing.T) {
			p := replyProvider(t, s)

			t.Run("in turn", func(t *testing.T) {
				c, back := builtCircuit(t, p, 1)
				payload, cover, err := c.open(back.reply(t, 0, "pong"), 0)
				if err != nil || cover || string(payload) != "pong" {
					t.Fatalf("reply 0: %q, cover %v, %v", payload, cover, err)
				}
				payload, cover, err = c.open(back.cover(t, 0), 0)
				if err != nil || !cover || len(payload) != 0 {
					t.Fatalf("cover reply 0: %q, cover %v, %v", payload, cover, err)
				}
			})

			for _, tc := range []struct {
				name       string
				want, sent uint64
				cell       func(t *testing.T, c *Client, back *backChain) *wire.Cell
				refused    error
			}{
				{"copy of reply 0", 1, 2, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.reply(t, 0, "a")
				}, ErrReplyOutOfTurn},
				{"reply 1 before reply 0", 0, 2, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.reply(t, 1, "b")
				}, ErrReplyOutOfTurn},
				{"reply 2 after reply 0", 1, 3, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.reply(t, 2, "c")
				}, ErrReplyOutOfTurn},
				{"cover reply out of turn", 0, 2, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.cover(t, 1)
				}, ErrReplyOutOfTurn},
				{"reply before the first cell", 0, 0, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.reply(t, 0, "a")
				}, ErrReplyUnsolicited},
				{"one reply too many", 1, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.reply(t, 1, "b")
				}, ErrReplyUnsolicited},
				{"cover reply too many", 1, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.cover(t, 1)
				}, ErrReplyUnsolicited},
				{"zero body under the header of reply 0", 0, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return back.unsealed(t, 0)
				}, ErrReplyNotOpened},
				{"reply of another circuit under this identifier", 0, 1, func(t *testing.T, c *Client, _ *backChain) *wire.Cell {
					_, other := builtCircuit(t, p, 1)
					cell := other.reply(t, 0, "a")
					cell.SetCircuit(c.inbound)
					return cell
				}, ErrReplyNotOpened},
				{"forward cell of the same circuit", 0, 1, func(t *testing.T, c *Client, _ *backChain) *wire.Cell {
					cell, err := c.circuit.Seal(0, []byte("a"))
					if err != nil {
						t.Fatalf("Seal: %v", err)
					}
					return cell
				}, ErrReplyNotOpened},
				{"altered payload reply", 0, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return flipped(back.reply(t, 0, "a"), wire.CellSize-1, 0x01)
				}, ErrReplyNotOpened},
				{"altered cover reply", 0, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return flipped(back.cover(t, 0), wire.CellSize-1, 0x01)
				}, ErrReplyNotOpened},
				{"control kind under the header of reply 0", 0, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					cell := back.reply(t, 0, "a")
					cell[1] = byte(wire.KindControl)
					return cell
				}, ErrReplyHeader},
				{"identifier of another link", 0, 1, func(t *testing.T, _ *Client, back *backChain) *wire.Cell {
					return otherCircuit(back.reply(t, 0, "a"))
				}, ErrReplyHeader},
			} {
				t.Run(tc.name, func(t *testing.T) {
					c, back := builtCircuit(t, p, tc.sent)
					payload, cover, err := c.open(tc.cell(t, c, back), tc.want)
					if err != tc.refused {
						t.Fatalf("open = %v, want %v", err, tc.refused)
					}
					if payload != nil || cover {
						t.Fatalf("a refused reply gave payload %q, cover %v", payload, cover)
					}
				})
			}
		})
	}
}

// the header check and the layer of the first node between them cover every
// byte of a reply on the client's link: bytes 0 to 9 are the version, the kind
// and the identifier, the counter in bytes 10 to 17 enters every layer, and
// the layer of the first node spans the whole body
func TestAlteredBitAnywhereInAReplyIsRefused(t *testing.T) {
	for _, s := range replySuites {
		t.Run(s.String(), func(t *testing.T) {
			c, back := builtCircuit(t, replyProvider(t, s), 1)
			genuine := back.reply(t, 0, "pong")
			if payload, _, err := c.open(genuine, 0); err != nil || string(payload) != "pong" {
				t.Fatalf("the genuine reply: %q, %v", payload, err)
			}
			for at := 0; at < wire.CellSize; at++ {
				want := ErrReplyNotOpened
				if at < 10 {
					want = ErrReplyHeader
				}
				for _, mask := range []byte{0x01, 0x80} {
					if _, _, err := c.open(flipped(genuine, at, mask), 0); err != want {
						t.Fatalf("byte %d, mask %#02x: open = %v, want %v", at, mask, err, want)
					}
				}
			}
		})
	}
}

// plays every node of the chain by the test's own hand: it holds the key of
// each, opens the setup node by node and puts on the client's link exactly the
// cells the test gives it
type scriptedChain struct {
	*backChain
	conn *link.Conn
	raw  net.Conn
}

func acceptScripted(ln net.Listener, p jcrypto.CryptoProvider, privs []*secmem.Buffer) (*scriptedChain, error) {
	raw, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	conn, err := link.Accept(raw, p, privs[0])
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	s := &scriptedChain{backChain: &backChain{}, conn: conn, raw: raw}
	cell := new(wire.Cell)
	if err := conn.ReadCell(cell); err != nil {
		s.close()
		return nil, err
	}
	for i, priv := range privs {
		hdr, err := cell.Header()
		if err != nil {
			s.close()
			return nil, err
		}
		layer, err := wire.OpenSetup(p, priv, cell)
		if err != nil {
			s.close()
			return nil, fmt.Errorf("setup layer %d: %w", i, err)
		}
		hop, err := wire.NewHop(p, layer.CellKey, layer.Offsets, i)
		layer.CellKey.Release()
		if err != nil {
			s.close()
			return nil, err
		}
		s.hops = append(s.hops, hop)
		s.ids = append(s.ids, hdr.Circuit)
		if i+1 == len(privs) {
			break
		}
		if cell, err = wire.ForwardSetup(layer, i); err != nil {
			s.close()
			return nil, err
		}
	}
	return s, nil
}

func (s *scriptedChain) close() {
	_ = s.conn.Close()
	s.backChain.close()
}

func dialScripted(t *testing.T, p jcrypto.CryptoProvider) (*Client, *scriptedChain) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	privs := make([]*secmem.Buffer, replyHops)
	nodes := make([]Node, replyHops)
	for i := range nodes {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(priv.Release)
		privs[i] = priv
		nodes[i] = Node{Addr: fmt.Sprintf("node-%d:9000", i), StaticPub: pub}
	}
	nodes[0].Addr = ln.Addr().String()

	type accepted struct {
		s   *scriptedChain
		err error
	}
	got := make(chan accepted, 1)
	go func() {
		s, err := acceptScripted(ln, p, privs)
		got <- accepted{s, err}
	}()
	cl, err := Dial(Config{Provider: p, Chain: nodes})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	select {
	case a := <-got:
		if a.err != nil {
			t.Fatalf("the scripted chain: %v", a.err)
		}
		t.Cleanup(a.s.close)
		return cl, a.s
	case <-time.After(3 * time.Second):
		t.Fatal("the setup never reached the scripted chain")
		return nil, nil
	}
}

// waits for n forward cells, so the test knows the client has counted them
func (s *scriptedChain) read(t *testing.T, n int) {
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

// the client closes its socket at the cell it refuses, so only the writes up
// to that one have to succeed; bad < 0 means every write does
func (s *scriptedChain) send(t *testing.T, bad int, cells ...*wire.Cell) {
	t.Helper()
	for i, c := range cells {
		if err := s.conn.WriteCell(c); err != nil && (bad < 0 || i <= bad) {
			t.Fatalf("scripted chain, cell %d: %v", i, err)
		}
	}
}

// the client closed the link itself: the read ends in an error, not in the
// deadline
func (s *scriptedChain) expectClosedByClient(t *testing.T) {
	t.Helper()
	_ = s.raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var c wire.Cell
		err := s.conn.ReadCell(&c)
		if err == nil {
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("the client kept its link open")
		}
		return
	}
}

func write(t *testing.T, cl *Client, s *scriptedChain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := cl.Send([]byte("ping")); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	s.read(t, n)
}

func nextReply(t *testing.T, cl *Client) string {
	t.Helper()
	select {
	case got, open := <-cl.Replies():
		if !open {
			t.Fatal("the circuit closed while a reply was due")
		}
		return string(got)
	case <-time.After(3 * time.Second):
		t.Fatal("no reply came back")
		return ""
	}
}

// every reply the client passed on before its reply channel closed
func repliesUntilClosed(t *testing.T, cl *Client) []string {
	t.Helper()
	var got []string
	timeout := time.After(3 * time.Second)
	for {
		select {
		case reply, open := <-cl.Replies():
			if !open {
				return got
			}
			got = append(got, string(reply))
		case <-timeout:
			t.Fatal("the client kept the circuit")
		}
	}
}

// nothing is tolerated: the first reply that fails a check closes the link,
// leaves its class behind and lets nothing after it through
func TestFirstRefusedReplyEndsTheCircuit(t *testing.T) {
	type refusal struct {
		name string
		// cells the client writes before the chain answers
		written int
		cells   func(t *testing.T, s *scriptedChain) []*wire.Cell
		// index of the cell that must be refused
		bad       int
		delivered []string
		refused   error
		// both suites
		everySuite bool
	}
	cases := []refusal{
		{"copy", 2, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			first := s.reply(t, 0, "a")
			return []*wire.Cell{first, first}
		}, 1, []string{"a"}, ErrReplyOutOfTurn, true},
		{"altered body", 1, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{flipped(s.reply(t, 0, "a"), wire.CellSize/2, 0x01)}
		}, 0, nil, ErrReplyNotOpened, true},
		{"identifier of another link", 1, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{otherCircuit(s.reply(t, 0, "a"))}
		}, 0, nil, ErrReplyHeader, false},
		{"one reply too many", 1, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "a"), s.reply(t, 1, "b")}
		}, 1, []string{"a"}, ErrReplyUnsolicited, false},
		{"reply 1 before reply 0", 2, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 1, "b"), s.reply(t, 0, "a")}
		}, 0, nil, ErrReplyOutOfTurn, false},
		{"reply 2 after reply 0", 3, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{s.reply(t, 0, "a"), s.reply(t, 2, "c")}
		}, 1, []string{"a"}, ErrReplyOutOfTurn, false},
		// with any tolerance the genuine replies behind the unsealed cell would be
		// taken and the link would stay open
		{"unsealed cell ahead of genuine replies", 2, func(t *testing.T, s *scriptedChain) []*wire.Cell {
			return []*wire.Cell{s.unsealed(t, 0), s.reply(t, 0, "a"), s.reply(t, 1, "b")}
		}, 0, nil, ErrReplyNotOpened, false},
	}
	for _, chosen := range replySuites {
		for _, tc := range cases {
			if chosen != jcrypto.SuiteC25519 && !tc.everySuite {
				continue
			}
			t.Run(chosen.String()+"/"+tc.name, func(t *testing.T) {
				cl, s := dialScripted(t, replyProvider(t, chosen))
				write(t, cl, s, tc.written)
				s.send(t, tc.bad, tc.cells(t, s)...)

				if got := repliesUntilClosed(t, cl); !slices.Equal(got, tc.delivered) {
					t.Fatalf("the client passed on %q, want %q", got, tc.delivered)
				}
				if got := cl.Refused(); got != tc.refused {
					t.Fatalf("Refused = %v, want %v", got, tc.refused)
				}
				if !cl.Broken() {
					t.Fatal("Broken is false after a refused reply")
				}
				if err := cl.Send([]byte("ping")); err == nil {
					t.Fatal("Send went through after a refused reply")
				}
				s.expectClosedByClient(t)
			})
		}
	}
}

// replies in turn are not a refusal, whether they carry anything or not
func TestRepliesInTurnKeepTheCircuit(t *testing.T) {
	for _, chosen := range replySuites {
		t.Run(chosen.String(), func(t *testing.T) {
			cl, s := dialScripted(t, replyProvider(t, chosen))
			write(t, cl, s, 3)
			s.send(t, -1, s.cover(t, 0), s.reply(t, 1, "b"), s.cover(t, 2))
			if got := nextReply(t, cl); got != "b" {
				t.Fatalf("reply %q, want %q", got, "b")
			}
			// reply 3 is in turn only if the cover reply before it was taken
			write(t, cl, s, 1)
			s.send(t, -1, s.reply(t, 3, "d"))
			if got := nextReply(t, cl); got != "d" {
				t.Fatalf("reply %q, want %q", got, "d")
			}
			if err := cl.Refused(); err != nil || cl.Broken() {
				t.Fatalf("Refused = %v, Broken = %v on a circuit that only saw replies in turn", err, cl.Broken())
			}
		})
	}
}

// a reply that never comes is not a refusal: the far side closing the link
// with a cell still unanswered leaves no class behind
func TestCloseByTheFarSideIsNotARefusal(t *testing.T) {
	cl, s := dialScripted(t, replyProvider(t, jcrypto.SuiteC25519))
	write(t, cl, s, 2)
	s.send(t, -1, s.reply(t, 0, "a"))
	_ = s.conn.Close()

	if got := repliesUntilClosed(t, cl); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("the client passed on %q, want only %q", got, "a")
	}
	if err := cl.Refused(); err != nil || cl.Broken() {
		t.Fatalf("Refused = %v, Broken = %v after the far side closed the link", err, cl.Broken())
	}
}
