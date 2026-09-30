package wire_test

import (
	"bytes"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

const hops = 3

func provider() jcrypto.CryptoProvider { return c25519.New() }

func hopKeys(t *testing.T, p jcrypto.CryptoProvider, n int) []*secmem.Buffer {
	t.Helper()
	keys := make([]*secmem.Buffer, n)
	for i := range keys {
		k, err := secmem.New(p.KeySize())
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		// distinct, deterministic key per hop; the values do not matter here
		for j := range k.Bytes() {
			k.Bytes()[j] = byte(i*31 + j)
		}
		keys[i] = k
		t.Cleanup(k.Release)
	}
	return keys
}

// distinct, deterministic offsets per hop; setup derives them from the shared
// secret, here only their effect matters
func hopOffsets(n int) []wire.Offsets {
	offs := make([]wire.Offsets, n)
	for i := range offs {
		offs[i] = wire.Offsets{uint64(i+1) * 0x9e3779b97f4a7c15 % (1 << 62), uint64(i+7) * 0xc2b2ae3d27d4eb4f % (1 << 62)}
	}
	return offs
}

func newCircuit(t *testing.T, p jcrypto.CryptoProvider, keys []*secmem.Buffer, links ...uint64) *wire.Circuit {
	t.Helper()
	if len(links) == 0 {
		links = make([]uint64, len(keys))
		for i := range links {
			links[i] = uint64(100 + i)
		}
	}
	c, err := wire.NewCircuit(p, keys, hopOffsets(len(keys)), links)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// the chain: client seals, every relay peels its own layer, the exit reads the
// message
func TestChainRoundTrip(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	links := []uint64{100, 101, 102}
	circuit := newCircuit(t, p, keys, links...)

	msg := []byte("meet me at the usual place")
	cell, err := circuit.Seal(42, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	current := cell
	for i := 0; i < hops-1; i++ {
		hop, err := wire.NewHop(p, keys[i], hopOffsets(hops)[i], i)
		if err != nil {
			t.Fatalf("NewHop %d: %v", i, err)
		}
		next, err := hop.Peel(current)
		hop.Close()
		if err != nil {
			t.Fatalf("Peel %d: %v", i, err)
		}
		if len(next) != wire.CellSize {
			t.Fatalf("hop %d changed the cell size", i)
		}
		next.SetCircuit(links[i+1])
		current = next
	}

	exit, err := wire.NewHop(p, keys[hops-1], hopOffsets(hops)[hops-1], hops-1)
	if err != nil {
		t.Fatalf("NewHop exit: %v", err)
	}
	defer exit.Close()

	got, cover, err := exit.OpenLast(current)
	if err != nil || cover {
		t.Fatalf("OpenLast: cover %v, err %v", cover, err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// a cell looks the same whatever it carries: this is the property the whole
// metadata argument rests on
func TestCellSizeIsConstant(t *testing.T) {
	p := provider()
	circuit := newCircuit(t, p, hopKeys(t, p, hops))

	sizes := map[int]struct{}{}
	for _, payload := range [][]byte{
		nil,
		[]byte("a"),
		bytes.Repeat([]byte("x"), 100),
		bytes.Repeat([]byte("x"), circuit.MaxPayload()),
	} {
		cell, err := circuit.Seal(1, payload)
		if err != nil {
			t.Fatalf("Seal(%d): %v", len(payload), err)
		}
		sizes[len(cell)] = struct{}{}
	}
	cover, err := circuit.SealCover(2)
	if err != nil {
		t.Fatalf("Seal(cover): %v", err)
	}
	sizes[len(cover)] = struct{}{}

	if len(sizes) != 1 {
		t.Fatalf("cells differ in size: %v", sizes)
	}
	if _, ok := sizes[wire.CellSize]; !ok {
		t.Fatalf("cell size is not %d", wire.CellSize)
	}
}

// two cells with the same payload must not produce the same ciphertext, or an
// observer could match repeated messages
func TestCiphertextDiffersPerCounter(t *testing.T) {
	p := provider()
	circuit := newCircuit(t, p, hopKeys(t, p, hops))

	msg := []byte("same message")
	first, err := circuit.Seal(1, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := circuit.Seal(2, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first.Body(), second.Body()) {
		t.Fatal("identical ciphertext for different counters")
	}
}

func TestPayloadTooLarge(t *testing.T) {
	p := provider()
	circuit := newCircuit(t, p, hopKeys(t, p, hops))

	oversized := bytes.Repeat([]byte("x"), circuit.MaxPayload()+1)
	if _, err := circuit.Seal(1, oversized); err == nil {
		t.Fatal("Seal must reject an oversized payload")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	circuit := newCircuit(t, p, keys)

	cell, err := circuit.Seal(3, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	hop, err := wire.NewHop(p, keys[0], hopOffsets(hops)[0], 0)
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer hop.Close()

	tampered := *cell
	tampered[wire.CellSize-1] ^= 0xFF
	if _, err := hop.Peel(&tampered); err == nil {
		t.Fatal("a modified body must not open")
	}

	movedCounter := *cell
	movedCounter[17] ^= 0x01
	if _, err := hop.Peel(&movedCounter); err == nil {
		t.Fatal("a modified counter must not open")
	}

	movedKind := *cell
	movedKind[1] = byte(wire.KindControl)
	if _, err := hop.Peel(&movedKind); err == nil {
		t.Fatal("a modified kind must not open")
	}
}

// a cell belongs to its position in the chain: replaying it into another hop
// must fail even when the attacker knows that hop's key
func TestLayerIsBoundToHopIndex(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	circuit := newCircuit(t, p, keys)

	cell, err := circuit.Seal(8, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wrong, err := wire.NewHop(p, keys[0], hopOffsets(hops)[0], 1) // right key, wrong position
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer wrong.Close()

	if _, err := wrong.Peel(cell); err == nil {
		t.Fatal("a layer must not open at the wrong hop index")
	}
}

// the circuit identifier is rewritten on every link, so it must not be part of
// what a layer authenticates
func TestCircuitIDIsPerLink(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	circuit := newCircuit(t, p, keys)

	cell, err := circuit.Seal(5, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cell.SetCircuit(999)

	hop, err := wire.NewHop(p, keys[0], hopOffsets(hops)[0], 0)
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer hop.Close()

	// the nonce is derived from the circuit id, so rewriting it changes the
	// nonce and the cell must not open with the old one
	if _, err := hop.Peel(cell); err == nil {
		t.Fatal("rewritten circuit id must change the nonce")
	}
}

func TestReplayWindow(t *testing.T) {
	w := wire.NewReplayWindow(64)

	if !w.Accept(100) {
		t.Fatal("first counter must be accepted")
	}
	if w.Accept(100) {
		t.Fatal("repeated counter must be rejected")
	}
	if !w.Accept(101) {
		t.Fatal("next counter must be accepted")
	}
	if !w.Accept(99) {
		t.Fatal("slightly out of order counter must be accepted")
	}
	if w.Accept(99) {
		t.Fatal("repeat inside the window must be rejected")
	}
	if !w.Accept(200) {
		t.Fatal("jump forward must be accepted")
	}
	if w.Accept(101) {
		t.Fatal("counter that fell out of the window must be rejected")
	}
}

// window 64: top 200 accepts 137..200 and refuses 136, which is 64 behind;
// jumping to 300 drops every mark, so 250 is new but 236 is too old
func TestReplayWindowEdges(t *testing.T) {
	w := wire.NewReplayWindow(64)
	for _, c := range []uint64{200, 137} {
		if !w.Accept(c) {
			t.Fatalf("counter %d must be accepted", c)
		}
	}
	if w.Accept(136) || w.Accept(137) {
		t.Fatal("a counter 64 behind and a repeat must both be refused")
	}
	if !w.Accept(300) || !w.Accept(250) {
		t.Fatal("a jump and a counter inside the new window must be accepted")
	}
	if w.Accept(236) {
		t.Fatal("236 is 64 behind 300 and must be refused")
	}
}

// a forged cell with a far counter fails authentication; if its counter were
// recorded anyway, every genuine cell after it would look too old
func TestCheckDoesNotMoveTheWindow(t *testing.T) {
	w := wire.NewReplayWindow(64)
	if !w.Commit(10) {
		t.Fatal("first counter must be committed")
	}
	if !w.Check(1 << 40) {
		t.Fatal("a far counter must pass the check")
	}
	if !w.Check(11) || !w.Commit(11) {
		t.Fatal("the next genuine counter must still pass after a check alone")
	}
	if w.Commit(11) {
		t.Fatal("a committed counter must not commit twice")
	}
}

func TestMaxPayloadShrinksWithChain(t *testing.T) {
	p := provider()
	short := newCircuit(t, p, hopKeys(t, p, 1))
	long := newCircuit(t, p, hopKeys(t, p, 3))

	if long.MaxPayload() >= short.MaxPayload() {
		t.Fatalf("a longer chain must carry less: %d vs %d", long.MaxPayload(), short.MaxPayload())
	}
	if long.MaxPayload() <= 0 {
		t.Fatal("three hops must still leave room for a payload")
	}
	t.Logf("payload per cell: 1 hop %d bytes, 3 hops %d bytes", short.MaxPayload(), long.MaxPayload())
}

// a relay before the exit sees the header and its own layer only; a cover
// cell must look to it exactly like a payload cell with the same counter
func TestCoverIsHiddenFromEveryHopButTheExit(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	links := []uint64{100, 101, 102}
	payloadCircuit := newCircuit(t, p, keys, links...)

	payload, err := payloadCircuit.Seal(9, []byte("real"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cover, err := payloadCircuit.SealCover(9)
	if err != nil {
		t.Fatalf("SealCover: %v", err)
	}

	cells := []*wire.Cell{payload, cover}
	for i := 0; i < hops-1; i++ {
		hop, err := wire.NewHop(p, keys[i], hopOffsets(hops)[i], i)
		if err != nil {
			t.Fatalf("NewHop %d: %v", i, err)
		}
		first := *cells[0]
		for j, c := range cells {
			if !bytes.Equal(c[:18], first[:18]) {
				t.Fatalf("hop %d sees a different header on cell %d", i, j)
			}
			out, err := hop.Peel(c)
			if err != nil {
				t.Fatalf("hop %d Peel: %v", i, err)
			}
			out.SetCircuit(links[i+1])
			cells[j] = out
		}
		hop.Close()
	}

	exit, err := wire.NewHop(p, keys[hops-1], hopOffsets(hops)[hops-1], hops-1)
	if err != nil {
		t.Fatalf("NewHop exit: %v", err)
	}
	defer exit.Close()
	if got, isCover, err := exit.OpenLast(cells[0]); err != nil || isCover || string(got) != "real" {
		t.Fatalf("payload at the exit: %q, cover %v, err %v", got, isCover, err)
	}
	if got, isCover, err := exit.OpenLast(cells[1]); err != nil || !isCover || len(got) != 0 {
		t.Fatalf("cover at the exit: %q, cover %v, err %v", got, isCover, err)
	}
}

// the old cover kind no longer exists on the wire; a header carrying it is
// malformed and dropped before any key is used
func TestRetiredCoverKindIsRejected(t *testing.T) {
	var c wire.Cell
	c[0], c[1] = wire.Version, 2
	if _, err := c.Header(); !errors.Is(err, wire.ErrKind) {
		t.Fatalf("Header: %v, want ErrKind", err)
	}
}

// a cell out and its reply back through three hops on either suite: every link
// carries its own counter, and the layers still open at the exit and at the
// client
func TestEveryLinkCarriesItsOwnCounter(t *testing.T) {
	for _, p := range []jcrypto.CryptoProvider{c25519.New(), gost.New()} {
		t.Run(p.Suite().String(), func(t *testing.T) {
			keys := hopKeys(t, p, hops)
			links := []uint64{100, 101, 102}
			circuit := newCircuit(t, p, keys, links...)
			nodes := make([]*wire.Hop, hops)
			for i := range nodes {
				h, err := wire.NewHop(p, keys[i], hopOffsets(hops)[i], i)
				if err != nil {
					t.Fatalf("NewHop %d: %v", i, err)
				}
				defer h.Close()
				nodes[i] = h
			}

			cell, err := circuit.Seal(7, []byte("out"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			var fwd []uint64
			for i := 0; i < hops-1; i++ {
				h, _ := cell.Header()
				fwd = append(fwd, h.Counter)
				if cell, err = nodes[i].Peel(cell); err != nil {
					t.Fatalf("Peel %d: %v", i, err)
				}
				cell.SetCircuit(links[i+1])
			}
			h, _ := cell.Header()
			fwd = append(fwd, h.Counter)
			if got, _, err := nodes[hops-1].OpenLast(cell); err != nil || string(got) != "out" {
				t.Fatalf("OpenLast: %q, %v", got, err)
			}

			back, err := nodes[hops-1].SealReply(links[hops-1], 7, []byte("back"))
			if err != nil {
				t.Fatalf("SealReply: %v", err)
			}
			var bwd []uint64
			for i := hops - 2; i >= 0; i-- {
				h, _ := back.Header()
				bwd = append(bwd, h.Counter)
				if back, err = nodes[i].Wrap(back, links[i]); err != nil {
					t.Fatalf("Wrap %d: %v", i, err)
				}
			}
			h, _ = back.Header()
			bwd = append(bwd, h.Counter)
			if got, _, err := circuit.OpenExit(back, wire.Backward); err != nil || string(got) != "back" {
				t.Fatalf("OpenExit: %q, %v", got, err)
			}

			if fwd[0] != 7 {
				t.Fatalf("the client's own link carries %d, want the base counter 7", fwd[0])
			}
			for _, values := range [][]uint64{fwd, bwd} {
				for i := range values {
					for j := i + 1; j < len(values); j++ {
						if values[i] == values[j] {
							t.Fatalf("two links carry counter %d: %v", values[i], values)
						}
					}
				}
			}
		})
	}
}

// the base counter stops short of the nonce limit, so a link value never wraps
// onto one already used
func TestCounterPastTheLimitIsRefused(t *testing.T) {
	p := provider()
	keys := hopKeys(t, p, hops)
	circuit := newCircuit(t, p, keys)
	if _, err := circuit.Seal(1<<60, []byte("late")); err == nil {
		t.Fatal("Seal accepted a base counter at the limit")
	}
	exit, err := wire.NewHop(p, keys[hops-1], hopOffsets(hops)[hops-1], hops-1)
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	if _, err := exit.SealReply(1, 1<<60, nil); err == nil {
		t.Fatal("SealReply accepted a base counter at the limit")
	}
	middle, err := wire.NewHop(p, keys[1], hopOffsets(hops)[1], 1)
	if err != nil {
		t.Fatal(err)
	}
	defer middle.Close()
	reply, err := exit.SealReply(1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := reply.Header()
	far, err := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: 1, Counter: h.Counter | 1<<62}, reply.Body())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := middle.Wrap(far, 2); err == nil {
		t.Fatal("Wrap accepted a counter past the nonce limit")
	}
}
