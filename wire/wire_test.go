package wire_test

import (
	"bytes"
	"errors"
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/wire"
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

func newCircuit(t *testing.T, p jcrypto.CryptoProvider, keys []*secmem.Buffer, links ...uint64) *wire.Circuit {
	t.Helper()
	if len(links) == 0 {
		links = make([]uint64, len(keys))
		for i := range links {
			links[i] = uint64(100 + i)
		}
	}
	c, err := wire.NewCircuit(p, keys, links)
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
		hop, err := wire.NewHop(p, keys[i], i)
		if err != nil {
			t.Fatalf("NewHop %d: %v", i, err)
		}
		next, err := hop.Peel(current, wire.Forward)
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

	exit, err := wire.NewHop(p, keys[hops-1], hops-1)
	if err != nil {
		t.Fatalf("NewHop exit: %v", err)
	}
	defer exit.Close()

	got, cover, err := exit.OpenLast(current, wire.Forward)
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

	hop, err := wire.NewHop(p, keys[0], 0)
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer hop.Close()

	tampered := *cell
	tampered[wire.CellSize-1] ^= 0xFF
	if _, err := hop.Peel(&tampered, wire.Forward); err == nil {
		t.Fatal("a modified body must not open")
	}

	movedCounter := *cell
	movedCounter[17] ^= 0x01
	if _, err := hop.Peel(&movedCounter, wire.Forward); err == nil {
		t.Fatal("a modified counter must not open")
	}

	movedKind := *cell
	movedKind[1] = byte(wire.KindControl)
	if _, err := hop.Peel(&movedKind, wire.Forward); err == nil {
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

	wrong, err := wire.NewHop(p, keys[0], 1) // right key, wrong position
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer wrong.Close()

	if _, err := wrong.Peel(cell, wire.Forward); err == nil {
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

	hop, err := wire.NewHop(p, keys[0], 0)
	if err != nil {
		t.Fatalf("NewHop: %v", err)
	}
	defer hop.Close()

	// the nonce is derived from the circuit id, so rewriting it changes the
	// nonce and the cell must not open with the old one
	if _, err := hop.Peel(cell, wire.Forward); err == nil {
		t.Fatal("rewritten circuit id must change the nonce")
	}
}

func TestReplayWindow(t *testing.T) {
	w := wire.NewReplayWindow(8)

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
		hop, err := wire.NewHop(p, keys[i], i)
		if err != nil {
			t.Fatalf("NewHop %d: %v", i, err)
		}
		first := *cells[0]
		for j, c := range cells {
			if !bytes.Equal(c[:18], first[:18]) {
				t.Fatalf("hop %d sees a different header on cell %d", i, j)
			}
			out, err := hop.Peel(c, wire.Forward)
			if err != nil {
				t.Fatalf("hop %d Peel: %v", i, err)
			}
			out.SetCircuit(links[i+1])
			cells[j] = out
		}
		hop.Close()
	}

	exit, err := wire.NewHop(p, keys[hops-1], hops-1)
	if err != nil {
		t.Fatalf("NewHop exit: %v", err)
	}
	defer exit.Close()
	if got, isCover, err := exit.OpenLast(cells[0], wire.Forward); err != nil || isCover || string(got) != "real" {
		t.Fatalf("payload at the exit: %q, cover %v, err %v", got, isCover, err)
	}
	if got, isCover, err := exit.OpenLast(cells[1], wire.Forward); err != nil || !isCover || len(got) != 0 {
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
