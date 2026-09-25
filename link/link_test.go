package link_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/link"
	"github.com/blsssss/jimichi/wire"
)

type recorder struct {
	net.Conn
	seen bytes.Buffer
}

func (r *recorder) Write(b []byte) (int, error) {
	r.seen.Write(b)
	return r.Conn.Write(b)
}

func pair(t *testing.T, authenticate bool) (*link.Conn, *link.Conn, *recorder) {
	t.Helper()
	p := c25519.New()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)

	a, b := net.Pipe()
	rec := &recorder{Conn: a}

	type res struct {
		c   *link.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := link.Accept(b, p, priv)
		done <- res{c, err}
	}()

	var static []byte
	if authenticate {
		static = pub
	}
	client, err := link.Dial(rec, p, static)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("Accept: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })
	return client, r.c, rec
}

func sample(counter uint64) *wire.Cell {
	body := bytes.Repeat([]byte{0x5A}, wire.BodySize)
	c, _ := wire.NewCell(wire.Header{Kind: wire.KindPayload, Circuit: 0xCAFE, Counter: counter}, body)
	return c
}

func TestCellsCrossTheLink(t *testing.T) {
	for _, auth := range []bool{false, true} {
		client, server, _ := pair(t, auth)
		go func() {
			for i := uint64(0); i < 3; i++ {
				_ = client.WriteCell(sample(i))
			}
		}()
		for i := uint64(0); i < 3; i++ {
			var got wire.Cell
			if err := server.ReadCell(&got); err != nil {
				t.Fatalf("ReadCell: %v", err)
			}
			h, err := got.Header()
			if err != nil || h.Counter != i {
				t.Fatalf("cell %d: header %+v, err %v", i, h, err)
			}
		}
	}
}

// the whole point of the layer: nothing of the cell header is visible on the
// wire, so counters cannot be matched across links
func TestHeaderIsHidden(t *testing.T) {
	client, server, rec := pair(t, true)
	go func() { _ = client.WriteCell(sample(0x0102030405060708)) }()
	var got wire.Cell
	if err := server.ReadCell(&got); err != nil {
		t.Fatalf("ReadCell: %v", err)
	}

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, 0x0102030405060708)
	circuit := make([]byte, 8)
	binary.BigEndian.PutUint64(circuit, 0xCAFE)
	wire := rec.seen.Bytes()
	if bytes.Contains(wire, counter) || bytes.Contains(wire, circuit) {
		t.Fatal("cell header leaked onto the wire")
	}
	if bytes.Contains(wire, bytes.Repeat([]byte{0x5A}, 32)) {
		t.Fatal("cell body leaked onto the wire")
	}
}

func TestFramesHaveOneSize(t *testing.T) {
	client, server, rec := pair(t, false)
	p := c25519.New()
	hs, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)

	go func() {
		for i := uint64(0); i < 4; i++ {
			_ = client.WriteCell(sample(i))
		}
	}()
	for i := 0; i < 4; i++ {
		var got wire.Cell
		if err := server.ReadCell(&got); err != nil {
			t.Fatal(err)
		}
	}
	if n := rec.seen.Len() - hs; n != 4*frame {
		t.Fatalf("wire carried %d bytes after the handshake, want %d", n, 4*frame)
	}
}

func TestWrongStaticKeyFails(t *testing.T) {
	p := c25519.New()
	priv, _, _ := p.GenerateEphemeral()
	defer priv.Release()
	_, otherPub, _ := p.GenerateEphemeral()

	a, b := net.Pipe()
	errs := make(chan error, 1)
	go func() {
		srv, err := link.Accept(b, p, priv)
		if err != nil {
			errs <- err
			return
		}
		var c wire.Cell
		errs <- srv.ReadCell(&c)
	}()

	client, err := link.Dial(a, p, otherPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = client.WriteCell(sample(1))
	if err := <-errs; err == nil {
		t.Fatal("a client holding the wrong static key must not get through")
	}
}

// padding costs a frame of the same size on the wire and never reaches the reader
func TestPaddingIsDroppedByTheReceiver(t *testing.T) {
	client, server, rec := pair(t, false)
	p := c25519.New()
	hs, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)

	go func() {
		_ = client.WritePadding()
		_ = client.WriteCell(sample(7))
		_ = client.WritePadding()
		_ = client.WritePadding()
		_ = client.WriteCell(sample(8))
	}()
	for _, want := range []uint64{7, 8} {
		var got wire.Cell
		if err := server.ReadCell(&got); err != nil {
			t.Fatalf("ReadCell: %v", err)
		}
		h, err := got.Header()
		if err != nil || h.Counter != want || h.Kind != wire.KindPayload {
			t.Fatalf("got %+v, err %v, want payload %d", h, err, want)
		}
	}
	if n := rec.seen.Len() - hs; n != 5*frame {
		t.Fatalf("wire carried %d bytes after the handshake, want %d", n, 5*frame)
	}
}
