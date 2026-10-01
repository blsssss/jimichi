package link_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/link"
	"github.com/jimichi-org/jimichi/wire"
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
	c, _ := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: 0xCAFE, Counter: counter}, body)
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

// padding costs a frame of the same size on the wire and never reaches the reader
func TestPaddingIsDroppedByTheReceiver(t *testing.T) {
	client, server, rec := pair(t, false)
	p := c25519.New()
	hs, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)

	go func() {
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(sample(7))
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(wire.NewPadding())
		_ = client.WriteCell(sample(8))
	}()
	for _, want := range []uint64{7, 8} {
		var got wire.Cell
		if err := server.ReadCell(&got); err != nil {
			t.Fatalf("ReadCell: %v", err)
		}
		h, err := got.Header()
		if err != nil || h.Counter != want || h.Kind != wire.KindData {
			t.Fatalf("got %+v, err %v, want payload %d", h, err, want)
		}
	}
	if n := rec.seen.Len() - hs; n != 5*frame {
		t.Fatalf("wire carried %d bytes after the handshake, want %d", n, 5*frame)
	}
}

// a peer that stops reading must not hold the writer, and once a frame has
// failed the link sends nothing more: the peer's frame numbers are out of step
func TestWriteGivesUpOnAPeerThatStopsReading(t *testing.T) {
	client, server, _ := pair(t, false)
	client.SetWriteTimeout(50 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- client.WriteCell(sample(1)) }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write returned %v, want a deadline error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write still blocked on a peer that does not read")
	}

	go func() {
		var cell wire.Cell
		_ = server.ReadCell(&cell)
	}()
	if err := client.WriteCell(sample(2)); err == nil {
		t.Fatal("the link sent a frame after a failed one")
	}
}

// counts both directions of the initiator's side of a link
type meter struct {
	net.Conn
	mu            sync.Mutex
	read, written int
}

func (m *meter) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	m.mu.Lock()
	m.read += n
	m.mu.Unlock()
	return n, err
}

func (m *meter) Write(b []byte) (int, error) {
	n, err := m.Conn.Write(b)
	m.mu.Lock()
	m.written += n
	m.mu.Unlock()
	return n, err
}

func (m *meter) totals() (read, written int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.read, m.written
}

// the handshake is the hello one way and the public key with one confirming
// frame the other way, in both modes; cells then flow both ways and none of
// them is the confirmation
func TestResponderConfirmsTheKeys(t *testing.T) {
	p := c25519.New()
	hello, _ := link.InitiatorHandshakeSize(p)
	answer, _ := link.ResponderHandshakeSize(p)
	frame, _ := link.FrameSize(p)
	if answer != hello-1+frame {
		t.Fatalf("responder handshake of %d bytes, want the key and one frame, %d", answer, hello-1+frame)
	}
	for _, auth := range []bool{false, true} {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer priv.Release()
		a, b := net.Pipe()
		m := &meter{Conn: a}
		accepted := make(chan *link.Conn, 1)
		go func() {
			srv, err := link.Accept(b, p, priv)
			if err != nil {
				t.Errorf("Accept: %v", err)
			}
			accepted <- srv
		}()
		var static []byte
		if auth {
			static = pub
		}
		client, err := link.Dial(m, p, static)
		if err != nil {
			t.Fatalf("auth %v: Dial: %v", auth, err)
		}
		server := <-accepted
		if server == nil {
			t.FailNow()
		}
		if read, written := m.totals(); read != answer || written != hello {
			t.Fatalf("auth %v: the initiator read %d and wrote %d bytes in the handshake, want %d and %d", auth, read, written, answer, hello)
		}

		go func() {
			_ = server.WriteCell(sample(41))
			_ = server.WriteCell(sample(42))
		}()
		for _, want := range []uint64{41, 42} {
			var got wire.Cell
			if err := client.ReadCell(&got); err != nil {
				t.Fatalf("auth %v: ReadCell: %v", auth, err)
			}
			if h, err := got.Header(); err != nil || h.Counter != want {
				t.Fatalf("auth %v: got %+v, %v, want cell %d", auth, h, err, want)
			}
		}
		if read, _ := m.totals(); read != answer+2*frame {
			t.Fatalf("auth %v: %d bytes came back for two cells after the handshake, want %d", auth, read-answer, 2*frame)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

func TestWrongStaticKeyFailsTheHandshake(t *testing.T) {
	p := c25519.New()
	priv, _, _ := p.GenerateEphemeral()
	defer priv.Release()
	_, otherPub, _ := p.GenerateEphemeral()
	hello, _ := link.InitiatorHandshakeSize(p)

	a, b := net.Pipe()
	defer a.Close()
	m := &meter{Conn: a}
	go func() {
		if srv, err := link.Accept(b, p, priv); err == nil {
			defer srv.Close()
			var c wire.Cell
			_ = srv.ReadCell(&c)
		}
	}()

	client, err := link.Dial(m, p, otherPub)
	if !errors.Is(err, link.ErrHandshake) || client != nil {
		t.Fatalf("Dial with a key the responder does not hold = %v, want %v", err, link.ErrHandshake)
	}
	if _, written := m.totals(); written != hello {
		t.Fatalf("the initiator wrote %d bytes, want its hello of %d and nothing after it", written, hello)
	}
}

// what a responder would write that derived the anonymous keys correctly: its
// public key and frame 0 carrying the given cell
func answerWith(t *testing.T, conn net.Conn, first *wire.Cell) {
	t.Helper()
	p := c25519.New()
	n, _ := link.InitiatorHandshakeSize(p)
	hello := make([]byte, n)
	if _, err := io.ReadFull(conn, hello); err != nil {
		t.Errorf("hello: %v", err)
		return
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Error(err)
		return
	}
	defer priv.Release()
	secret, err := p.Agree(priv, hello[1:], hello[1:])
	if err != nil {
		t.Error(err)
		return
	}
	defer secret.Release()
	key, err := p.DeriveKey(secret, []byte("jimichi/link/r2i"), p.KeySize())
	if err != nil {
		t.Error(err)
		return
	}
	defer key.Release()
	aead, err := p.NewAEAD(key)
	if err != nil {
		t.Error(err)
		return
	}
	defer aead.Destroy()
	frame := aead.Seal(nil, make([]byte, aead.NonceSize()), first[:], nil)
	_, _ = conn.Write(append(pub, frame...))
}

func TestHandshakeNeedsTheConfirmation(t *testing.T) {
	p := c25519.New()
	hello, _ := link.InitiatorHandshakeSize(p)
	frame, _ := link.FrameSize(p)
	_, pub, _ := p.GenerateEphemeral()

	for _, tc := range []struct {
		name    string
		respond func(conn net.Conn)
		ok      bool
		timeout bool
	}{
		{"a padding cell under the right keys", func(conn net.Conn) { answerWith(t, conn, wire.NewPadding()) }, true, false},
		{"a data cell under the right keys", func(conn net.Conn) { answerWith(t, conn, sample(0)) }, false, false},
		{"a frame of noise", func(conn net.Conn) {
			_, _ = io.ReadFull(conn, make([]byte, hello))
			_, _ = conn.Write(append(bytes.Clone(pub), bytes.Repeat([]byte{0xA5}, frame)...))
		}, false, false},
		{"the key and then silence", func(conn net.Conn) {
			_, _ = io.ReadFull(conn, make([]byte, hello))
			_, _ = conn.Write(pub)
		}, false, true},
		{"the key and then a closed connection", func(conn net.Conn) {
			_, _ = io.ReadFull(conn, make([]byte, hello))
			_, _ = conn.Write(pub)
			_ = conn.Close()
		}, false, false},
	} {
		a, b := net.Pipe()
		m := &meter{Conn: a}
		go tc.respond(b)
		_ = a.SetDeadline(time.Now().Add(200 * time.Millisecond))
		client, err := link.Dial(m, p, nil)
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: Dial = %v, want a link", tc.name, err)
		case !tc.ok && !errors.Is(err, link.ErrHandshake):
			t.Errorf("%s: Dial = %v, want %v", tc.name, err, link.ErrHandshake)
		case tc.timeout && !errors.Is(err, os.ErrDeadlineExceeded):
			t.Errorf("%s: Dial = %v, want the caller's deadline to end the wait", tc.name, err)
		}
		if _, written := m.totals(); written != hello {
			t.Errorf("%s: the initiator wrote %d bytes, want only its hello of %d", tc.name, written, hello)
		}
		if client != nil {
			_ = client.Close()
		}
		_ = a.Close()
		_ = b.Close()
	}
}
