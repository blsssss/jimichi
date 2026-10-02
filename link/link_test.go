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

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
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

func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			run(t, p)
		})
	}
}

func modeName(auth bool) string {
	if auth {
		return "authenticated"
	}
	return "anonymous"
}

func eachMode(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider, auth bool)) {
	t.Helper()
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		for _, auth := range []bool{false, true} {
			t.Run(modeName(auth), func(t *testing.T) { run(t, p, auth) })
		}
	})
}

func keyPair(t *testing.T, p jcrypto.CryptoProvider) (*secmem.Buffer, []byte) {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Release)
	return priv, pub
}

func pairOn(t *testing.T, p jcrypto.CryptoProvider, authenticate bool) (*link.Conn, *link.Conn, *recorder) {
	t.Helper()
	priv, pub := keyPair(t, p)

	a, b := net.Pipe()
	rec := &recorder{Conn: a}

	type res struct {
		c   *link.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := link.Accept(b, p, priv, pub)
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

func pair(t *testing.T, authenticate bool) (*link.Conn, *link.Conn, *recorder) {
	t.Helper()
	return pairOn(t, c25519.New(), authenticate)
}

func sample(counter uint64) *wire.Cell {
	body := bytes.Repeat([]byte{0x5A}, wire.BodySize)
	c, _ := wire.NewCell(wire.Header{Kind: wire.KindData, Circuit: 0xCAFE, Counter: counter}, body)
	return c
}

func TestCellsCrossTheLink(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		client, server, _ := pairOn(t, p, auth)
		for _, dir := range []struct {
			name     string
			from, to *link.Conn
		}{{"initiator to responder", client, server}, {"responder to initiator", server, client}} {
			go func() {
				for i := uint64(0); i < 3; i++ {
					_ = dir.from.WriteCell(sample(i))
				}
			}()
			for i := uint64(0); i < 3; i++ {
				var got wire.Cell
				if err := dir.to.ReadCell(&got); err != nil {
					t.Fatalf("%s: ReadCell: %v", dir.name, err)
				}
				h, err := got.Header()
				if err != nil || h.Counter != i {
					t.Fatalf("%s: cell %d: header %+v, err %v", dir.name, i, h, err)
				}
			}
		}
	})
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

// counts both directions of the initiator's side of a link, and stands in for
// whoever sits on the wire: flipWritten and flipRead name a byte of the stream
// in that direction and the bits to change in it
type meter struct {
	net.Conn
	mu            sync.Mutex
	read, written int

	flipWritten, flipRead map[int]byte
}

func flipped(b []byte, at int, flips map[int]byte) []byte {
	if len(flips) == 0 {
		return b
	}
	out := bytes.Clone(b)
	for i := range out {
		out[i] ^= flips[at+i]
	}
	return out
}

func (m *meter) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	m.mu.Lock()
	copy(b[:n], flipped(b[:n], m.read, m.flipRead))
	m.read += n
	m.mu.Unlock()
	return n, err
}

func (m *meter) Write(b []byte) (int, error) {
	m.mu.Lock()
	out := flipped(b, m.written, m.flipWritten)
	m.mu.Unlock()
	n, err := m.Conn.Write(out)
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
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		hello, _ := link.InitiatorHandshakeSize(p)
		answer, _ := link.ResponderHandshakeSize(p)
		frame, _ := link.FrameSize(p)
		if answer != hello-1+frame {
			t.Fatalf("responder handshake of %d bytes, want the key and one frame, %d", answer, hello-1+frame)
		}
		priv, pub := keyPair(t, p)
		a, b := net.Pipe()
		m := &meter{Conn: a}
		accepted := make(chan *link.Conn, 1)
		go func() {
			srv, err := link.Accept(b, p, priv, pub)
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
			t.Fatalf("Dial: %v", err)
		}
		server := <-accepted
		if server == nil {
			t.FailNow()
		}
		if read, written := m.totals(); read != answer || written != hello {
			t.Fatalf("the initiator read %d and wrote %d bytes in the handshake, want %d and %d", read, written, answer, hello)
		}

		go func() {
			_ = server.WriteCell(sample(41))
			_ = server.WriteCell(sample(42))
		}()
		for _, want := range []uint64{41, 42} {
			var got wire.Cell
			if err := client.ReadCell(&got); err != nil {
				t.Fatalf("ReadCell: %v", err)
			}
			if h, err := got.Header(); err != nil || h.Counter != want {
				t.Fatalf("got %+v, %v, want cell %d", h, err, want)
			}
		}
		if read, _ := m.totals(); read != answer+2*frame {
			t.Fatalf("%d bytes came back for two cells after the handshake, want %d", read-answer, 2*frame)
		}
		_ = client.Close()
		_ = server.Close()
	})
}

// a handshake between Dial and Accept that must fail at the initiator, which
// has then written its hello and nothing else
func refused(t *testing.T, p jcrypto.CryptoProvider, m *meter, b net.Conn, dialStatic []byte, acceptPriv *secmem.Buffer, acceptPub []byte) {
	t.Helper()
	hello, _ := link.InitiatorHandshakeSize(p)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if srv, err := link.Accept(b, p, acceptPriv, acceptPub); err == nil {
			defer srv.Close()
			var c wire.Cell
			_ = srv.ReadCell(&c)
		}
	}()

	client, err := link.Dial(m, p, dialStatic)
	if !errors.Is(err, link.ErrHandshake) || client != nil {
		t.Fatalf("Dial = %v, want %v", err, link.ErrHandshake)
	}
	if _, written := m.totals(); written != hello {
		t.Fatalf("the initiator wrote %d bytes, want its hello of %d and nothing after it", written, hello)
	}
	_ = m.Close()
	_ = b.Close()
	<-done
}

func TestWrongStaticKeyFailsTheHandshake(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		_, otherPub := keyPair(t, p)
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, otherPub, priv, pub)
	})
}

// the responder holds the right private key and names other bytes as its
// published key: the initiator put the descriptor's bytes into the transcript
func TestResponderNamingAnotherKeyIsNotConfirmed(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		_, otherPub := keyPair(t, p)
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, pub, priv, otherPub)
	})

	// X25519 drops the top bit, so this is the same point written another way
	t.Run("another encoding of the same key", func(t *testing.T) {
		p := c25519.New()
		priv, pub := keyPair(t, p)
		other := bytes.Clone(pub)
		other[len(other)-1] ^= 0x80
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a}, b, pub, priv, other)
	})
}

// the mode byte is part of the transcript: a hello moved to the other mode on
// the way is answered under keys the initiator does not derive
func TestFlippedModeByteFailsTheHandshake(t *testing.T) {
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		priv, pub := keyPair(t, p)
		var static []byte
		if auth {
			static = pub
		}
		a, b := net.Pipe()
		refused(t, p, &meter{Conn: a, flipWritten: map[int]byte{0: 0x01}}, b, static, priv, pub)
	})
}

// X25519 ignores the top bit of a public key, so a key re-encoded on the way
// gives both sides the same raw agreement; the transcripts differ
func TestReencodedEphemeralKeyFailsTheHandshake(t *testing.T) {
	p := c25519.New()
	hello, _ := link.InitiatorHandshakeSize(p)
	for _, auth := range []bool{false, true} {
		for _, tc := range []struct {
			name          string
			written, read map[int]byte
		}{
			{"the initiator's key", map[int]byte{hello - 1: 0x80}, nil},
			{"the responder's key", nil, map[int]byte{hello - 2: 0x80}},
		} {
			t.Run(modeName(auth)+"/"+tc.name, func(t *testing.T) {
				priv, pub := keyPair(t, p)
				var static []byte
				if auth {
					static = pub
				}
				a, b := net.Pipe()
				m := &meter{Conn: a, flipWritten: tc.written, flipRead: tc.read}
				refused(t, p, m, b, static, priv, pub)
			})
		}
	}
}

// an authenticated hello to a responder that holds no link key is refused
// before the responder generates or agrees anything
func TestAuthenticatedHelloNeedsALinkKey(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		priv, pub := keyPair(t, p)
		for _, tc := range []struct {
			name string
			priv *secmem.Buffer
			pub  []byte
		}{
			{"no key", nil, nil},
			{"no public key", priv, nil},
			{"no private key", nil, pub},
			{"a short public key", priv, pub[:len(pub)-1]},
		} {
			a, b := net.Pipe()
			m := &meter{Conn: b}
			go func() { _, _ = a.Write(append([]byte{1}, pub...)) }()
			_ = b.SetDeadline(time.Now().Add(2 * time.Second))
			conn, err := link.Accept(m, p, tc.priv, tc.pub)
			if !errors.Is(err, link.ErrHandshake) || conn != nil {
				t.Fatalf("%s: Accept = %v, want %v", tc.name, err, link.ErrHandshake)
			}
			if _, written := m.totals(); written != 0 {
				t.Fatalf("%s: the responder wrote %d bytes", tc.name, written)
			}
			_ = a.Close()
			_ = b.Close()
		}
	})
}

func TestDialRefusesALinkKeyOfAnotherLength(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		_, pub := keyPair(t, p)
		for _, static := range [][]byte{{}, pub[:len(pub)-1], append(bytes.Clone(pub), 0)} {
			a, b := net.Pipe()
			m := &meter{Conn: a}
			conn, err := link.Dial(m, p, static)
			if !errors.Is(err, link.ErrHandshake) || conn != nil {
				t.Fatalf("link key of %d bytes: Dial = %v, want %v", len(static), err, link.ErrHandshake)
			}
			if _, written := m.totals(); written != 0 {
				t.Fatalf("link key of %d bytes: the initiator wrote %d bytes", len(static), written)
			}
			_ = a.Close()
			_ = b.Close()
		}
	})
}

// which agreements a hand-made responder puts into the frame keys
type keying int

const (
	keyedInFull keying = iota
	keyedByStaticOnly
	keyedByEphemeralOnly
)

// what a responder writes: its public key and frame 0 carrying the given cell.
// The transcript is assembled here byte by byte, a second record of the layout
// next to the one in link:
//
//	"jimichi/v1/<suite>/transcript/link" || 00 || u8(parts)
//	  || 0001 version || 0001 mode || u16be(len) initiator key
//	  || u16be(len) responder key [ || u16be(len) responder link key, mode 01 ]
func answerWith(t *testing.T, p jcrypto.CryptoProvider, conn net.Conn, staticPriv *secmem.Buffer, staticPub []byte, how keying, first *wire.Cell) {
	t.Helper()
	n, _ := link.InitiatorHandshakeSize(p)
	hello := make([]byte, n)
	if _, err := io.ReadFull(conn, hello); err != nil {
		t.Errorf("hello: %v", err)
		return
	}
	mode, peerEph := hello[0], hello[1:]
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Error(err)
		return
	}
	defer priv.Release()

	keys := [][]byte{peerEph, pub}
	if mode == 1 {
		keys = append(keys, staticPub)
	}
	transcript := []byte("jimichi/v1/" + p.Suite().String() + "/transcript/link")
	transcript = append(transcript, 0x00, byte(2+len(keys)))
	transcript = append(transcript, 0x00, 0x01, wire.Version)
	transcript = append(transcript, 0x00, 0x01, mode)
	for _, k := range keys {
		transcript = append(transcript, byte(len(k)>>8), byte(len(k)))
		transcript = append(transcript, k...)
	}
	parts := append([][]byte{{wire.Version}, {mode}}, keys...)
	if same, err := jcrypto.TranscriptBytes(p.Suite(), "link", parts...); err != nil || !bytes.Equal(same, transcript) {
		t.Errorf("the transcript written out by hand is not what crypto builds: %v\n%x\n%x", err, transcript, same)
		return
	}
	ctx, err := jcrypto.NewContext(p, "link", parts...)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(ctx.Sum(), p.Hash(transcript)) {
		t.Error("the context is not the hash of the transcript")
		return
	}

	ee, err := p.Agree(priv, peerEph, ctx)
	if err != nil {
		t.Error(err)
		return
	}
	defer ee.Release()
	secret := ee
	if mode == 1 {
		es, err := p.Agree(staticPriv, peerEph, ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer es.Release()
		switch how {
		case keyedInFull:
			if secret, err = p.MixKey(es, ee, ctx); err != nil {
				t.Error(err)
				return
			}
			defer secret.Release()
		case keyedByStaticOnly:
			secret = es
		}
	}
	key, err := p.DeriveKey(secret, "link/r2i", ctx, p.KeySize())
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
	eachMode(t, func(t *testing.T, p jcrypto.CryptoProvider, auth bool) {
		hello, _ := link.InitiatorHandshakeSize(p)
		frame, _ := link.FrameSize(p)
		priv, pub := keyPair(t, p)
		_, eph := keyPair(t, p)
		var static []byte
		if auth {
			static = pub
		}
		answer := func(how keying, first *wire.Cell) func(net.Conn) {
			return func(conn net.Conn) { answerWith(t, p, conn, priv, pub, how, first) }
		}

		type respond struct {
			name    string
			respond func(conn net.Conn)
			ok      bool
			timeout bool
		}
		cases := []respond{
			{"a padding cell under the right keys", answer(keyedInFull, wire.NewPadding()), true, false},
			{"a data cell under the right keys", answer(keyedInFull, sample(0)), false, false},
			{"a frame of noise", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(append(bytes.Clone(eph), bytes.Repeat([]byte{0xA5}, frame)...))
			}, false, false},
			{"the key and then silence", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(eph)
			}, false, true},
			{"the key and then a closed connection", func(conn net.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, hello))
				_, _ = conn.Write(eph)
				_ = conn.Close()
			}, false, false},
		}
		if auth {
			// the frame keys depend on both agreements
			cases = append(cases,
				respond{"keys from the static agreement alone", answer(keyedByStaticOnly, wire.NewPadding()), false, false},
				respond{"keys from the ephemeral agreement alone", answer(keyedByEphemeralOnly, wire.NewPadding()), false, false},
			)
		}
		for _, tc := range cases {
			a, b := net.Pipe()
			m := &meter{Conn: a}
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.respond(b)
			}()
			_ = a.SetDeadline(time.Now().Add(time.Second))
			client, err := link.Dial(m, p, static)
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
			<-done
		}
	})
}
