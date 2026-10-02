package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/c25519"
	"github.com/jimichi-org/jimichi/crypto/gost"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func derived(t *testing.T, p jcrypto.CryptoProvider, secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) []byte {
	t.Helper()
	b, err := p.DeriveKey(secret, purpose, ctx, size)
	if err != nil {
		t.Fatalf("DeriveKey(%s): %v", purpose, err)
	}
	defer b.Release()
	return bytes.Clone(b.Bytes())
}

// the key schedule of a hop, redone here from the bytes on the wire with the
// transcript and the purposes written out, a second record of what BuildSetup
// and OpenSetup pass to the provider:
//
//	T = "jimichi/v1/<suite>/transcript/setup" || 00 || 05
//	    || 0001 version || 0001 hop index || 0008 link id
//	    || u16be(len) onion key || u16be(len) ephemeral key
//	secret = Agree(onion private key, ephemeral key, Hash(T))
//	layer key "setup", hop key "cell", replay tag "setup/replay" (16 bytes),
//	offsets "counter/fwd" and "counter/bwd" (8 bytes, top two bits cleared)
//
// the link ids use all eight bytes and the chain has hops past index 0
func TestSetupKeyScheduleByHand(t *testing.T) {
	for _, p := range []jcrypto.CryptoProvider{c25519.New(), gost.New()} {
		t.Run(p.Suite().String(), func(t *testing.T) {
			const n = 3
			links := [n]uint64{0x0102030405060708, 0xf1e2d3c4b5a69788, 0x8000000000000001}
			privs := make([]*secmem.Buffer, n)
			chain := make([]SetupHop, n)
			for i := range chain {
				priv, pub, err := p.GenerateEphemeral()
				if err != nil {
					t.Fatal(err)
				}
				defer priv.Release()
				privs[i] = priv
				chain[i] = SetupHop{StaticPub: pub, Link: links[i]}
				if i < n-1 {
					chain[i].NextAddr, chain[i].NextCircuit = "relay-next:9000", links[i+1]
				}
			}
			setup, err := BuildSetup(p, chain)
			if err != nil {
				t.Fatalf("BuildSetup: %v", err)
			}
			for _, k := range setup.CellKeys {
				defer k.Release()
			}

			cell := setup.Cell
			for i := 0; i < n; i++ {
				pub := chain[i].StaticPub
				eph := bytes.Clone(cell.Body()[:len(pub)])

				transcript := []byte("jimichi/v1/" + p.Suite().String() + "/transcript/setup")
				transcript = append(transcript, 0x00, 0x05)
				transcript = append(transcript, 0x00, 0x01, 0x02)
				transcript = append(transcript, 0x00, 0x01, byte(i))
				transcript = append(transcript, 0x00, 0x08)
				transcript = binary.BigEndian.AppendUint64(transcript, links[i])
				for _, k := range [][]byte{pub, eph} {
					transcript = append(transcript, byte(len(k)>>8), byte(len(k)))
					transcript = append(transcript, k...)
				}
				id := binary.BigEndian.AppendUint64(nil, links[i])
				ctx, err := jcrypto.NewContext(p, "setup", []byte{0x02}, []byte{byte(i)}, id, pub, eph)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ctx.Sum(), p.Hash(transcript)) {
					t.Fatalf("hop %d: the context is not the hash of the transcript written out by hand", i)
				}

				secret, err := p.Agree(privs[i], eph, ctx)
				if err != nil {
					t.Fatalf("hop %d: Agree: %v", i, err)
				}
				setupKey, err := p.DeriveKey(secret, "setup", ctx, p.KeySize())
				if err != nil {
					t.Fatal(err)
				}
				cellKey := derived(t, p, secret, "cell", ctx, p.KeySize())
				tag := derived(t, p, secret, "setup/replay", ctx, 16)
				var offsets Offsets
				for dir, purpose := range [...]string{Forward: "counter/fwd", Backward: "counter/bwd"} {
					offsets[dir] = binary.BigEndian.Uint64(derived(t, p, secret, purpose, ctx, 8)) &^ (3 << 62)
				}
				secret.Release()

				sz, err := sizesOf(p)
				if err != nil {
					t.Fatal(err)
				}
				aead, err := p.NewAEAD(setupKey)
				if err != nil {
					t.Fatal(err)
				}
				nonce, err := nonceFor(aead.NonceSize(), Forward, links[i], 0)
				if err != nil {
					t.Fatal(err)
				}
				sealed := cell.Body()[len(pub):setupLayerLen(i, perHopCost(sz.pub, sz.overhead))]
				_, err = aead.Open(nil, nonce, sealed, []byte{0x02, byte(KindControl), byte(i)})
				aead.Destroy()
				if err != nil {
					t.Fatalf("hop %d: the layer does not open under the key derived by hand for the purpose setup: %v", i, err)
				}
				if bytes.HasPrefix(setupKey.Bytes(), tag) || bytes.HasPrefix(cellKey, tag) {
					t.Fatalf("hop %d: the replay tag is the head of a key", i)
				}
				if bytes.Equal(setupKey.Bytes(), cellKey) {
					t.Fatalf("hop %d: the layer key and the hop key are one key", i)
				}
				setupKey.Release()

				if !bytes.Equal(setup.CellKeys[i].Bytes(), cellKey) {
					t.Fatalf("hop %d: the client's hop key is not the one derived for the purpose cell", i)
				}
				if setup.Offsets[i] != offsets {
					t.Fatalf("hop %d: the client's offsets %x, by hand %x", i, setup.Offsets[i], offsets)
				}

				layer, err := OpenSetup(p, privs[i], pub, cell)
				if err != nil {
					t.Fatalf("hop %d: OpenSetup: %v", i, err)
				}
				same := bytes.Equal(layer.CellKey.Bytes(), cellKey)
				layer.CellKey.Release()
				if !same {
					t.Fatalf("hop %d: the node's hop key is not the one derived for the purpose cell", i)
				}
				if !bytes.Equal(layer.Tag[:], tag) {
					t.Fatalf("hop %d: replay tag %x, by hand %x", i, layer.Tag, tag)
				}
				if layer.Offsets != offsets {
					t.Fatalf("hop %d: the node's offsets %x, by hand %x", i, layer.Offsets, offsets)
				}
				if i == n-1 {
					break
				}
				if cell, err = ForwardSetup(layer, i); err != nil {
					t.Fatalf("hop %d: ForwardSetup: %v", i, err)
				}
			}
		})
	}
}

// the purposes of a hop pinned to fixed numbers. The layer is the one of the
// golden agreement in crypto/providertest: hop 0 on link 200, the node holds b
// and publishes B, the client's ephemeral key is A (c25519: the keys of
// RFC 7748, 6.1; gost: a = 01..20, b = 11..30), which gives the transcript
// hash th, the secret and the setup key written there. The test seals an exit
// layer under that setup key; OpenSetup has to open it and return the values
// below, computed outside this code from that secret and th, with Python hmac
// and hashlib on c25519 and a separate implementation of Streebog on gost:
//
//	c25519: HMAC-SHA256(secret, "jimichi/v1/c25519/<purpose>" || 00 || th || 01)
//	  cell          5b74dea6..5dc36ecf
//	  setup/replay  1d44db7866a94b97d711fbc7d964b112 (first 16 bytes)
//	  counter/fwd   b182857f2e9b88d9 -> 3182857f2e9b88d9 (first 8, top two bits cleared)
//	  counter/bwd   c0216dc0b6202324 -> 00216dc0b6202324
//	gost: HMAC-Streebog256(secret, 01 || "jimichi/v1/gost/<purpose>" || 00 || th || 01 00)
//	  cell          713df95a..0ab48cc1
//	  setup/replay  8d4d03a604fbcc19b3e47f059ec7eb08
//	  counter/fwd   2770ef3738ed2014 -> 2770ef3738ed2014
//	  counter/bwd   95ea9932c2a27b6d -> 15ea9932c2a27b6d
func TestOpenSetupKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		p                      jcrypto.CryptoProvider
		pubA, privB, pubB      string
		setupKey, cellKey, tag string
		forward, backward      uint64
	}{
		{
			p:        c25519.New(),
			pubA:     "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
			privB:    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			pubB:     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			setupKey: "0a0d88469644b07cd9797e2eef6c2efcde74cc78964d74940ff7e77656772e02",
			cellKey:  "5b74dea6ccc307babb31e0dbe66a3d17d311ecacb47559144403d7c55dc36ecf",
			tag:      "1d44db7866a94b97d711fbc7d964b112",
			forward:  0x3182857f2e9b88d9,
			backward: 0x00216dc0b6202324,
		},
		{
			p: gost.New(),
			pubA: "000ad8811b8280e56a2c9b37b7170a3de04039df9151482097e3cc0669ecb7a0" +
				"623f29508cc68b124c3d15a4e2a26e3e71dc391fb2c62d558071878e6814f9a3",
			privB: "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
			pubB: "b6749ce1d202dd4550a1ad7a8797e16e47cfdb0a0b446465e447f56abb4dae1b" +
				"43cad001b96e51d4f10df16549327c9eea30e0a74adf0ce5a01c5934ec52edc6",
			setupKey: "7e9d78151bab2b2fd46d348e3a08aeba7a9aacfc406b301fb05b1220d833babb",
			cellKey:  "713df95a6ec1b768d182064b0d220c6267cdf282de5a5117530c60910ab48cc1",
			tag:      "8d4d03a604fbcc19b3e47f059ec7eb08",
			forward:  0x2770ef3738ed2014,
			backward: 0x15ea9932c2a27b6d,
		},
	} {
		t.Run(tc.p.Suite().String(), func(t *testing.T) {
			p := tc.p
			unhex := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			pubA, pubB := unhex(tc.pubA), unhex(tc.pubB)
			privB, err := secmem.NewFrom(unhex(tc.privB))
			if err != nil {
				t.Fatal(err)
			}
			defer privB.Release()
			setupKey, err := secmem.NewFrom(unhex(tc.setupKey))
			if err != nil {
				t.Fatal(err)
			}
			defer setupKey.Release()

			aead, err := p.NewAEAD(setupKey)
			if err != nil {
				t.Fatal(err)
			}
			defer aead.Destroy()
			nonce, err := nonceFor(aead.NonceSize(), Forward, 200, 0)
			if err != nil {
				t.Fatal(err)
			}
			// all zero: an exit layer whose first forward counter is 0
			plain := make([]byte, BodySize-len(pubA)-aead.Overhead())
			body := append(bytes.Clone(pubA), aead.Seal(nil, nonce, plain, []byte{0x02, byte(KindControl), 0x00})...)
			cell, err := NewCell(Header{Kind: KindControl, Circuit: 200, Counter: 0}, body)
			if err != nil {
				t.Fatal(err)
			}

			layer, err := OpenSetup(p, privB, pubB, cell)
			if err != nil {
				t.Fatalf("OpenSetup: %v", err)
			}
			defer layer.CellKey.Release()
			if got := hex.EncodeToString(layer.CellKey.Bytes()); got != tc.cellKey {
				t.Errorf("hop key %s, want %s", got, tc.cellKey)
			}
			if got := hex.EncodeToString(layer.Tag[:]); got != tc.tag {
				t.Errorf("replay tag %s, want %s", got, tc.tag)
			}
			if layer.Offsets[Forward] != tc.forward || layer.Offsets[Backward] != tc.backward {
				t.Errorf("offsets %#x %#x, want %#x %#x", layer.Offsets[Forward], layer.Offsets[Backward], tc.forward, tc.backward)
			}
			if layer.NextAddr != "" || layer.First != 0 {
				t.Errorf("exit layer: next %q, first counter %d", layer.NextAddr, layer.First)
			}
		})
	}
}
