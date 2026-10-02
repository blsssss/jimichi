package wire

import (
	"bytes"
	"encoding/binary"
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
