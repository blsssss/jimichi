package wire

import (
	"encoding/binary"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// a link carries at most this many cells each way, a quarter of the modulus
// its values wrap at: a Sequence, seeded wherever the first cell puts it, never
// comes round to a value it has carried, so Wrap never seals twice under one
// backward nonce, and the client and the exit never reuse a base counter
const cellLimit = uint64(1) << 60

// Offsets are one hop's counter offsets, indexed by Direction. Every hop adds
// its own to each cell it passes on, so no two links of a circuit carry the
// same counter value
type Offsets [2]uint64

func deriveOffsets(p jcrypto.CryptoProvider, secret *secmem.Buffer, ctx jcrypto.Context) (Offsets, error) {
	var out Offsets
	for dir, purpose := range [...]string{Forward: purposeCounterForward, Backward: purposeCounterBackward} {
		b, err := p.DeriveKey(secret, purpose, ctx, 8)
		if err != nil {
			return Offsets{}, err
		}
		out[dir] = binary.BigEndian.Uint64(b.Bytes()) & (counterLimit - 1)
		b.Release()
	}
	return out, nil
}

// link values wrap at the nonce limit: the offset stays uniform over the whole
// range, so the value on one link says nothing about the value on another
func shift(value, offset uint64) uint64 { return (value + offset) & (counterLimit - 1) }

func unshift(value, offset uint64) uint64 { return (value - offset) & (counterLimit - 1) }
