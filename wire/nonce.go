package wire

import (
	"encoding/binary"
	"fmt"
)

// a hop key serves both directions, so the direction enters the nonce
type Direction uint8

const (
	Forward  Direction = 0
	Backward Direction = 1
)

// two top bits of the counter word are taken: bit 62 carries the direction in
// the 16-byte case and bit 63 must stay zero there, as MGM (R 1323565.1.026)
// only accepts nonces below 2^127
const counterLimit = uint64(1) << 62

// derived from values both sides know, so no nonce travels on the wire; a key
// belongs to one hop of one circuit, so (direction, counter) never repeats
func nonceFor(size int, dir Direction, circuit, counter uint64) ([]byte, error) {
	if counter >= counterLimit {
		return nil, fmt.Errorf("wire: counter exhausted")
	}
	switch {
	case size >= 17:
		n := make([]byte, size)
		n[0] = byte(dir)
		binary.BigEndian.PutUint64(n[1:9], circuit)
		binary.BigEndian.PutUint64(n[9:17], counter)
		return n, nil
	case size == 16:
		// the random circuit id goes last: first it would set the top bit of the
		// nonce for half of all circuits
		n := make([]byte, 16)
		binary.BigEndian.PutUint64(n[0:8], counter|uint64(dir)<<62)
		binary.BigEndian.PutUint64(n[8:16], circuit)
		return n, nil
	default:
		return nil, fmt.Errorf("wire: nonce size %d too small", size)
	}
}
