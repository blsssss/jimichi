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

// leaves the top bit of the counter free for the direction in the 16-byte case
const counterLimit = uint64(1) << 63

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
		// no room for a direction byte, so it rides in the top bit of the counter
		n := make([]byte, 16)
		binary.BigEndian.PutUint64(n[0:8], circuit)
		binary.BigEndian.PutUint64(n[8:16], counter|uint64(dir)<<63)
		return n, nil
	default:
		return nil, fmt.Errorf("wire: nonce size %d too small", size)
	}
}
