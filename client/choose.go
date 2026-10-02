package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrChoice = errors.New("client: no such choice of nodes")

// Choose draws the path of a circuit as indices into a list of n nodes: the
// entry first, then the other hops in order, no node twice. Every ordered path
// is equally likely when rnd is uniform
func Choose(n, hops int, rnd io.Reader) ([]int, error) {
	if hops < 1 || hops > n {
		return nil, fmt.Errorf("%w: %d hops among %d nodes", ErrChoice, hops, n)
	}
	entry, err := ChooseEntry(n, rnd)
	if err != nil {
		return nil, err
	}
	return ChooseRest(entry, n, hops, rnd)
}

func ChooseEntry(n int, rnd io.Reader) (int, error) {
	if n < 1 {
		return 0, fmt.Errorf("%w: %d nodes", ErrChoice, n)
	}
	return below(rnd, n)
}

// the path that starts at entry: the other hops are drawn among the n-1 other
// nodes without replacement, by the first steps of a Fisher-Yates shuffle
func ChooseRest(entry, n, hops int, rnd io.Reader) ([]int, error) {
	if hops < 1 || hops > n || entry < 0 || entry >= n {
		return nil, fmt.Errorf("%w: %d hops among %d nodes", ErrChoice, hops, n)
	}
	others := make([]int, 0, n-1)
	for i := 0; i < n; i++ {
		if i != entry {
			others = append(others, i)
		}
	}
	path := make([]int, 1, hops)
	path[0] = entry
	for i := 0; i < hops-1; i++ {
		j, err := below(rnd, len(others)-i)
		if err != nil {
			return nil, err
		}
		others[i], others[i+j] = others[i+j], others[i]
		path = append(path, others[i])
	}
	return path, nil
}

// how many of the n listed nodes the mirror of an entry may lack for a chain
// of hops nodes: at most missing, and never so many that fewer than hops stay
func MaxAbsent(n, hops, missing int) int {
	return min(missing, n-hops)
}

// a 64-bit value reduced modulo m favours the low remainders unless the first
// 2^64 mod m values are thrown away, which leaves a whole number of cycles
func below(rnd io.Reader, m int) (int, error) {
	bound := uint64(m)
	reject := -bound % bound
	var b [8]byte
	// a draw is rejected with probability below m/2^64, so a uniform source
	// never comes near this many; a stuck one must not hold the client forever
	for range maxDraws {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return 0, fmt.Errorf("client: random choice: %w", err)
		}
		if v := binary.BigEndian.Uint64(b[:]); v >= reject {
			return int(v % bound), nil
		}
	}
	return 0, fmt.Errorf("%w: the random source gave no usable value in %d draws", ErrChoice, maxDraws)
}

const maxDraws = 128
