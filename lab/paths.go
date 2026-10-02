package lab

import (
	"fmt"
	"math/rand"

	"github.com/jimichi-org/jimichi/client"
)

// SamplePaths draws paths the way a client draws its chain, with the client's
// own Choose, on a stream derived from the seed in place of the system
// generator: no traffic and no nodes, only the choice, so a sample of any size
// repeats exactly
func SamplePaths(nodes, hops, samples int, seed int64) ([][]int, error) {
	stream := rand.New(rand.NewSource(Derive(seed, streamPaths)))
	paths := make([][]int, samples)
	for i := range paths {
		path, err := client.Choose(nodes, hops, stream)
		if err != nil {
			return nil, err
		}
		paths[i] = path
	}
	return paths, nil
}

// SampleMirrorPaths draws paths the way a client does when the mirror of its
// entry need not hold every listed node; mirrors[e][i] says whether entry e
// serves node i. Each attempt draws the entry among all the nodes, is refused
// when the mirror lacks the entry itself or more nodes than the client allows
// for that -missing (client.MaxAbsent), and otherwise draws the other hops
// among the nodes the mirror holds. A refused attempt gives no path and is
// counted. With full mirrors the paths are those of SamplePaths for the same
// seed
func SampleMirrorPaths(mirrors [][]bool, hops, missing, samples int, seed int64) (paths [][]int, refused int, err error) {
	nodes := len(mirrors)
	if hops < 1 || hops > nodes {
		return nil, 0, fmt.Errorf("%w: %d hops among %d nodes", client.ErrChoice, hops, nodes)
	}
	if missing < 0 || samples < 0 {
		return nil, 0, fmt.Errorf("lab: missing %d, samples %d: must not be negative", missing, samples)
	}
	// the nodes each entry serves, in the listed order, and where the entry
	// stands among them, as the client numbers the bundles it verified
	held := make([][]int, nodes)
	place := make([]int, nodes)
	for entry, mirror := range mirrors {
		if len(mirror) != nodes {
			return nil, 0, fmt.Errorf("lab: the mirror of node %d covers %d nodes, want %d", entry, len(mirror), nodes)
		}
		place[entry] = -1
		for node, served := range mirror {
			if !served {
				continue
			}
			if node == entry {
				place[entry] = len(held[entry])
			}
			held[entry] = append(held[entry], node)
		}
	}
	allowed := client.MaxAbsent(nodes, hops, missing)
	stream := rand.New(rand.NewSource(Derive(seed, streamPaths)))
	paths = make([][]int, 0, samples)
	for range samples {
		entry, err := client.ChooseEntry(nodes, stream)
		if err != nil {
			return nil, 0, err
		}
		if place[entry] < 0 || nodes-len(held[entry]) > allowed {
			refused++
			continue
		}
		path, err := client.ChooseRest(place[entry], len(held[entry]), hops, stream)
		if err != nil {
			return nil, 0, err
		}
		for i, node := range path {
			path[i] = held[entry][node]
		}
		paths = append(paths, path)
	}
	return paths, refused, nil
}

// SurvivingPaths splits the paths a client chose into those the nodes set up
// and the number that fail on the way: extends[x][y] says whether node x
// extends a circuit to node y, which an honest node does only while it holds
// the verified descriptor of y. A path fails when any of its nodes does not
// extend to the next
func SurvivingPaths(paths [][]int, extends [][]bool) (up [][]int, failed int, err error) {
	for node, row := range extends {
		if len(row) != len(extends) {
			return nil, 0, fmt.Errorf("lab: node %d extends to one of %d nodes, want %d", node, len(row), len(extends))
		}
	}
	up = make([][]int, 0, len(paths))
	for _, path := range paths {
		extended := true
		for i, node := range path {
			if node < 0 || node >= len(extends) {
				return nil, 0, fmt.Errorf("lab: node %d on a path among %d nodes", node, len(extends))
			}
			if i > 0 && !extends[path[i-1]][node] {
				extended = false
			}
		}
		if !extended {
			failed++
			continue
		}
		up = append(up, path)
	}
	return up, failed, nil
}
