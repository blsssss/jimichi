package lab

import (
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
