package lab

// streams that must not share values, each derived from the run seed
const (
	streamPhases uint64 = iota + 1
	streamGaps
)

// Derive mixes the parts into the seed with splitmix64, so neighbouring seeds,
// repeats and flows give unrelated streams; seed+flow would hand repeat r+1
// the schedules of repeat r shifted by one flow
func Derive(seed int64, parts ...uint64) int64 {
	x := uint64(seed)
	for _, p := range parts {
		x = splitmix64(x ^ splitmix64(p))
	}
	return int64(splitmix64(x) >> 1)
}

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}
