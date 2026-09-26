package lab

import "testing"

// the overlap that motivated Derive: base+repeat+flow collides for repeat 0
// flow 1 and repeat 1 flow 0; derived seeds for 30 repeats of 10 flows in
// two streams must all differ
func TestDerivedSeedsDoNotCollide(t *testing.T) {
	seen := make(map[int64]string)
	for r := uint64(0); r < 30; r++ {
		run := Derive(1, r)
		for _, stream := range []uint64{streamPhases, streamGaps} {
			for f := uint64(0); f < 10; f++ {
				s := Derive(run, stream, f)
				if s < 0 {
					t.Fatalf("negative seed %d", s)
				}
				key := string(rune('a'+r)) + string(rune('a'+stream)) + string(rune('a'+f))
				if prev, dup := seen[s]; dup {
					t.Fatalf("seed %d repeats for %s and %s", s, prev, key)
				}
				seen[s] = key
			}
		}
	}
	if Derive(1, 0) != Derive(1, 0) {
		t.Fatal("Derive is not deterministic")
	}
}
