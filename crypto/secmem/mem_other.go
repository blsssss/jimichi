//go:build !linux

package secmem

import "errors"

// falls back to the Go heap and reports Locked() == false: usable for tests,
// never for a node that must guarantee keys stay in RAM
func alloc(size int) ([]byte, bool, error) {
	return make([]byte, size), false, nil
}

func free(mem []byte, _ bool) {
	zero(mem)
}

func HardenProcess() error {
	return errors.New("secmem: process hardening requires linux")
}

func MemlockBudget() (uint64, error) {
	return 0, errors.New("secmem: memlock budget requires linux")
}
