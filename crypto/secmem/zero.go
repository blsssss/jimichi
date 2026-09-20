package secmem

import "runtime"

// KeepAlive stops the compiler from dropping a clearing loop whose result is
// never read
func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

func Zero(b []byte) { zero(b) }
