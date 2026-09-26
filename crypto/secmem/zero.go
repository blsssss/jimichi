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

// clears a heap copy of key material unless the policy has zeroing off, which
// only a baseline run does
func Zero(b []byte) {
	if CurrentPolicy().Zero {
		zero(b)
	}
}
