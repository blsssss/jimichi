// Package secmem holds key material outside the Go heap: mlocked, excluded from
// core dumps, zeroed on release. Locking is linux-only; other platforms report
// the buffer as unlocked so callers can refuse to run instead of silently
// degrading.
package secmem
