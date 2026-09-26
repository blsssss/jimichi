//go:build linux

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func alloc(size int, p Policy) ([]byte, bool, error) {
	if !p.OffHeap {
		return make([]byte, size), false, nil
	}
	mem, err := unix.Mmap(-1, 0, size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, false, fmt.Errorf("secmem: mmap %d bytes: %w", size, err)
	}

	// keeps the pages out of core dumps even when dumping is on for the process
	if p.DontDump {
		if err := unix.Madvise(mem, unix.MADV_DONTDUMP); err != nil {
			_ = unix.Munmap(mem)
			return nil, false, fmt.Errorf("secmem: madvise: %w", err)
		}
	}

	if !p.Lock {
		return mem, false, nil
	}
	if err := unix.Mlock(mem); err != nil {
		_ = unix.Munmap(mem)
		return nil, false, fmt.Errorf("secmem: mlock %d bytes (check RLIMIT_MEMLOCK): %w", size, err)
	}
	return mem, true, nil
}

func free(mem []byte, locked bool, p Policy) {
	if mem == nil {
		return
	}
	if p.Zero {
		zero(mem)
	}
	if !p.OffHeap {
		return
	}
	if locked {
		_ = unix.Munlock(mem)
	}
	_ = unix.Munmap(mem)
}

// PR_SET_DUMPABLE=0 also blocks ptrace and /proc/pid/mem for the same uid; it is
// a switch so a baseline run can measure what the measure is worth
func HardenProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("secmem: prctl(PR_SET_DUMPABLE): %w", err)
	}
	lim := unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("secmem: setrlimit(RLIMIT_CORE): %w", err)
	}
	return nil
}

func MemlockBudget() (uint64, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return 0, fmt.Errorf("secmem: getrlimit(RLIMIT_MEMLOCK): %w", err)
	}
	return lim.Cur, nil
}
