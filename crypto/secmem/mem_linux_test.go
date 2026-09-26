//go:build linux

package secmem_test

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/blsssss/jimichi/crypto/secmem"
)

// what the kernel records for the mapping that holds a buffer: "lo" is locked,
// "dd" is excluded from core dumps
func vmFlags(t *testing.T, addr uintptr) string {
	t.Helper()
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		t.Skipf("no smaps: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inside := false
	for sc.Scan() {
		line := sc.Text()
		var lo, hi uintptr
		if n, _ := fmt.Sscanf(line, "%x-%x", &lo, &hi); n == 2 && strings.Contains(line, " ") && !strings.HasPrefix(line, "VmFlags") {
			inside = addr >= lo && addr < hi
			continue
		}
		if inside && strings.HasPrefix(line, "VmFlags:") {
			return line
		}
	}
	t.Fatalf("no mapping holds %#x", addr)
	return ""
}

func TestProtectedPagesAreLockedAndUndumpable(t *testing.T) {
	if err := secmem.SetPolicy(secmem.Protected); err != nil {
		t.Fatal(err)
	}
	b, err := secmem.New(32)
	if err != nil {
		t.Skipf("cannot lock memory here: %v", err)
	}
	defer b.Release()
	flags := vmFlags(t, uintptr(unsafe.Pointer(&b.Bytes()[0])))
	for _, want := range []string{" lo", " dd"} {
		if !strings.Contains(flags, want) {
			t.Fatalf("mapping flags %q lack%s", flags, want)
		}
	}
}

func TestOffHeapWithoutMeasuresIsPlainMapping(t *testing.T) {
	defer func() { _ = secmem.SetPolicy(secmem.Protected) }()
	if err := secmem.SetPolicy(secmem.Policy{OffHeap: true}); err != nil {
		t.Fatal(err)
	}
	b, err := secmem.New(32)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	flags := vmFlags(t, uintptr(unsafe.Pointer(&b.Bytes()[0])))
	if strings.Contains(flags, " lo") || strings.Contains(flags, " dd") {
		t.Fatalf("mapping flags %q show a measure that was switched off", flags)
	}
}
