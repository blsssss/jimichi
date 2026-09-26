package secmem

import (
	"fmt"
	"strings"
	"sync"
)

// each measure can be switched off on its own, so an experiment can build a
// node without it and measure what it was worth
type Policy struct {
	// OffHeap maps each buffer on pages of its own, outside the Go heap
	OffHeap bool
	// Lock keeps those pages out of swap
	Lock bool
	// DontDump keeps them out of core dumps
	DontDump bool
	// Zero clears key material on release and the heap copies handed to NewFrom
	// and Zero
	Zero bool
}

var (
	Protected = Policy{OffHeap: true, Lock: true, DontDump: true, Zero: true}
	Baseline  = Policy{}
)

var (
	policyMu sync.RWMutex
	current  = Protected
)

// SetPolicy applies to buffers allocated after the call, so a process sets it
// once, before it creates any key
func SetPolicy(p Policy) error {
	if (p.Lock || p.DontDump) && !p.OffHeap {
		return fmt.Errorf("secmem: lock and dontdump work on pages of their own and need offheap")
	}
	policyMu.Lock()
	current = p
	policyMu.Unlock()
	return nil
}

func CurrentPolicy() Policy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return current
}

// ParsePolicy reads "all", "none" or a comma list of offheap, lock, dontdump
// and zero naming the measures that stay on
func ParsePolicy(s string) (Policy, error) {
	switch strings.TrimSpace(s) {
	case "all":
		return Protected, nil
	case "none":
		return Baseline, nil
	}
	var p Policy
	for _, f := range strings.Split(s, ",") {
		switch strings.TrimSpace(f) {
		case "offheap":
			p.OffHeap = true
		case "lock":
			p.Lock = true
		case "dontdump":
			p.DontDump = true
		case "zero":
			p.Zero = true
		default:
			return Policy{}, fmt.Errorf("secmem: unknown measure %q", f)
		}
	}
	if (p.Lock || p.DontDump) && !p.OffHeap {
		return Policy{}, fmt.Errorf("secmem: lock and dontdump need offheap")
	}
	return p, nil
}

func (p Policy) String() string {
	switch p {
	case Protected:
		return "all"
	case Baseline:
		return "none"
	}
	var on []string
	for _, m := range []struct {
		name string
		set  bool
	}{{"offheap", p.OffHeap}, {"lock", p.Lock}, {"dontdump", p.DontDump}, {"zero", p.Zero}} {
		if m.set {
			on = append(on, m.name)
		}
	}
	return strings.Join(on, ",")
}
