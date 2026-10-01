package pki

import (
	"bytes"
	"encoding/json"
	"sort"
)

type RosterNode struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// the nodes of one enrollment and the anchor that certifies them, as every
// node of that enrollment receives it
type Roster struct {
	Anchor Anchor
	Nodes  []RosterNode
}

type rosterEnvelope struct {
	Anchor string       `json:"anchor"`
	Nodes  []RosterNode `json:"nodes"`
}

func (r Roster) Marshal() []byte {
	nodes := r.Nodes
	if nodes == nil {
		nodes = []RosterNode{}
	}
	out, err := json.Marshal(rosterEnvelope{Anchor: r.Anchor.String(), Nodes: nodes})
	if err != nil {
		panic("pki: encoding strings cannot fail")
	}
	return out
}

// accepts only the spelling Marshal writes, so equal rosters are equal bytes
func ParseRoster(raw []byte) (*Roster, error) {
	var e rosterEnvelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, ErrFormat
	}
	anchor, err := ParseAnchor(e.Anchor)
	if err != nil {
		return nil, err
	}
	if len(e.Nodes) == 0 {
		return nil, ErrFormat
	}
	seen := make(map[string]bool, 2*len(e.Nodes))
	for _, n := range e.Nodes {
		if !ValidName(n.Name) || !ValidAddr(n.Addr) {
			return nil, ErrFormat
		}
		// a name has no colon and an address always has one
		if seen[n.Name] || seen[n.Addr] {
			return nil, ErrDuplicate
		}
		seen[n.Name], seen[n.Addr] = true, true
	}
	r := &Roster{Anchor: anchor, Nodes: e.Nodes}
	if !bytes.Equal(r.Marshal(), raw) {
		return nil, ErrFormat
	}
	return r, nil
}

func (r *Roster) Has(name, addr string) bool {
	for _, n := range r.Nodes {
		if n.Name == name && n.Addr == addr {
			return true
		}
	}
	return false
}

// one node of a descriptor mirror: the address its certificate carries and the
// bundle it serves
type MirrorEntry struct {
	Addr   string
	Bundle []byte
}

type mirrorItem struct {
	Addr   string          `json:"addr"`
	Bundle json.RawMessage `json:"bundle"`
}

// sorted by address, so one set of bundles has one encoding
func MarshalMirror(entries []MirrorEntry) ([]byte, error) {
	items := make([]mirrorItem, len(entries))
	for i, e := range entries {
		items[i] = mirrorItem{Addr: e.Addr, Bundle: e.Bundle}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Addr < items[j].Addr })
	if err := checkMirror(items); err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

// a mirror only carries bundles: every one of them still has to pass Verify
// under the reader's own anchor
func ParseMirror(raw []byte) ([]MirrorEntry, error) {
	var items []mirrorItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, ErrFormat
	}
	if err := checkMirror(items); err != nil {
		return nil, err
	}
	if again, err := json.Marshal(items); err != nil || !bytes.Equal(again, raw) {
		return nil, ErrFormat
	}
	entries := make([]MirrorEntry, len(items))
	for i, it := range items {
		entries[i] = MirrorEntry{Addr: it.Addr, Bundle: it.Bundle}
	}
	return entries, nil
}

func checkMirror(items []mirrorItem) error {
	if len(items) == 0 {
		return ErrFormat
	}
	for i, it := range items {
		if !ValidAddr(it.Addr) {
			return ErrFormat
		}
		if i > 0 && items[i-1].Addr == it.Addr {
			return ErrDuplicate
		}
		if i > 0 && items[i-1].Addr > it.Addr {
			return ErrFormat
		}
		if _, err := ParseBundle(it.Bundle); err != nil {
			return err
		}
	}
	return nil
}
