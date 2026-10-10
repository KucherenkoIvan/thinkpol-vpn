package router

import (
	"fmt"
	"net/netip"
	"slices"
)

// Route sends the destinations in Prefix to Egress; a nil Egress blocks
// them.
type Route struct {
	Prefix netip.Prefix
	Egress *Egress
}

// Table is what the router classifies packets by. Within each list the
// longest matching prefix wins, so first-match rules must be compiled into
// disjoint prefixes before they get here.
type Table struct {
	// Overlay are the space's overlay networks (its IPv4 range and its ULA
	// /48). A destination inside one is classified by Peers alone.
	Overlay []netip.Prefix
	// Peers route overlay addresses, each peer's own, to the egress whose
	// WireGuard device has the peer.
	Peers []Route
	// Rules route every other destination (TP-015's rule table).
	Rules []Route
	// Local are the node's own overlay addresses: the only destinations
	// an egress writes to the TUN. Whatever a WireGuard device decrypts
	// for anything else is dropped, so a peer can't use the node as a
	// router into its other networks.
	Local []netip.Addr
}

// compiled is a Table ready for lookups.
type compiled struct {
	overlay, peers, rules lpm
	local                 map[netip.Addr]bool
}

func (r *Router) compile(t Table) (*compiled, error) {
	c := &compiled{local: make(map[netip.Addr]bool, len(t.Local))}
	for _, a := range t.Local {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
			return nil, fmt.Errorf("router: local address %s", a)
		}
		c.local[a] = true
	}
	for _, p := range t.Overlay {
		if err := c.overlay.add(p, nil); err != nil {
			return nil, fmt.Errorf("router: overlay network: %w", err)
		}
	}
	for _, list := range []struct {
		what   string
		routes []Route
		into   *lpm
	}{{"peer route", t.Peers, &c.peers}, {"rule", t.Rules, &c.rules}} {
		for _, rt := range list.routes {
			if rt.Egress != nil && rt.Egress.r != r {
				return nil, fmt.Errorf("router: %s %s: egress %q belongs to another router", list.what, rt.Prefix, rt.Egress.name)
			}
			if err := list.into.add(rt.Prefix, rt.Egress); err != nil {
				return nil, fmt.Errorf("router: %s: %w", list.what, err)
			}
		}
	}
	return c, nil
}

// classify returns the egress for a destination; ok is false when nothing
// routes it. A nil egress with ok blocks it.
func (c *compiled) classify(dst netip.Addr) (e *Egress, ok bool) {
	if _, inOverlay := c.overlay.lookup(dst); inOverlay {
		return c.peers.lookup(dst)
	}
	return c.rules.lookup(dst)
}

// lpm is a longest-prefix-match table: one map per prefix length in use,
// tried from the longest. That is at most 33 or 129 map lookups and usually
// a handful; a trie can replace it behind the same methods if rule tables
// with many lengths make it matter.
type lpm struct {
	v4, v6 lengths
}

type lengths struct {
	bits     []int // descending
	prefixes map[netip.Prefix]*Egress
}

func (l *lpm) add(p netip.Prefix, e *Egress) error {
	switch {
	case !p.IsValid():
		return fmt.Errorf("invalid prefix %s", p)
	case p.Addr().Zone() != "":
		return fmt.Errorf("prefix %s has a zone", p)
	case p.Addr().Is4In6():
		return fmt.Errorf("prefix %s: IPv4-mapped IPv6 never matches; use the IPv4 prefix", p)
	}
	p = p.Masked()
	f := &l.v6
	if p.Addr().Is4() {
		f = &l.v4
	}
	if f.prefixes == nil {
		f.prefixes = make(map[netip.Prefix]*Egress)
	}
	if _, dup := f.prefixes[p]; dup {
		return fmt.Errorf("prefix %s routed twice", p)
	}
	f.prefixes[p] = e
	if i, found := slices.BinarySearchFunc(f.bits, p.Bits(), func(a, b int) int { return b - a }); !found {
		f.bits = slices.Insert(f.bits, i, p.Bits())
	}
	return nil
}

func (l *lpm) lookup(a netip.Addr) (*Egress, bool) {
	f := &l.v6
	if a.Is4() {
		f = &l.v4
	}
	for _, bits := range f.bits {
		p, _ := a.Prefix(bits)
		if e, ok := f.prefixes[p]; ok {
			return e, true
		}
	}
	return nil, false
}
