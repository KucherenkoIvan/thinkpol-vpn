package router

import (
	"fmt"
	"net/netip"
	"slices"
)

// Route sends the destinations in Prefix to Egress; a nil Egress blocks
// them, unless the route is Direct.
type Route struct {
	Prefix netip.Prefix
	Egress *Egress
	// Direct marks destinations the rules send around the tunnel: route
	// tables keep them out of the TUN, so one that enters it anyway is
	// dropped and counted (Counters.Direct), never sent through an exit.
	// A Direct route has no Egress.
	Direct bool
}

// direct is what a Direct route resolves to.
var direct = &Egress{name: "(direct)"}

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
	// Forward are the egresses that also write packets for destinations
	// outside the overlay networks to the TUN, for the node to forward to
	// the internet: the node is its space's exit (TP-014). Overlay
	// destinations other than Local are dropped all the same.
	Forward []*Egress
	// ReflectLocal writes packets read from the TUN for a Local address
	// back into the TUN (Counters.Reflected), for the OS to deliver to
	// itself. macOS routes its own address on a point-to-point utun
	// into the utun instead of delivering it locally, so without this
	// the node's processes never reach a service on its overlay address
	// (its resolver). Elsewhere the OS never hands the TUN such packets.
	ReflectLocal bool
}

// compiled is a Table ready for lookups.
type compiled struct {
	overlay, peers, rules lpm
	local                 map[netip.Addr]bool
	forward               map[*Egress]bool
	reflect               bool
}

// delivers reports whether egress e writes a packet for dst to the TUN:
// the node's own address, or, for a forwarding egress, an address outside
// the overlay (never an IPv4-mapped one, which no network routes).
func (c *compiled) delivers(e *Egress, dst netip.Addr) bool {
	if c.local[dst] {
		return true
	}
	if !c.forward[e] || dst.Is4In6() {
		return false
	}
	_, inOverlay := c.overlay.lookup(dst)
	return !inOverlay
}

func (r *Router) compile(t Table) (*compiled, error) {
	c := &compiled{local: make(map[netip.Addr]bool, len(t.Local)), forward: make(map[*Egress]bool, len(t.Forward)), reflect: t.ReflectLocal}
	for _, e := range t.Forward {
		if e == nil || e.r != r {
			return nil, fmt.Errorf("router: forwarding egress of another router")
		}
		c.forward[e] = true
	}
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
			e := rt.Egress
			switch {
			case rt.Direct && e != nil:
				return nil, fmt.Errorf("router: %s %s: direct, with egress %q", list.what, rt.Prefix, e.name)
			case rt.Direct:
				e = direct
			case e != nil && e.r != r:
				return nil, fmt.Errorf("router: %s %s: egress %q belongs to another router", list.what, rt.Prefix, e.name)
			}
			if err := list.into.add(rt.Prefix, e); err != nil {
				return nil, fmt.Errorf("router: %s: %w", list.what, err)
			}
		}
	}
	return c, nil
}

// classify returns the egress for a destination; ok is false when nothing
// routes it. A nil egress with ok blocks it; direct is a Direct route's.
func (c *compiled) classify(dst netip.Addr) (e *Egress, ok bool) {
	// An IPv4-mapped destination goes by its IPv4 address: tables hold
	// IPv4 only as IPv4, so ::/0 never swallows it.
	dst = dst.Unmap()
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
