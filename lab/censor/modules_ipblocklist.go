package censor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
)

func init() {
	RegisterPassive("ip-blocklist", newIPBlocklist)
}

// ipBlocklist is a censor's address blocklist: every packet to or from a
// listed address or network is blocked, both directions of a connection
// and either end of it, so a listed server's replies and its own
// connections out are blocked too. A flow is judged on its first packet,
// its addresses being all the module reads, and pinned either way.
type ipBlocklist struct {
	set   prefixSet
	block blocking
}

// newIPBlocklist builds the module from its settings:
//
//	{"addresses": ["203.0.113.9", "2001:db8::/32"], "verdict": "drop"}
//
// with blockSettings' verdict (drop by default), rate and burst.
func newIPBlocklist(settings json.RawMessage) (Passive, error) {
	var s struct {
		Addresses []string `json:"addresses"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	prefixes, err := parseDestinations(s.Addresses)
	if err != nil {
		return nil, err
	}
	b, err := s.blockSettings.parse(Drop)
	if err != nil {
		return nil, err
	}
	return &ipBlocklist{set: newPrefixSet(prefixes), block: b}, nil
}

func (m *ipBlocklist) Name() string { return "ip-blocklist" }

func (m *ipBlocklist) Inspect(p *Packet, _ *Flow) Decision {
	for _, a := range []netip.Addr{p.Dst, p.Src} {
		if listed, ok := m.set.lookup(a); ok {
			return m.block.decide(fmt.Sprintf("address %s listed as %s", a, listed))
		}
	}
	return retire
}

// prefixSet finds the listed network an address is in with one map lookup
// per prefix length the list uses, however long the list: a country's
// worth of networks costs what a handful does.
type prefixSet struct {
	listed map[netip.Prefix]bool
	// lens are the prefix lengths listed, longest first, by family.
	lens4, lens6 []int
}

func newPrefixSet(prefixes []netip.Prefix) prefixSet {
	s := prefixSet{listed: map[netip.Prefix]bool{}}
	for _, p := range prefixes {
		p = p.Masked()
		s.listed[p] = true
		lens := &s.lens6
		if p.Addr().Is4() {
			lens = &s.lens4
		}
		if !slices.Contains(*lens, p.Bits()) {
			*lens = append(*lens, p.Bits())
		}
	}
	slices.SortFunc(s.lens4, func(a, b int) int { return b - a })
	slices.SortFunc(s.lens6, func(a, b int) int { return b - a })
	return s
}

// lookup returns the longest listed network holding a. An IPv4-mapped
// IPv6 address is not an IPv4 one: on the wire it is an IPv6 packet.
func (s prefixSet) lookup(a netip.Addr) (netip.Prefix, bool) {
	lens := s.lens6
	if a.Is4() {
		lens = s.lens4
	}
	for _, bits := range lens {
		p, err := a.Prefix(bits)
		if err == nil && s.listed[p] {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
