package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Options are what Compile resolves rules against.
type Options struct {
	// Overlay are the space's overlay networks. They are decided before any
	// rule (by the overlay's peers), so no route covers them.
	Overlay []netip.Prefix
	// GeoIP returns the GeoIP list a geoip matcher names; false while the
	// node doesn't have it. Nil: no lists.
	GeoIP func(name string) (*lists.Set, bool)
	// Chain reports whether a chain can carry traffic; rules sending
	// traffic to one that can't block it instead. Nil: every chain can.
	Chain func(name string) bool
}

// Reason is why a rule isn't enforced as written, from a fixed vocabulary
// that quotes nothing from the rule.
type Reason uint8

const (
	ReasonByName         Reason = iota + 1 // a domain or geosite matcher: not enforced in route-table mode
	ReasonNoList                           // a GeoIP list the node doesn't have (yet): matches nothing
	ReasonUnknownMatch                     // a matcher the node doesn't know or can't read: matches nothing
	ReasonUnknownAction                    // an action the node doesn't know: blocks
	ReasonNoChain                          // a chain that can't carry traffic: blocks
	ReasonAfterUnknown                     // a direct rule after one whose addresses aren't known: off
	ReasonByNameUndercut                   // as ReasonByName, and a later direct rule may send its names' addresses around the tunnel
)

func (r Reason) String() string {
	switch r {
	case ReasonByName:
		return "not enforced in route-table mode"
	case ReasonNoList:
		return "list not available"
	case ReasonUnknownMatch:
		return "unknown matcher"
	case ReasonUnknownAction:
		return "unknown action, blocked"
	case ReasonNoChain:
		return "chain unavailable, blocked"
	case ReasonAfterUnknown:
		return "direct after a rule with unknown addresses, off"
	case ReasonByNameUndercut:
		return "not enforced in route-table mode, and a later direct rule may route its names around the tunnel"
	}
	return fmt.Sprintf("Reason(%d)", uint8(r))
}

// Skip is a rule not enforced as written.
type Skip struct {
	Origin Origin
	Index  int
	Reason Reason
}

// Route sends the destinations in Prefix by Action.
type Route struct {
	Prefix netip.Prefix
	Action netmap.Action
}

// Table is a compiled rule list.
type Table struct {
	routes  []Route // the /0 routes (nzero of them), then the others in address order
	nzero   int
	chains  []string
	overlay *lists.Set
	direct  *lists.Set
	skipped []Skip
}

// Compile resolves an effective rule list (see the package doc for what
// route-table mode can't enforce and what it does instead).
func Compile(entries []Entry, o Options) *Table {
	t := &Table{overlay: setOf(o.Overlay)}
	p := newPartition(t.overlay)
	t.claimRules(entries, o, p)
	rest := netmap.Block
	if len(entries) == 0 {
		rest = netmap.Direct
	}
	p.claim(rest, lists.All())

	// Per family, the action with the most prefixes becomes a /0 route,
	// and the other actions' prefixes, disjoint, override it. A
	// longest-prefix match still finds every address's action, from far
	// fewer routes than the partition itself: the rest of the world around
	// a country's list fragments into many times its prefixes.
	for _, a := range p.actions {
		if a.Kind == netmap.ActionChain {
			t.chains = append(t.chains, a.Chain)
		}
	}
	sets, counts := p.build()
	t.direct = sets[netmap.Direct]
	zero, background := backgroundRoutes(p.actions, counts)
	t.routes = zero
	specific := specificRoutes(p.actions, sets, background)
	t.nzero = len(t.routes)
	slices.SortFunc(specific, func(a, b Route) int { return a.Prefix.Addr().Compare(b.Prefix.Addr()) })
	t.routes = append(t.routes, specific...)
	if t.direct == nil {
		t.direct = &lists.Set{}
	}
	return t
}

// partition gives each address the action of the first claim on it.
type partition struct {
	claimed   *lists.Set
	actions   []netmap.Action // in order of first use, so the result is deterministic
	effective map[netmap.Action]*lists.Builder
}

// newPartition is a partition with claimed (the overlay) already taken.
func newPartition(claimed *lists.Set) *partition {
	return &partition{claimed: claimed, effective: make(map[netmap.Action]*lists.Builder)}
}

// claim gives a the addresses of s no earlier claim took; false when
// there were none.
func (p *partition) claim(a netmap.Action, s *lists.Set) bool {
	eff := s.Minus(p.claimed)
	if eff.IsEmpty() {
		return false
	}
	if p.effective[a] == nil {
		p.actions = append(p.actions, a)
		p.effective[a] = &lists.Builder{}
	}
	p.effective[a].AddSet(eff)
	p.claimed = union(p.claimed, eff)
	return true
}

// build is each action's addresses, and how many prefixes they take per
// family (IPv4, IPv6).
func (p *partition) build() (map[netmap.Action]*lists.Set, [2]map[netmap.Action]int) {
	sets := make(map[netmap.Action]*lists.Set, len(p.actions))
	var counts [2]map[netmap.Action]int
	counts[0], counts[1] = make(map[netmap.Action]int), make(map[netmap.Action]int)
	for _, a := range p.actions {
		s, st := p.effective[a].Build()
		sets[a] = s
		counts[0][a], counts[1][a] = st.Prefixes4, st.Prefixes6
	}
	return sets, counts
}

// claimRules claims each rule's addresses for its action, in rule order,
// and records the rules not enforced as written in t.skipped.
func (t *Table) claimRules(entries []Entry, o Options, p *partition) {
	unknown := false // a rule whose addresses aren't known came first
	var byName []int // skips of name rules that don't go direct, not yet followed by a direct rule
	for _, e := range entries {
		r := e.Rule
		skip := func(reason Reason) {
			t.skipped = append(t.skipped, Skip{Origin: e.Origin, Index: e.Index, Reason: reason})
		}
		if r.Match.Kind.ByName() {
			if r.Action.Kind != netmap.ActionDirect {
				byName = append(byName, len(t.skipped))
			}
			skip(ReasonByName)
			continue
		}
		set, reason := o.resolve(r.Match)
		if reason != 0 {
			skip(reason)
			unknown = unknown || r.Action.Kind != netmap.ActionDirect
			continue
		}
		action := r.Action
		switch {
		case action != netmap.Direct && action != netmap.Block && (action.Kind != netmap.ActionChain || action.Chain == ""):
			skip(ReasonUnknownAction)
			action = netmap.Block
		case action.Kind == netmap.ActionChain && o.Chain != nil && !o.Chain(action.Chain):
			skip(ReasonNoChain)
			action = netmap.Block
		case action == netmap.Direct && unknown:
			skip(ReasonAfterUnknown)
			continue
		}
		if p.claim(action, set) && action == netmap.Direct {
			for _, i := range byName {
				t.skipped[i].Reason = ReasonByNameUndercut
			}
			byName = nil
		}
	}
}

// backgroundRoutes are the /0 routes: per family (IPv4, IPv6), the
// action with the most prefixes there, the first one on a tie; none for
// a family no action has prefixes in. background is that action per
// family, nil for none.
func backgroundRoutes(actions []netmap.Action, counts [2]map[netmap.Action]int) (routes []Route, background [2]*netmap.Action) {
	for f, zero := range []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)} {
		most := 0
		for _, a := range actions {
			if n := counts[f][a]; n > most {
				background[f], most = &a, n
			}
		}
		if background[f] != nil {
			routes = append(routes, Route{Prefix: zero, Action: *background[f]})
		}
	}
	return routes, background
}

// specificRoutes are the prefixes of every action but its family's
// background, in action order.
func specificRoutes(actions []netmap.Action, sets map[netmap.Action]*lists.Set, background [2]*netmap.Action) []Route {
	var specific []Route
	for _, a := range actions {
		// The background's own prefixes are never listed, nor made.
		if background[0] != nil && *background[0] == a && background[1] != nil && *background[1] == a {
			continue
		}
		for _, p := range sets[a].Prefixes() {
			f := 1
			if p.Addr().Is4() {
				f = 0
			}
			if background[f] == nil || *background[f] != a {
				specific = append(specific, Route{Prefix: p, Action: a})
			}
		}
	}
	return specific
}

func (o Options) resolve(m netmap.Match) (*lists.Set, Reason) {
	switch m.Kind {
	case netmap.MatchDefault:
		return lists.All(), 0
	case netmap.MatchLocal:
		return lists.Local(), 0
	case netmap.MatchCIDR:
		s, ok := cidrSet(m.Prefix)
		if !ok {
			return nil, ReasonUnknownMatch
		}
		return s, 0
	case netmap.MatchGeoIP:
		if o.GeoIP != nil {
			if s, ok := o.GeoIP(m.Value); ok {
				return s, 0
			}
		}
		return nil, ReasonNoList
	}
	return nil, ReasonUnknownMatch
}

var mapped = netip.MustParsePrefix("::ffff:0:0/96")

// cidrSet is a cidr matcher's addresses. IPv4 is matched only as IPv4, so
// an IPv6 prefix around ::ffff:0:0/96 (::/0, ::/80) leaves that range out,
// and one inside it matches nothing a list can hold: false.
func cidrSet(p netip.Prefix) (*lists.Set, bool) {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return nil, false
	}
	p = p.Masked()
	var b lists.Builder
	if p.Addr().Is6() && p.Overlaps(mapped) {
		if p.Bits() >= mapped.Bits() {
			return nil, false
		}
		first, last := p.Addr(), lastAddr(p)
		if first.Less(mapped.Addr()) {
			_ = b.AddRange(first, mapped.Addr().Prev())
		}
		if mappedLast := lastAddr(mapped); mappedLast.Less(last) {
			_ = b.AddRange(mappedLast.Next(), last)
		}
	} else if b.AddPrefix(p) != nil {
		return nil, false
	}
	s, _ := b.Build()
	return s, true
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func setOf(prefixes []netip.Prefix) *lists.Set {
	var b lists.Builder
	for _, p := range prefixes {
		_ = b.AddPrefix(p) // an overlay network a list can't hold isn't one
	}
	s, _ := b.Build()
	return s
}

func union(a, b *lists.Set) *lists.Set {
	var u lists.Builder
	u.AddSet(a)
	u.AddSet(b)
	s, _ := u.Build()
	return s
}

// Routes are the table for a longest-prefix match, which gives every
// address outside the overlay networks the action of the first rule that
// matches it: per family a /0 route (the action with the most prefixes),
// and the other actions' prefixes, which never overlap one another or the
// overlay. The /0 routes come first, then the rest in address order. The
// slice is shared: don't modify it.
func (t *Table) Routes() []Route { return t.routes }

// Lookup returns the action for a destination; false for one inside the
// overlay networks. An IPv4-mapped address is looked up as IPv4.
func (t *Table) Lookup(a netip.Addr) (netmap.Action, bool) {
	a = a.WithZone("").Unmap()
	if t.overlay.Contains(a) {
		return netmap.Action{}, false
	}
	specific := t.routes[t.nzero:]
	i := sort.Search(len(specific), func(i int) bool { return a.Less(specific[i].Prefix.Addr()) }) - 1
	if i >= 0 && specific[i].Prefix.Contains(a) {
		return specific[i].Action, true
	}
	for _, r := range t.routes[:t.nzero] {
		if r.Prefix.Contains(a) {
			return r.Action, true
		}
	}
	return netmap.Action{}, false
}

// Direct is every address that goes around the tunnel: what route-table
// mode installs as routes through the physical gateway.
func (t *Table) Direct() *lists.Set { return t.direct }

// Chains are the chains some destination goes through, in rule order.
func (t *Table) Chains() []string { return t.chains }

// Skipped are the rules not enforced as written, in rule order.
func (t *Table) Skipped() []Skip { return t.skipped }
