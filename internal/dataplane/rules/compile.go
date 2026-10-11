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
	ReasonByName        Reason = iota + 1 // a domain or geosite matcher: not enforced in route-table mode
	ReasonNoList                          // a GeoIP list the node doesn't have (yet): matches nothing
	ReasonUnknownMatch                    // a matcher the node doesn't know or can't read: matches nothing
	ReasonUnknownAction                   // an action the node doesn't know: blocks
	ReasonNoChain                         // a chain that can't carry traffic: blocks
	ReasonAfterUnknown                    // a direct rule after one whose addresses aren't known: off
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
	overlay *lists.Set
	direct  *lists.Set
	skipped []Skip
}

// Compile resolves an effective rule list (see the package doc for what
// route-table mode can't enforce and what it does instead).
func Compile(entries []Entry, o Options) *Table {
	t := &Table{overlay: setOf(o.Overlay)}
	claimed := t.overlay
	var actions []netmap.Action // in order of first use, so the result is deterministic
	effective := make(map[netmap.Action]*lists.Builder)
	claim := func(a netmap.Action, s *lists.Set) {
		eff := s.Minus(claimed)
		if eff.IsEmpty() {
			return
		}
		if effective[a] == nil {
			actions = append(actions, a)
			effective[a] = &lists.Builder{}
		}
		effective[a].AddSet(eff)
		claimed = union(claimed, eff)
	}

	unknown := false // a rule whose addresses aren't known came first
	for _, e := range entries {
		r := e.Rule
		skip := func(reason Reason) {
			t.skipped = append(t.skipped, Skip{Origin: e.Origin, Index: e.Index, Reason: reason})
		}
		if r.Match.Kind.ByName() {
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
		claim(action, set)
	}
	rest := netmap.Block
	if len(entries) == 0 {
		rest = netmap.Direct
	}
	claim(rest, lists.All())

	// Per family, the action with the most prefixes becomes a /0 route,
	// and the other actions' prefixes, disjoint, override it. A
	// longest-prefix match still finds every address's action, from far
	// fewer routes than the partition itself: the rest of the world around
	// a country's list fragments into many times its prefixes.
	sets := make(map[netmap.Action]*lists.Set, len(actions))
	var counts [2]map[netmap.Action]int // prefixes per family
	counts[0], counts[1] = make(map[netmap.Action]int), make(map[netmap.Action]int)
	for _, a := range actions {
		s, st := effective[a].Build()
		sets[a] = s
		counts[0][a], counts[1][a] = st.Prefixes4, st.Prefixes6
	}
	t.direct = sets[netmap.Direct]
	var background [2]*netmap.Action
	for f, zero := range []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)} {
		most := 0
		for _, a := range actions {
			if n := counts[f][a]; n > most {
				background[f], most = &a, n
			}
		}
		if background[f] != nil {
			t.routes = append(t.routes, Route{Prefix: zero, Action: *background[f]})
		}
	}
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
	t.nzero = len(t.routes)
	slices.SortFunc(specific, func(a, b Route) int { return a.Prefix.Addr().Compare(b.Prefix.Addr()) })
	t.routes = append(t.routes, specific...)
	if t.direct == nil {
		t.direct = &lists.Set{}
	}
	return t
}

func (o Options) resolve(m netmap.Match) (*lists.Set, Reason) {
	switch m.Kind {
	case netmap.MatchDefault:
		return lists.All(), 0
	case netmap.MatchLocal:
		return lists.Local(), 0
	case netmap.MatchCIDR:
		// The builder's rule for IPv4-mapped IPv6 holds here too.
		var b lists.Builder
		if m.Prefix.Addr().Zone() != "" || b.AddPrefix(m.Prefix) != nil {
			return nil, ReasonUnknownMatch
		}
		s, _ := b.Build()
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

// Skipped are the rules not enforced as written, in rule order.
func (t *Table) Skipped() []Skip { return t.skipped }
