package rules

import (
	"math"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Names is a rule list compiled for DNS names (DESIGN.md "DNS is
// routing"): the action of the first rule that matches a name, which
// decides where the name is resolved: direct names by the domestic
// upstream, a chain's through the tunnel at its exit, blocked ones
// nowhere.
//
// It follows the same list as Compile, with the same fail-closed rules,
// seen from names:
//
//   - domain matches the name exactly, domain-suffix the name and every
//     name under it, default every name;
//   - address matchers (local, cidr, geoip) can't decide a name and are
//     passed over;
//   - a matcher whose names aren't known (geosite, until there is a
//     geosite list format; an unknown matcher) matches nothing and, unless
//     it is direct itself, turns off every later direct rule;
//   - an unknown action, or a chain that can't carry traffic, blocks;
//   - a name no rule matches is blocked; with no rules at all, every name
//     is direct, as every address is.
//
// A name's action decides only which upstream answers it: the addresses in
// the answer are routed by the address rules, like any other.
type Names struct {
	exact, suffix map[string]nameRule
	rest          nameRule
}

type nameRule struct {
	index  int // in the effective list: the first match wins
	action netmap.Action
}

// CompileNames compiles an effective rule list for names. Of the options
// only Chain is used.
func CompileNames(entries []Entry, o Options) *Names {
	n := &Names{exact: map[string]nameRule{}, suffix: map[string]nameRule{}, rest: nameRule{index: math.MaxInt, action: netmap.Block}}
	if len(entries) == 0 {
		n.rest.action = netmap.Direct
		return n
	}
	unknown := false
	for i, e := range entries {
		r := e.Rule
		switch r.Match.Kind {
		case netmap.MatchDomain, netmap.MatchDomainSuffix, netmap.MatchDefault:
		case netmap.MatchLocal, netmap.MatchCIDR, netmap.MatchGeoIP:
			continue
		default:
			unknown = unknown || r.Action.Kind != netmap.ActionDirect
			continue
		}
		action := r.Action
		switch {
		case action != netmap.Direct && action != netmap.Block && (action.Kind != netmap.ActionChain || action.Chain == ""):
			action = netmap.Block
		case action.Kind == netmap.ActionChain && o.Chain != nil && !o.Chain(action.Chain):
			action = netmap.Block
		case action == netmap.Direct && unknown:
			continue
		}
		rule := nameRule{index: i, action: action}
		switch r.Match.Kind {
		case netmap.MatchDefault:
			if n.rest.index == math.MaxInt {
				n.rest = rule
			}
		case netmap.MatchDomain:
			if _, ok := n.exact[r.Match.Value]; !ok {
				n.exact[r.Match.Value] = rule
			}
		case netmap.MatchDomainSuffix:
			if _, ok := n.suffix[r.Match.Value]; !ok {
				n.suffix[r.Match.Value] = rule
			}
		}
	}
	return n
}

// Lookup returns the action for a name, lowercase and without the
// trailing dot.
func (n *Names) Lookup(name string) netmap.Action {
	best := n.rest
	if r, ok := n.exact[name]; ok && r.index < best.index {
		best = r
	}
	for d := name; ; {
		if r, ok := n.suffix[d]; ok && r.index < best.index {
			best = r
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return best.action
}
