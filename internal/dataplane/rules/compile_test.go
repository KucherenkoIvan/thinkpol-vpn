package rules

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var (
	nl       = netmap.ToChain("nl")
	de       = netmap.ToChain("de")
	overlay  = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16"), netip.MustParsePrefix("fd00:1:2::/48")}
	ruList   = []string{"77.88.0.0/18", "5.255.255.0/24", "2a02:6b8::/32"}
	inRU     = []string{"77.88.8.8", "5.255.255.5", "2a02:6b8::feed:ff"}
	outRU    = []string{"8.8.8.8", "2001:4860:4860::8888"}
	overlay4 = "100.64.0.7"
	overlay6 = "fd00:1:2::7"
)

// mustRules parses one rule per line, the space's.
func mustRules(t testing.TB, text string) []netmap.Rule {
	t.Helper()
	var out []netmap.Rule
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		r, err := netmap.ParseRule(line)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func entriesOf(rs []netmap.Rule, origin Origin) []Entry {
	var out []Entry
	for i, r := range rs {
		out = append(out, Entry{Rule: r, Origin: origin, Index: i})
	}
	return out
}

func set(t testing.TB, prefixes ...string) *lists.Set {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func geoip(t testing.TB, available map[string][]string) func(string) (*lists.Set, bool) {
	sets := make(map[string]*lists.Set)
	for name, ps := range available {
		sets[name] = set(t, ps...)
	}
	return func(name string) (*lists.Set, bool) {
		s, ok := sets[name]
		return s, ok
	}
}

func onlyChains(names ...string) func(string) bool {
	return func(n string) bool { return slices.Contains(names, n) }
}

// overlayDest marks a destination the table leaves to the overlay.
var overlayDest = netmap.Action{Kind: 0, Chain: "(overlay)"}

func TestCompile(t *testing.T) {
	type want map[netmap.Action][]string
	tests := []struct {
		name    string
		rules   string
		lists   map[string][]string
		chains  []string // nil: every chain can carry traffic
		want    want
		skipped []Skip
	}{
		{
			name:  "a wider prefix first shadows a narrower one",
			rules: "cidr:10.0.0.0/8 -> chain:nl\ncidr:10.1.0.0/16 -> direct\ndefault -> block",
			want:  want{nl: {"10.1.2.3", "10.0.0.0", "10.255.255.255"}, netmap.Block: {"11.0.0.0", "9.255.255.255", "2001:db8::1"}},
		},
		{
			name:  "a narrower prefix first carves a hole in a wider one",
			rules: "cidr:10.1.0.0/16 -> direct\ncidr:10.0.0.0/8 -> chain:nl\ndefault -> block",
			want:  want{netmap.Direct: {"10.1.0.0", "10.1.255.255"}, nl: {"10.0.255.255", "10.2.0.0"}, netmap.Block: {"8.8.8.8"}},
		},
		{
			name:  "IPv6, and IPv4-mapped addresses as IPv4",
			rules: "cidr:2001:db8::/32 -> direct\ncidr:2001:db8:1::/48 -> block\ncidr:192.0.2.0/24 -> block\ndefault -> chain:nl",
			want: want{
				netmap.Direct: {"2001:db8::1", "2001:db8:1::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
				nl:            {"2001:db9::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", "::", "::ffff:8.8.8.8", "8.8.8.8"},
				netmap.Block:  {"::ffff:192.0.2.1", "192.0.2.255"},
			},
		},
		{
			name:  "all but domestic",
			rules: "local -> direct\ngeoip:ru -> direct\ndefault -> chain:nl",
			lists: map[string][]string{"ru": ruList},
			want: want{
				netmap.Direct: append([]string{"192.168.1.1", "10.0.0.1", "fe80::1", "ff02::fb", "224.0.0.251", "255.255.255.255"}, inRU...),
				nl:            append([]string{"100.65.0.1", "127.0.0.1", "172.32.0.1"}, outRU...),
			},
		},
		{
			name:  "the overlay is decided first, whatever the rules say",
			rules: "cidr:100.64.0.0/10 -> direct\ncidr:fd00::/8 -> direct\ndefault -> block",
			want: want{
				overlayDest:   {overlay4, overlay6, "100.64.255.255", "fd00:1:2:ffff::1"},
				netmap.Direct: {"100.65.0.1", "100.127.255.255", "fd00:1:3::1", "fd00:1:1:ffff:ffff:ffff:ffff:ffff"},
				netmap.Block:  {"100.63.255.255", "100.128.0.0"},
			},
		},
		{
			name:  "domain matchers are kept but not enforced",
			rules: "domain-suffix:example.com -> chain:de\ngeosite:youtube -> block\ndomain:mail.example.ru -> direct\ngeoip:ru -> direct\ndefault -> chain:nl",
			lists: map[string][]string{"ru": ruList},
			want:  want{netmap.Direct: inRU, nl: outRU},
			skipped: []Skip{
				{OriginSpace, 0, ReasonByName}, {OriginSpace, 1, ReasonByName}, {OriginSpace, 2, ReasonByName},
			},
		},
		{
			name:    "a direct list not there yet matches nothing",
			rules:   "geoip:ru -> direct\nlocal -> direct\ndefault -> chain:nl",
			want:    want{nl: append(inRU, outRU...), netmap.Direct: {"192.168.0.1"}},
			skipped: []Skip{{OriginSpace, 0, ReasonNoList}},
		},
		{
			name:    "after a tunnelled list not there yet, nothing goes direct",
			rules:   "geoip:de -> chain:de\nlocal -> direct\ngeoip:ru -> direct\ndefault -> chain:nl",
			lists:   map[string][]string{"ru": ruList},
			want:    want{nl: append(append([]string{"192.168.0.1"}, inRU...), outRU...)},
			skipped: []Skip{{OriginSpace, 0, ReasonNoList}, {OriginSpace, 1, ReasonAfterUnknown}, {OriginSpace, 2, ReasonAfterUnknown}},
		},
		{
			name:    "a chain that can't carry traffic blocks",
			rules:   "geoip:ru -> chain:de\nlocal -> direct\ndefault -> chain:nl",
			lists:   map[string][]string{"ru": ruList},
			chains:  []string{"nl"},
			want:    want{netmap.Block: inRU, nl: outRU, netmap.Direct: {"10.9.9.9"}},
			skipped: []Skip{{OriginSpace, 0, ReasonNoChain}},
		},
		{
			name:  "without a default, the rest is blocked",
			rules: "cidr:10.0.0.0/8 -> direct",
			want:  want{netmap.Direct: {"10.0.0.1"}, netmap.Block: {"8.8.8.8", "2001:db8::1"}, overlayDest: {overlay4}},
		},
		{
			name:  "without rules, nothing goes through the tunnel",
			want:  want{netmap.Direct: {"8.8.8.8", "10.0.0.1", "2001:db8::1", "100.65.0.1"}, overlayDest: {overlay4, overlay6}},
			rules: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Options{Overlay: overlay, GeoIP: geoip(t, tt.lists)}
			if tt.chains != nil {
				o.Chain = onlyChains(tt.chains...)
			}
			entries := entriesOf(mustRules(t, tt.rules), OriginSpace)
			tab := Compile(entries, o)
			for action, addrs := range tt.want {
				for _, s := range addrs {
					a := netip.MustParseAddr(s)
					got, ok := tab.Lookup(a)
					if !ok {
						got = overlayDest
					}
					if got != action {
						t.Errorf("%s: %v, want %v", a, got, action)
					}
					if inDirect := tab.Direct().Contains(a); inDirect != (action == netmap.Direct) {
						t.Errorf("%s: in the direct set: %v", a, inDirect)
					}
				}
			}
			if !slices.Equal(tab.Skipped(), tt.skipped) {
				t.Errorf("skipped %v, want %v", tab.Skipped(), tt.skipped)
			}
			var probes []netip.Addr
			for _, addrs := range tt.want {
				for _, s := range addrs {
					probes = append(probes, netip.MustParseAddr(s))
				}
			}
			checkTable(t, tab, overlay, probes)
		})
	}
}

// checkTable: at most one /0 route per family, first; the other routes
// sorted, disjoint and clear of the overlay; and for each address a
// longest-prefix match over the routes agrees with Lookup, and the direct
// set with both.
func checkTable(t *testing.T, tab *Table, overlay []netip.Prefix, probes []netip.Addr) {
	t.Helper()
	routes := tab.Routes()
	zero := 0
	for zero < len(routes) && routes[zero].Prefix.Bits() == 0 {
		zero++
	}
	if zero > 2 || zero == 2 && routes[0].Prefix.Addr().Is4() == routes[1].Prefix.Addr().Is4() {
		t.Fatalf("%d /0 routes: %v", zero, routes[:zero])
	}
	ov := setOf(overlay)
	for i, r := range routes[zero:] {
		if r.Prefix.Bits() == 0 {
			t.Fatalf("a second /0 route %v", r)
		}
		if i > 0 {
			prev := routes[zero+i-1]
			if prev.Prefix.Overlaps(r.Prefix) || !prev.Prefix.Addr().Less(r.Prefix.Addr()) {
				t.Fatalf("routes %v and %v overlap or are out of order", prev, r)
			}
		}
		if !set(t, r.Prefix.String()).Minus(ov).Equal(set(t, r.Prefix.String())) {
			t.Fatalf("route %v overlaps the overlay", r)
		}
	}
	for _, a := range probes {
		got, ok := tab.Lookup(a)
		if !ok {
			if !ov.Contains(a) {
				t.Fatalf("%s: no action outside the overlay", a)
			}
			continue
		}
		if lpm := longestMatch(routes, a.Unmap()); lpm != got {
			t.Fatalf("%s: Lookup %v, longest prefix match %v", a, got, lpm)
		}
		if tab.Direct().Contains(a) != (got == netmap.Direct) {
			t.Fatalf("%s: %v, in the direct set: %v", a, got, tab.Direct().Contains(a))
		}
	}
}

func longestMatch(routes []Route, a netip.Addr) netmap.Action {
	best := Route{Prefix: netip.PrefixFrom(a, 0), Action: netmap.Action{Chain: "(none)"}}
	bits := -1
	for _, r := range routes {
		if r.Prefix.Contains(a) && r.Prefix.Bits() > bits {
			best, bits = r, r.Prefix.Bits()
		}
	}
	return best.Action
}

func TestEffectiveOverridesAndPresets(t *testing.T) {
	space := mustRules(t, "local -> direct\ngeoip:ru -> direct\ncidr:198.51.100.0/24 -> block\ndefault -> chain:nl")
	presets := netmap.RulePresets{Domestic: "ru", Chain: "nl"}
	o := Options{Overlay: overlay, GeoIP: geoip(t, map[string][]string{"ru": ruList})}
	type want map[netmap.Action][]string
	tests := []struct {
		name     string
		local    string
		presets  netmap.RulePresets
		base     Preset
		want     want
		disabled []string // the space's rules a preset leaves out
	}{
		{
			name: "the space's rules", presets: presets, base: PresetSpace,
			want: want{netmap.Direct: append([]string{"192.168.1.1"}, inRU...), nl: outRU, netmap.Block: {"198.51.100.1"}},
		},
		{
			name:    "local rules go first",
			local:   "cidr:77.88.8.0/24 -> chain:nl\ncidr:198.51.100.7/32 -> direct\ncidr:8.8.8.0/24 -> block",
			presets: presets, base: PresetSpace,
			want: want{
				nl:            {"77.88.8.8", "1.1.1.1"},
				netmap.Direct: {"77.88.0.1", "198.51.100.7", "192.168.1.1"},
				netmap.Block:  {"8.8.8.8", "198.51.100.8"},
			},
		},
		{
			name: "a local default leaves the space's rules nothing", local: "default -> chain:de", presets: presets, base: PresetSpace,
			want: want{de: {"192.168.1.1", "1.1.1.1", "5.255.255.5", "198.51.100.1"}},
		},
		{
			name: "everything", local: "preset everything", presets: presets, base: PresetEverything,
			want: want{netmap.Direct: {"192.168.1.1", "fe80::1"}, nl: append(append([]string{"198.51.100.1"}, inRU...), outRU...)},
		},
		{
			name: "all but domestic", local: "preset all-but-domestic", presets: presets, base: PresetAllButDomestic,
			want: want{netmap.Direct: append([]string{"192.168.1.1"}, inRU...), nl: append([]string{"198.51.100.1"}, outRU...)},
		},
		{
			name: "a preset with local rules on top", local: "preset everything\ngeoip:ru -> direct", presets: presets, base: PresetEverything,
			want: want{netmap.Direct: inRU, nl: outRU},
		},
		{
			name: "a preset the space can't build falls back to its rules", local: "preset all-but-domestic",
			presets: netmap.RulePresets{Chain: "nl"}, base: PresetSpace,
			want: want{netmap.Block: {"198.51.100.1"}, netmap.Direct: inRU},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l Local
			if err := l.UnmarshalText([]byte(tt.local)); err != nil {
				t.Fatal(err)
			}
			entries, base := Effective(space, tt.presets, l)
			if base != tt.base {
				t.Fatalf("base %v, want %v", base, tt.base)
			}
			for i, e := range entries {
				if i < len(l.Rules) != (e.Origin == OriginLocal) {
					t.Fatalf("entry %d from %v: local rules must come first", i, e.Origin)
				}
			}
			tab := Compile(entries, o)
			for action, addrs := range tt.want {
				for _, s := range addrs {
					if got, _ := tab.Lookup(netip.MustParseAddr(s)); got != action {
						t.Errorf("%s: %v, want %v", s, got, action)
					}
				}
			}
		})
	}
}

func TestPresetRules(t *testing.T) {
	p := netmap.RulePresets{Domestic: "ru", Chain: "nl"}
	for preset, want := range map[Preset]string{
		PresetEverything:     "local -> direct; default -> chain:nl",
		PresetAllButDomestic: "local -> direct; geoip:ru -> direct; default -> chain:nl",
		PresetSpace:          "cidr:10.0.0.0/8 -> block",
	} {
		rs, err := PresetRules(preset, mustRules(t, "cidr:10.0.0.0/8 -> block"), p)
		if err != nil {
			t.Fatal(err)
		}
		var text []string
		for _, r := range rs {
			text = append(text, r.String())
		}
		if got := strings.Join(text, "; "); got != want {
			t.Errorf("%v: %s, want %s", preset, got, want)
		}
	}
	for _, tc := range []struct {
		p Preset
		s netmap.RulePresets
	}{
		{PresetEverything, netmap.RulePresets{Domestic: "ru"}},
		{PresetAllButDomestic, netmap.RulePresets{Chain: "nl"}},
		{Preset(9), p},
	} {
		if _, err := PresetRules(tc.p, nil, tc.s); err == nil {
			t.Errorf("%v from %+v: no error", tc.p, tc.s)
		}
	}
}

func TestLocalFile(t *testing.T) {
	text := "# this device\n\npreset all-but-domestic\ncidr:192.0.2.0/24 -> direct\n  geoip:de → chain:de  \ndomain-suffix:Example.COM -> block\n"
	var l Local
	if err := l.UnmarshalText([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if l.Preset != PresetAllButDomestic || len(l.Rules) != 3 {
		t.Fatalf("%+v", l)
	}
	out, err := l.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := "preset all-but-domestic\ncidr:192.0.2.0/24 -> direct\ngeoip:de -> chain:de\ndomain-suffix:example.com -> block\n"
	if string(out) != want {
		t.Fatalf("written as\n%s\nwant\n%s", out, want)
	}
	var again Local
	if err := again.UnmarshalText(out); err != nil || !slices.Equal(again.Rules, l.Rules) || again.Preset != l.Preset {
		t.Fatalf("read back as %+v, %v", again, err)
	}
	if b, err := (Local{}).MarshalText(); err != nil || len(b) != 0 {
		t.Errorf("the empty file is %q, %v", b, err)
	}

	for name, bad := range map[string]string{
		"two presets":    "preset everything\npreset space",
		"unknown preset": "preset most",
		"bad rule":       "preset everything\ncidr:10.0.0.1/8 -> direct",
		"not a rule":     "everything",
		"too many rules": strings.Repeat("default -> block\n", maxLocalRules+1),
	} {
		var l Local
		err := l.UnmarshalText([]byte(bad))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "line ") {
			t.Errorf("%s: %v doesn't say where", name, err)
		}
	}
	if _, err := (Local{Preset: 7}).MarshalText(); err == nil {
		t.Error("an unknown preset was written")
	}
}

// TestCompileMatchesFirstMatch compares the compiled table with a naive
// first-match evaluator over random rule lists: overlapping prefixes of
// both families, lists present and missing, domain and unknown matchers,
// unknown actions and unavailable chains, at every prefix's edges and
// around them.
func TestCompileMatchesFirstMatch(t *testing.T) {
	rng := rand.New(rand.NewPCG(15, 2026))
	for iter := range 400 {
		g := newGen(rng)
		entries, o := g.ruleList()
		tab := Compile(entries, o)
		probes := g.probes()
		checkTable(t, tab, o.Overlay, probes)
		for _, a := range probes {
			want, wantOK := g.naive(entries, o, a)
			got, ok := tab.Lookup(a)
			if got != want || ok != wantOK {
				t.Fatalf("iteration %d, %s: compiled %v (%v), first match %v (%v)\nrules:\n%s", iter, a, got, ok, want, wantOK, g.describe(entries))
			}
		}
	}
}

type gen struct {
	rng     *rand.Rand
	anchors []netip.Addr
	edges   []netip.Prefix // every prefix in play, for probes
	lists   map[string][]netip.Prefix
}

func newGen(rng *rand.Rand) *gen {
	g := &gen{rng: rng, lists: make(map[string][]netip.Prefix)}
	for range 4 {
		var a4 [4]byte
		var a6 [16]byte
		for i := range a4 {
			a4[i] = byte(rng.IntN(256))
		}
		for i := range a6 {
			a6[i] = byte(rng.IntN(256))
		}
		g.anchors = append(g.anchors, netip.AddrFrom4(a4), netip.AddrFrom16(a6))
	}
	// Edge cases next to the mapped range and the ends of each family.
	g.anchors = append(g.anchors, netip.MustParseAddr("::ffff:10.1.2.3"), netip.MustParseAddr("::"), netip.MustParseAddr("255.255.255.255"))
	g.edges = append(g.edges, lists.Local().Prefixes()...)
	return g
}

// prefix is a prefix around a random anchor: overlapping often.
func (g *gen) prefix() netip.Prefix {
	a := g.anchors[g.rng.IntN(len(g.anchors))]
	bits := g.rng.IntN(a.BitLen() + 1)
	if g.rng.IntN(3) > 0 { // mostly long prefixes, so they nest
		bits = a.BitLen() - g.rng.IntN(min(a.BitLen(), 24)+1)
	}
	p, _ := a.Prefix(bits)
	g.edges = append(g.edges, p)
	return p
}

func (g *gen) ruleList() ([]Entry, Options) {
	var o Options
	for range g.rng.IntN(3) {
		// Overlay networks are never IPv4-mapped (an IPv4 range and a ULA).
		if p := g.prefix(); !p.Addr().Is6() || !p.Overlaps(mappedRange) {
			o.Overlay = append(o.Overlay, p)
		}
	}
	available := make(map[string]*lists.Set)
	for _, name := range []string{"aa", "bb"} {
		var b lists.Builder
		for range g.rng.IntN(5) {
			p := g.prefix()
			if b.AddPrefix(p) == nil {
				g.lists[name] = append(g.lists[name], p)
			}
		}
		s, _ := b.Build()
		available[name] = s
	}
	o.GeoIP = func(name string) (*lists.Set, bool) { s, ok := available[name]; return s, ok }
	o.Chain = func(name string) bool { return name != "down" }

	matchers := []func() netmap.Match{
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchDefault} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchLocal} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchCIDR, Prefix: g.prefix()} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchCIDR, Prefix: g.prefix()} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchCIDR, Prefix: g.prefix()} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchGeoIP, Value: "aa"} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchGeoIP, Value: "bb"} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchGeoIP, Value: "missing"} },
		func() netmap.Match { return netmap.Match{Kind: netmap.MatchDomainSuffix, Value: "example.com"} },
		func() netmap.Match { return netmap.Match{Kind: 42, Value: "x"} },
	}
	actions := []netmap.Action{
		netmap.Direct, netmap.Direct, netmap.Direct, netmap.Block, nl, nl, de,
		netmap.ToChain("down"), {Kind: 9}, {Kind: netmap.ActionChain},
	}
	var entries []Entry
	for i := range g.rng.IntN(9) {
		r := netmap.Rule{
			Match:  matchers[g.rng.IntN(len(matchers))](),
			Action: actions[g.rng.IntN(len(actions))],
		}
		origin := OriginSpace
		if g.rng.IntN(3) == 0 {
			origin = OriginLocal
		}
		entries = append(entries, Entry{Rule: r, Origin: origin, Index: i})
	}
	return entries, o
}

var mappedRange = netip.MustParsePrefix("::ffff:0:0/96")

// naive is first match, written out: the semantics the package doc gives.
func (g *gen) naive(entries []Entry, o Options, a netip.Addr) (netmap.Action, bool) {
	a = a.Unmap()
	for _, p := range o.Overlay {
		if p.Masked().Contains(a) {
			return netmap.Action{}, false
		}
	}
	if len(entries) == 0 {
		return netmap.Direct, true
	}
	unknown := false
	for _, e := range entries {
		m := e.Rule.Match
		var matches bool
		switch {
		case m.Kind == netmap.MatchDefault:
			matches = true
		case m.Kind == netmap.MatchLocal:
			matches = lists.Local().Contains(a)
		case m.Kind == netmap.MatchCIDR && (m.Prefix.Addr().Is4() || !m.Prefix.Overlaps(mappedRange)):
			matches = m.Prefix.Masked().Contains(a)
		case m.Kind == netmap.MatchGeoIP && (m.Value == "aa" || m.Value == "bb"):
			for _, p := range g.lists[m.Value] {
				matches = matches || p.Contains(a)
			}
		case m.Kind.ByName():
			continue
		default: // addresses unknown
			if e.Rule.Action.Kind != netmap.ActionDirect {
				unknown = true
			}
			continue
		}
		action := e.Rule.Action
		switch {
		case action.Kind < netmap.ActionDirect || action.Kind > netmap.ActionBlock || action.Kind == netmap.ActionChain && action.Chain == "":
			action = netmap.Block
		case action.Chain == "down":
			action = netmap.Block
		case action == netmap.Direct && unknown:
			continue
		}
		if matches {
			return action, true
		}
	}
	return netmap.Block, true
}

// probes are every edge of every prefix in play, the addresses next to
// them, and random ones near the anchors.
func (g *gen) probes() []netip.Addr {
	var out []netip.Addr
	for _, p := range g.edges {
		first, last := p.Masked().Addr(), lastAddr(p)
		out = append(out, first, last, first.Next(), last.Prev(), first.Prev(), last.Next())
	}
	for _, a := range g.anchors {
		for range 8 {
			b := a.AsSlice()
			b[len(b)-1-g.rng.IntN(len(b))] ^= byte(1 << g.rng.IntN(8))
			c, _ := netip.AddrFromSlice(b)
			out = append(out, c.Unmap(), c)
		}
	}
	return slices.DeleteFunc(out, func(a netip.Addr) bool { return !a.IsValid() })
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func (g *gen) describe(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "  %v\n", e.Rule)
	}
	for name, ps := range g.lists {
		fmt.Fprintf(&b, "  list %s: %v\n", name, ps)
	}
	return b.String()
}

// BenchmarkCompileCountry compiles "all but domestic" with a list the size
// of RU's (12.9k IPv4 and 10.1k IPv6 prefixes).
func BenchmarkCompileCountry(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	var lb lists.Builder
	for range 12900 {
		p, _ := netip.AddrFrom4([4]byte{byte(rng.IntN(224)), byte(rng.IntN(256)), byte(rng.IntN(256)), 0}).Prefix(16 + rng.IntN(9))
		_ = lb.AddPrefix(p)
	}
	for range 10100 {
		var a [16]byte
		a[0], a[1], a[2], a[3] = 0x2a, byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))
		p, _ := netip.AddrFrom16(a).Prefix(29 + rng.IntN(20))
		_ = lb.AddPrefix(p)
	}
	country, _ := lb.Build()
	entries := entriesOf(mustRules(b, "local -> direct\ngeoip:ru -> direct\ndefault -> chain:nl"), OriginSpace)
	o := Options{Overlay: overlay, GeoIP: func(string) (*lists.Set, bool) { return country, true }}
	b.ResetTimer()
	var tab *Table
	for b.Loop() {
		tab = Compile(entries, o)
	}
	b.ReportMetric(float64(len(tab.Routes())), "routes")
	b.ReportMetric(float64(len(tab.Direct().Prefixes())), "direct")
}
