package rules

import (
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func TestNamesFollowTheRulesFirstMatchWins(t *testing.T) {
	nl, de := netmap.ToChain("nl"), netmap.ToChain("de")
	usable := func(name string) bool { return name != "gone" }
	tests := []struct {
		name  string
		rules []string
		want  map[string]netmap.Action
	}{
		{"no rules: everything direct", nil, map[string]netmap.Action{"example.com": netmap.Direct}},
		{"rules without default: the rest blocked", []string{"domain:a.example -> chain:nl"}, map[string]netmap.Action{
			"a.example": nl, "b.example": netmap.Block,
		}},
		{"domain is exact, domain-suffix covers the name and below", []string{
			"domain:shop.example.ru -> chain:de",
			"domain-suffix:example.ru -> direct",
			"default -> chain:nl",
		}, map[string]netmap.Action{
			"shop.example.ru":     de,
			"www.shop.example.ru": netmap.Direct,
			"example.ru":          netmap.Direct,
			"a.b.example.ru":      netmap.Direct,
			"notexample.ru":       nl,
			"ru":                  nl,
			"example.com":         nl,
		}},
		{"an earlier suffix beats a later exact name", []string{
			"domain-suffix:example.ru -> chain:nl",
			"domain:www.example.ru -> direct",
			"default -> block",
		}, map[string]netmap.Action{"www.example.ru": nl}},
		{"a more specific suffix later loses", []string{
			"domain-suffix:ru -> direct",
			"domain-suffix:youtube.ru -> chain:nl",
			"default -> chain:nl",
		}, map[string]netmap.Action{"m.youtube.ru": netmap.Direct}},
		{"address rules can't decide a name", []string{
			"local -> direct",
			"geoip:ru -> direct",
			"cidr:192.0.2.0/24 -> block",
			"default -> chain:nl",
		}, map[string]netmap.Action{"example.ru": nl, "lan": nl}},
		{"geosite turns later direct rules off", []string{
			"geosite:youtube -> chain:nl",
			"domain-suffix:ru -> direct",
			"default -> chain:nl",
		}, map[string]netmap.Action{"example.ru": nl}},
		{"a direct geosite doesn't", []string{
			"geosite:ru -> direct",
			"domain-suffix:ru -> direct",
			"default -> chain:nl",
		}, map[string]netmap.Action{"example.ru": netmap.Direct}},
		{"a chain that can't carry traffic blocks, never falls through", []string{
			"domain-suffix:example.com -> chain:gone",
			"default -> direct",
		}, map[string]netmap.Action{"www.example.com": netmap.Block, "example.org": netmap.Direct}},
		{"the first default wins", []string{
			"default -> chain:nl",
			"default -> direct",
			"domain:late.example -> direct",
		}, map[string]netmap.Action{"late.example": nl, "x.example": nl}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entries []Entry
			for i, text := range tt.rules {
				r, err := netmap.ParseRule(text)
				if err != nil {
					t.Fatal(err)
				}
				entries = append(entries, Entry{Rule: r, Origin: OriginSpace, Index: i})
			}
			n := CompileNames(entries, Options{Chain: usable})
			for name, want := range tt.want {
				if got := n.Lookup(name); got != want {
					t.Errorf("Lookup(%q) = %v, want %v", name, got, want)
				}
			}
		})
	}
}

func TestNamesBlockUnknownActionsAndKeepUnknownMatchersFailClosed(t *testing.T) {
	entries := []Entry{
		{Rule: netmap.Rule{Match: netmap.Match{Kind: netmap.MatchDomain, Value: "a.example"}, Action: netmap.Action{Kind: 9}}},
		{Rule: netmap.Rule{Match: netmap.Match{Kind: 42, Value: "x"}, Action: netmap.ToChain("nl")}},
		{Rule: netmap.Rule{Match: netmap.Match{Kind: netmap.MatchDomain, Value: "b.example"}, Action: netmap.Direct}},
		{Rule: netmap.Rule{Match: netmap.Match{Kind: netmap.MatchDefault}, Action: netmap.ToChain("nl")}},
	}
	n := CompileNames(entries, Options{})
	if got := n.Lookup("a.example"); got != netmap.Block {
		t.Errorf("unknown action: %v, want block", got)
	}
	if got := n.Lookup("b.example"); got != netmap.ToChain("nl") {
		t.Errorf("direct after an unknown matcher: %v, want the default's chain", got)
	}
}

// The effective list a device gets, presets included, decides names the
// same way: "everything" sends every name through the chain.
func TestNamesFollowPresets(t *testing.T) {
	space := []netmap.Rule{{Match: netmap.Match{Kind: netmap.MatchDefault}, Action: netmap.Direct}}
	own, err := netmap.ParseRule("domain-suffix:example.ru -> direct")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Effective(space, netmap.RulePresets{Chain: "nl"}, Local{Preset: PresetEverything, Rules: []netmap.Rule{own}})
	if err != nil {
		t.Fatal(err)
	}
	n := CompileNames(entries, Options{})
	if got := n.Lookup("www.example.ru"); got != netmap.Direct {
		t.Errorf("own rule: %v", got)
	}
	if got := n.Lookup("example.com"); got != netmap.ToChain("nl") {
		t.Errorf("preset: %v", got)
	}
}
