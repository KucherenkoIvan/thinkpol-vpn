package netmap

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

func TestParseRule(t *testing.T) {
	good := []struct {
		in   string
		want Rule
		text string // the canonical text form, when it differs from in
	}{
		{"default -> chain:ru-nl", Rule{Match{Kind: MatchDefault}, ToChain("ru-nl")}, ""},
		{"local -> direct", Rule{Match{Kind: MatchLocal}, Direct}, ""},
		{"geoip:ru → direct", Rule{Match{Kind: MatchGeoIP, Value: "ru"}, Direct}, "geoip:ru -> direct"},
		{"  cidr:10.0.0.0/8->block ", Rule{Match{Kind: MatchCIDR, Prefix: netip.MustParsePrefix("10.0.0.0/8")}, Block}, "cidr:10.0.0.0/8 -> block"},
		{"cidr:2001:db8::/32 -> chain:de", Rule{Match{Kind: MatchCIDR, Prefix: netip.MustParsePrefix("2001:db8::/32")}, ToChain("de")}, ""},
		{"domain:Mail.Example.RU. -> direct", Rule{Match{Kind: MatchDomain, Value: "mail.example.ru"}, Direct}, "domain:mail.example.ru -> direct"},
		{"domain-suffix:xn--p1ai -> direct", Rule{Match{Kind: MatchDomainSuffix, Value: "xn--p1ai"}, Direct}, ""},
		{"geosite:youtube -> chain:de", Rule{Match{Kind: MatchGeoSite, Value: "youtube"}, ToChain("de")}, ""},
	}
	for _, tt := range good {
		got, err := ParseRule(tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%q = %+v, want %+v", tt.in, got, tt.want)
		}
		text := tt.text
		if text == "" {
			text = tt.in
		}
		if got.String() != text {
			t.Errorf("%q prints as %q, want %q", tt.in, got.String(), text)
		}
		if again, err := ParseRule(got.String()); err != nil || again != got {
			t.Errorf("%q: the text form doesn't parse back: %+v, %v", tt.in, again, err)
		}
	}

	for _, in := range []string{
		"", "default", "default direct", "-> direct", "default ->",
		"default:x -> direct", "local:lan -> direct", "everything -> direct",
		"cidr -> direct", "cidr:10.0.0.1/8 -> direct", "cidr:10.0.0.0 -> direct", "cidr:fe80::%eth0/64 -> direct",
		"cidr:::/0 -> direct", "cidr:::ffff:0:0/96 -> direct", "cidr:::ffff:10.0.0.0/104 -> direct", "cidr:::ffff:0:0/95 -> block",
		"geoip -> direct", "geoip: -> direct", "geoip:RU -> direct", "geoip:-ru -> direct", "geoip:ru_x -> direct",
		"geoip:abcdefghijklmnopqrstuvwxyz0123456 -> direct",
		"domain: -> direct", "domain:a..b -> direct", "domain:-a.b -> direct", "domain:a b -> direct", "domain:пример.рф -> direct",
		"default -> tunnel", "default -> chain:", "default -> chain:NL", "default -> direct:x", "default -> block:x",
	} {
		if r, err := ParseRule(in); err == nil {
			t.Errorf("%q accepted as %+v", in, r)
		}
	}
}

// Rules need section reader 2; sections without them stay readable by M0
// nodes.
func TestOnlySectionsWithRulesNeedTheNewReader(t *testing.T) {
	f := newFixture(t, 2, 1) // entry, exit, device
	h := f.verify(t, f.build(t)).Header()
	for i, want := range []uint32{1, 1, 2} {
		s := f.contents.Recipients[i].Section
		if got := sectionToProto(&s, &h).GetMinReader(); got != want {
			t.Errorf("section %d (%d rules) needs reader %d, want %d", i, len(s.Rules), got, want)
		}
	}
	presetsOnly := f.contents.Recipients[0].Section
	presetsOnly.Presets = RulePresets{Domestic: "ru"}
	if got := sectionToProto(&presetsOnly, &h).GetMinReader(); got != 2 {
		t.Errorf("a section with presets only needs reader %d, want 2", got)
	}
}

// A reader keeps what only the builder refuses (unknown kinds, a prefix
// with host bits, a chain no rule or peer has): the node reports what it
// can't enforce instead of refusing its whole section.
func TestReadersKeepRulesTheyCannotEnforce(t *testing.T) {
	f := newFixture(t, 2, 1)
	env := f.build(t)
	h := f.verify(t, env).Header()
	device := f.contents.Recipients[2].Section
	pb := sectionToProto(&device, &h)
	pb.Rules = append(pb.Rules,
		&netmapv1.Rule{Match: 42, Value: "asn:13335", Action: netmapv1.ActionKind_ACTION_KIND_DIRECT},
		&netmapv1.Rule{Match: netmapv1.MatchKind_MATCH_KIND_CIDR, Value: "198.51.100.7/24", Action: 300},
		&netmapv1.Rule{Match: netmapv1.MatchKind_MATCH_KIND_GEOIP, Value: "NOT A NAME", Action: netmapv1.ActionKind_ACTION_KIND_CHAIN, Chain: "nowhere"},
	)
	pb.Chains = append(pb.Chains, &netmapv1.Chain{Name: "Odd Name", Exit: []byte{9, 9, 9, 9, 9, 9, 9, 9}})
	got, err := sectionFromProto(pb)
	if err == nil {
		err = got.wellFormed()
	}
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Concat(device.Rules, []Rule{
		{Match{Kind: 42, Value: "asn:13335"}, Direct},
		{Match{Kind: MatchCIDR, Prefix: netip.MustParsePrefix("198.51.100.7/24")}, Action{Kind: 255}},
		{Match{Kind: MatchGeoIP, Value: "NOT A NAME"}, ToChain("nowhere")},
	})
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("rules\n%+v\nwant\n%+v", got.Rules, want)
	}
	if len(got.Chains) != 2 || got.Chains[1].Name != "Odd Name" || got.Presets != device.Presets {
		t.Errorf("chains %+v, presets %+v", got.Chains, got.Presets)
	}
	if got.Rules[len(device.Rules)].String() != "MatchKind(42):asn:13335 -> direct" {
		t.Errorf("unknown matcher prints as %q", got.Rules[len(device.Rules)])
	}
}
