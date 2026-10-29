package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

const thisBoot = "6F1C0D2E-0000-4000-8000-000000000001"

// The host's own addresses in these tests.
var (
	ownV6 = netip.MustParseAddr("2001:db8:1::10")
	ownV4 = netip.MustParseAddr("192.0.2.10")
)

func set(t *testing.T, prefixes ...string) *lists.Set {
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

func pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func aps(ss ...string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range ss {
		out = append(out, netip.MustParseAddrPort(s))
	}
	return out
}

// exempt is a device's Exempt: a direct /48, an endpoint, an IPv4 direct
// range and upstream (neither the guard's), an IPv6 upstream.
func exempt(t *testing.T) routetable.Exempt {
	return routetable.Exempt{
		TUN:       "utun7",
		Mark:      routetable.Mark,
		Direct:    set(t, "2001:db8:d0::/48", "2001:db8:e::9/128", "198.51.100.0/24"),
		Upstreams: aps("[2001:db8:53::1]:53", "192.0.2.53:53"),
	}
}

// rulesFor is how many rules pfctl lists for exempt(t)'s anchor: lo0,
// the utun, the exempt table, DNS to the upstream (tcp, udp), its
// neighbour probes (2), MLD (4), the block.
const rulesFor = 12

// tempDir is a test's directory by a path without symlinks (macOS's
// temporary directories are under /var, a symlink), as trusteddir wants.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// rig is a guard on a fake pf, its record in a test directory.
type rig struct {
	pf   *fakePF
	dir  string
	boot string
}

func newRig(t *testing.T) *rig {
	return &rig{pf: newFakePF(), dir: tempDir(t), boot: thisBoot}
}

func (r *rig) store() tokenStore {
	return tokenStore{dir: r.dir, boot: func() (string, error) { return r.boot, nil }}
}

func ownAddrs() ([]netip.Addr, error) {
	return []netip.Addr{netip.IPv6Loopback(), ownV6, ownV4}, nil
}

func (r *rig) guard() *IPv6Guard { return newIPv6Guard(r.pf, r.store(), time.Hour, ownAddrs) }

func (r *rig) record(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, tokenRecord))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *rig) writeRecord(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, tokenRecord), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func tableOf(a *fakeAnchor, name string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range a.tables[name] {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// whole fails t unless pf holds the guard for e: the tables are exactly
// e's, the rules pass tun and end in the block, pf is on with exactly
// one reference besides others, the record's.
func (r *rig) whole(t *testing.T, e routetable.Exempt, others ...pfToken) {
	t.Helper()
	a := r.pf.anchor(GuardAnchor)
	if got, want := tableOf(a, exemptTable), exemptPrefixes(e); !slices.Equal(got, want) {
		t.Errorf("exempt table %v, want %v", got, want)
	}
	if len(a.tables) != 1 {
		t.Errorf("tables %v, want the exempt table alone", a.tables)
	}
	if err := saneRules(a.rules, e.TUN, upstreamTargets(e)); err != nil || a.rules[len(a.rules)-1] != "block return out quick inet6 all" {
		t.Errorf("rules %q: %v", a.rules, err)
	}
	if !r.pf.isOn() {
		t.Error("pf is off")
	}
	var ours []pfToken
	for _, ref := range r.pf.references() {
		if !slices.Contains(others, ref) {
			ours = append(ours, ref)
		}
	}
	if len(ours) != 1 {
		t.Fatalf("references %v besides %v, want one of the guard's", ours, others)
	}
	if rec := r.record(t); !strings.Contains(rec, "\nboot "+r.boot+"\n") ||
		!strings.Contains(rec, "\ntoken "+strconv.FormatUint(ours[0].value, 10)+" pid "+strconv.Itoa(ours[0].pid)+"\n") {
		t.Errorf("record %q, want %v of boot %s", rec, ours[0], r.boot)
	}
}

// gone fails t unless the guard left nothing: no rule, no table, none of
// its references, no record; others' references untouched.
func (r *rig) gone(t *testing.T, others ...pfToken) {
	t.Helper()
	if a := r.pf.anchor(GuardAnchor); len(a.rules) != 0 || len(a.tables) != 0 {
		t.Errorf("anchor left: %+v", a)
	}
	if refs := r.pf.references(); !slices.Equal(refs, others) {
		t.Errorf("references %v, want %v", refs, others)
	}
	if rec := r.record(t); rec != "" {
		t.Errorf("record left: %q", rec)
	}
}

func TestAnchorText(t *testing.T) {
	e := exempt(t)
	e.Upstreams = append(e.Upstreams, aps("[2001:db8:53::2]:5353", "[fe80::53%en0]:53")...)
	got := anchorText("utun7", exemptPrefixes(e), upstreamTargets(e))
	want := `table <thinkpol_exempt6> persist { \
	2001:db8:e::9/128, \
	2001:db8:d0::/48, \
	fe80::/10, \
	ff02::/16 }
pass out quick on lo0 inet6 all no state
pass out quick on utun7 inet6 all no state
pass out quick inet6 from any to <thinkpol_exempt6> no state
pass out quick inet6 proto { tcp, udp } from any to 2001:db8:53::1 port 53 no state
pass out quick inet6 proto { tcp, udp } from any to 2001:db8:53::2 port 5353 no state
pass out quick inet6 proto ipv6-icmp from any to 2001:db8:53::1 icmp6-type { 135, 136 } no state
pass out quick inet6 proto ipv6-icmp from any to 2001:db8:53::2 icmp6-type { 135, 136 } no state
pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state
block return out quick inet6 all
`
	if got != want {
		t.Errorf("anchor:\n%s\nwant:\n%s", got, want)
	}
	// Without IPv6 upstreams, no rule for them.
	e.Upstreams = aps("192.0.2.53:53", "[fe80::53%en0]:53")
	got = anchorText("utun7", exemptPrefixes(e), upstreamTargets(e))
	if strings.Contains(got, "port") || strings.Contains(got, "135") {
		t.Errorf("without global IPv6 upstreams:\n%s", got)
	}
}

// The exempt table is the IPv6 exempt destinations as the fewest
// prefixes, never the upstreams; each global IPv6 upstream is passed DNS
// on its own port, no other. IPv4 and zones never reach either.
func TestTheTableAndTheUpstreams(t *testing.T) {
	var b lists.Builder
	_ = b.AddRange(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")) // two prefixes
	_ = b.AddPrefix(netip.MustParsePrefix("2001:db8::4/126"))
	_ = b.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	direct, _ := b.Build()
	e := routetable.Exempt{TUN: "utun3", Direct: direct,
		Upstreams: aps("[2001:db8::3]:53", "[fe80::1%en0]:53", "[::ffff:192.0.2.1]:53", "192.0.2.2:5300", "[2001:db8:1::5]:5353", "[2001:db8:1::5]:53", "[2001:db8::3]:53")}
	if got, want := exemptPrefixes(e), pfxs("2001:db8::1/128", "2001:db8::2/128", "2001:db8::4/126", "fe80::/10", "ff02::/16"); !slices.Equal(got, want) {
		t.Errorf("exempt %v, want %v", got, want)
	}
	want := aps("[2001:db8::3]:53", "[2001:db8:1::5]:53", "[2001:db8:1::5]:5353")
	if got := upstreamTargets(e); !slices.Equal(got, want) {
		t.Errorf("upstreams %v, want %v", got, want)
	}
	text := anchorText("utun3", exemptPrefixes(e), upstreamTargets(e))
	for _, line := range []string{
		"pass out quick inet6 proto { tcp, udp } from any to 2001:db8::3 port 53 no state",
		"pass out quick inet6 proto { tcp, udp } from any to 2001:db8:1::5 port 53 no state",
		"pass out quick inet6 proto { tcp, udp } from any to 2001:db8:1::5 port 5353 no state",
	} {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("no %q in\n%s", line, text)
		}
	}
	if strings.Contains(text, "2001:db8::3 port 5353") || strings.Count(text, "to 2001:db8:1::5 icmp6-type") != 1 {
		t.Errorf("ports crossed or probes doubled:\n%s", text)
	}
	if got := exemptPrefixes(routetable.Exempt{TUN: "utun3"}); !slices.Equal(got, routetable.LinkScoped) {
		t.Errorf("nothing exempt: %v, want LinkScoped", got)
	}
}

// A name that isn't an interface's never reaches pf's grammar.
func TestApplyRefusesWhatIsntAnInterfaceName(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	for _, tun := range []string{"", "utun7 all\nblock", "utun 7", "UTUN7", "utun7}", "averyveryverylongname0"} {
		e := exempt(t)
		e.TUN = tun
		if err := g.Apply(context.Background(), e); err == nil {
			t.Errorf("%q: applied", tun)
		}
	}
	if n := len(r.pf.calls); n != 0 {
		t.Errorf("pfctl ran %d times", n)
	}
}

func TestHooked(t *testing.T) {
	for _, c := range []struct {
		rules string
		want  hook
	}{
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", hookOK},
		{"anchor \"com.apple/*\"\n", hookOK},
		{"  anchor \"com.apple/*\" all  \n", hookOK},
		{"No ALTQ support in kernel\nanchor \"com.apple/*\" all\n", hookOK},
		{"pass out quick inet6 all label \"ALTQ\"\nanchor \"com.apple/*\" all\n", hookBypassed}, // a label, no chatter
		{"ALTQ related functions disabled\npass out quick inet6 all label \"No ALTQ support in kernel\"\nanchor \"com.apple/*\" all\n", hookBypassed},
		{"pass out all flags S/SA keep state\nanchor \"com.apple/*\" all\n", hookOK},       // no quick: our block still wins
		{"pass in quick inet6 all\nanchor \"com.apple/*\" all\n", hookOK},                  // inbound only
		{"pass out quick inet proto tcp all\nanchor \"com.apple/*\" all\n", hookOK},        // IPv4 only
		{"anchor \"com.apple/*\" all\npass out quick inet6 all\n", hookOK},                 // after it
		{"pass out quick inet6 all\nanchor \"com.apple/*\" all\n", hookBypassed},           // before it
		{"pass quick all\nanchor \"com.apple/*\" all\n", hookBypassed},                     // both directions
		{"pass out quick on en0 all no state\nanchor \"com.apple/*\" all\n", hookBypassed}, // either family
		{"", hookMissing},
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\n", hookMissing},
		{"anchor \"com.apple/*\" in all\n", hookMissing},
		{"anchor \"com.apple/*\" on en0 all\n", hookMissing},
		{"anchor \"com.apple\" all\n", hookMissing},
		{"anchor \"com.apple/000.thinkpol\" all\n", hookMissing},
		{"pass out all # anchor \"com.apple/*\" all\n", hookMissing},
	} {
		if got := hooked([]byte(c.rules)); got != c.want {
			t.Errorf("%q: %v, want %v", c.rules, got, c.want)
		}
	}
}

// `set skip on` shows only in the interface listing; lo0 and the utun
// are passed by the anchor anyway.
func TestSkipped(t *testing.T) {
	for _, c := range []struct {
		ifaces string
		want   []string
	}{
		{"all\nen0\nlo0\nutun7\n", nil},
		{"all\nen0\nlo0 (skip)\nutun7 (skip)\n", nil},
		{altq + "all\nen0 (skip)\nen1\nlo0 (skip)\n", []string{"en0"}},
		{"en0 (skip)\nen1 (skip)\nbridge0 (skip)\n", []string{"en0", "en1", "bridge0"}},
		{"utun3 (skip)\nutun7 (skip)\n", []string{"utun3"}}, // another utun: another VPN's
		{"  en0   (skip)  \n", []string{"en0"}},
		// Strict on purpose: a skipped name no interface has (`set skip on
		// lo`, a group) counts too; one could come, and macOS's pf doesn't
		// say which names a group covers.
		{"lo (skip)\n", []string{"lo"}},
	} {
		if got := skipped([]byte(c.ifaces), "utun7"); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.ifaces, got, c.want)
		}
	}
}

// The hook evaluates the anchors under com.apple in path order: any that
// sorts before the guard's runs first. The listing is read as any
// wildcard's (childAnchors): com.apple missing lists none, and a line
// that isn't one of its children is an error.
func TestAnchorsBefore(t *testing.T) {
	for _, c := range []struct {
		stdout, stderr string
		want           []string
		ok             bool
	}{
		{"  com.apple/000.thinkpol\n  com.apple/200.AirDrop\n  com.apple/250.ApplicationFirewall\n", altq, nil, true},
		{"", altq, nil, true},
		{"", altq + "Anchor 'com.apple' not found.\n", nil, true},
		{"  com.apple/000.thinkpol\n  com.apple/100.other\n  com.apple/zz\n  com.apple/ALTQ\n", "", nil, true},
		{"  com.apple/0.first\n  com.apple/000.thinkpol\n", "", []string{"com.apple/0.first"}, true},
		{"  com.apple/-ALTQ\n  com.apple/000\n  com.apple/000.thinkpo\n", "", []string{"com.apple/-ALTQ", "com.apple/000", "com.apple/000.thinkpo"}, true},
		{"  com.apple/0 a\n", "", []string{"com.apple/0 a"}, true},
		{"  com.apple/000.thinkpol/0.nested\n", "", nil, false},
		{"0.relative\n", "", nil, false},
		{"  com.apple/0.first\n", "a warning\n", nil, false},
	} {
		got, err := anchorsBefore(pfOutput{stdout: []byte(c.stdout), stderr: []byte(c.stderr)}, nil)
		if !slices.Equal(got, c.want) || (err == nil) != c.ok {
			t.Errorf("%q / %q: %q, %v", c.stdout, c.stderr, got, err)
		}
	}
}

// The fake holds every anchor it lists under com.apple.
func TestTheFakeHoldsTheAnchorsItLists(t *testing.T) {
	f := newFakePF()
	out, err := f.run(context.Background(), nil, "-a", appleAnchor, "-s", "Anchors")
	if err != nil || len(lines(out.stdout)) != len(stockApple) {
		t.Fatalf("%q: %v, want %d anchors", out.stdout, err, len(stockApple))
	}
	for _, l := range lines(out.stdout) {
		if _, err := f.run(context.Background(), nil, "-a", l, "-s", "rules"); err != nil {
			t.Errorf("%s listed but not held: %v", l, err)
		}
	}
}

func TestParseToken(t *testing.T) {
	for _, c := range []struct {
		stdout, stderr string
		want           uint64
	}{
		{"Token : 14715852371098265711\n", altq + "pf enabled\n", 14715852371098265711},
		{"", "pf enabled\nToken : 42\n", 42},
		{"Token: 7", "", 7},
		{"", "pf enabled\n", 0},
		{"Token : 1\nToken : 2\n", "", 0},
		{"Token : 0\n", "", 0},
		{"Token : 99999999999999999999\n", "", 0},
		{"Token : 12abc\n", "", 0},
	} {
		got, err := parseToken(pfOutput{stdout: []byte(c.stdout), stderr: []byte(c.stderr)})
		if c.want == 0 && err == nil || c.want != 0 && (err != nil || got != c.want) {
			t.Errorf("%q/%q: %d, %v; want %d", c.stdout, c.stderr, got, err, c.want)
		}
	}
}

func TestParseEnabled(t *testing.T) {
	for _, c := range []struct {
		info    string
		on, bad bool
	}{
		{"Status: Enabled for 0 days 00:01:02           Debug: Urgent\n\nState Table\n", true, false},
		{"Status: Disabled for 0 days 00:00:00          Debug: Urgent\n", false, false},
		{"Status: Disabled\n", false, false},
		{"Interface Stats for en0\nStatus: Enabled\n", true, false},
		{"", false, true},
		{"Status: Unknown\n", false, true},
		{"Enabled\n", false, true},
	} {
		on, err := parseEnabled([]byte(c.info))
		if on != c.on || (err != nil) != c.bad {
			t.Errorf("%q: %v, %v", c.info, on, err)
		}
	}
}

// References as published OS X transcripts print them.
func TestParseReferences(t *testing.T) {
	listing := []byte(altq + "TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n" +
		"618      socketfilterfw               9813589183660731843   0 days 00:03:31\n" +
		"17013    pfctl                        18446743524308110600  0 days 01:05:50\n")
	refs, understood := parseReferences(pfOutput{stdout: listing})
	want := []pfReference{{618, 9813589183660731843}, {17013, 18446743524308110600}}
	if !understood || !slices.Equal(refs, want) {
		t.Fatalf("%v, %v", refs, understood)
	}
	for _, c := range []struct {
		t    pfToken
		want reference
	}{
		{pfToken{18446743524308110600, 17013}, refOurs},
		{pfToken{18446743524308110600, 17014}, refForeign}, // the value, reused by another enabler
		{pfToken{9813589183660731843, 17013}, refForeign},
		{pfToken{17013, 17013}, refGone}, // a pid isn't a token
		{pfToken{1844674352430811060, 17013}, refGone},
	} {
		if got := referenced(refs, c.t); got != c.want {
			t.Errorf("%v: %v, want %v", c.t, got, c.want)
		}
	}
	if v, ok := byPid(refs, 17013); !ok || v != 18446743524308110600 {
		t.Errorf("byPid: %d, %v", v, ok)
	}
	if _, ok := byPid(append(refs, pfReference{17013, 5}), 17013); ok {
		t.Error("byPid: two references of one pid, one chosen")
	}
	if _, ok := byPid(refs, 1); ok {
		t.Error("byPid: a pid not listed found")
	}
	// A Mac holding none prints answerNoReferences, not the header alone.
	if refs, understood := parseReferences(pfOutput{stdout: []byte("TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n")}); len(refs) != 0 || understood {
		t.Errorf("a header with no reference: %v, %v", refs, understood)
	}
	// A process named ALTQ is a reference, not chatter.
	if refs, understood := parseReferences(pfOutput{stdout: append(listing, "4242     ALTQ                         5000000000000000001   0 days 00:00:01\n"...)}); !understood || len(refs) != 3 || refs[2] != (pfReference{4242, 5000000000000000001}) {
		t.Errorf("a process named ALTQ: %v, %v", refs, understood)
	}
	for _, odd := range []string{"", "token=5 by pfctl(17013)\n", "17013 pfctl\n", "pfctl 17013 5 0 days\n"} {
		if refs, understood := parseReferences(pfOutput{stdout: []byte(odd)}); len(refs) != 0 || understood {
			t.Errorf("%q: %v, %v", odd, refs, understood)
		}
	}
}

func TestParseTable(t *testing.T) {
	got, err := parseTable([]byte(altq + "   2001:db8:d0::/48\n   2001:db8:53::1\n   ::102:304\n   fe80::/10\n\n"))
	want := pfxs("::102:304/128", "2001:db8:53::1/128", "2001:db8:d0::/48", "fe80::/10")
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("%v, %v; want %v", got, err, want)
	}
	for _, bad := range []string{"   !2001:db8::/32\n", "   192.0.2.0/24\n", "   2001:db8::1/32\n", "   fe80::1%en0\n", "   ::ffff:192.0.2.1\n", "   garbage\n"} {
		if got, err := parseTable([]byte(bad)); err == nil {
			t.Errorf("%q: %v", bad, got)
		}
	}
}

func TestParseStateAddrs(t *testing.T) {
	got, err := parseStateAddrs([]byte(altq +
		"ALL tcp 2001:db8:1::10[51000] -> 2001:db8:ab::7[443]       ESTABLISHED:ESTABLISHED\n" +
		"ALL udp 2001:db8:1::10[5353] <- 2001:db8:ab::8[53]       SINGLE:NO_TRAFFIC\n" +
		"en0 tcp 2001:db8:1::10[1] (2001:db8:1::11[2]) -> 2001:db8:ab::9[3]   X\n" +
		"ALL tcp 192.0.2.10:51000 -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED\n" +
		"ALL ipv6-icmp fe80::1%en0[3] -> ff02::1[0]       0:0\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := [][]netip.Addr{
		{ownV6, netip.MustParseAddr("2001:db8:ab::7")},
		{ownV6, netip.MustParseAddr("2001:db8:ab::8")},
		{ownV6, netip.MustParseAddr("2001:db8:1::11"), netip.MustParseAddr("2001:db8:ab::9")},
		{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("ff02::1")},
	}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("line %d: %v, want %v", i, got[i], want[i])
		}
	}
}

// Only a listing whose passes are stateless, with every word, rule for
// rule, is the guard's.
func TestSaneRules(t *testing.T) {
	a, err := fakeLoad(anchorText("utun7", exemptPrefixes(exempt(t)), upstreamTargets(exempt(t))))
	if err != nil {
		t.Fatal(err)
	}
	ports := upstreamTargets(exempt(t))
	if err := saneRules(a.rules, "utun7", ports); err != nil {
		t.Fatalf("the fake's listing: %v", err)
	}
	for name, change := range map[string]func([]string) []string{
		"kept state": func(r []string) []string {
			r[1] = strings.Replace(r[1], "no state", "flags S/SA keep state", 1)
			return r
		},
		"one missing":     func(r []string) []string { return r[1:] },
		"one more":        func(r []string) []string { return append(r, "pass out quick inet6 all no state") },
		"another utun":    func(r []string) []string { r[1] = strings.Replace(r[1], "utun7", "utun8", 1); return r },
		"block not quick": func(r []string) []string { r[len(r)-1] = "block return out inet6 all"; return r },
	} {
		if err := saneRules(change(slices.Clone(a.rules)), "utun7", ports); err == nil {
			t.Errorf("%s: sane", name)
		}
	}
}

// The fake lists an ICMPv6 type by the first name pfctl's icmp6 type
// table has for its number (130-132 have two each), and 143, which has
// none, by its number.
func TestTheFakeNamesICMPv6TypesAsPfctl(t *testing.T) {
	got := fakeExpand("pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state")
	var want []string
	for _, name := range []string{"groupqry", "grouprep", "groupterm", "143"} {
		want = append(want, "pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type "+name+" no state")
	}
	if !slices.Equal(got, want) {
		t.Errorf("listed\n%q\nwant\n%q", got, want)
	}
}

func TestApplyPutsTheGuardInPlace(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e)
	if a := r.pf.anchor(GuardAnchor); len(a.rules) != rulesFor {
		t.Errorf("%d rules: %q", len(a.rules), a.rules)
	}
	// The anchor is loaded before pf comes on.
	if f, en := slices.IndexFunc(r.pf.calls, func(c []string) bool { return slices.Contains(c, "-f") }),
		slices.IndexFunc(r.pf.calls, func(c []string) bool { return slices.Equal(c, []string{"-E"}) }); f < 0 || en < f {
		t.Errorf("load at %d, enable at %d", f, en)
	}
}

// withoutNone is a pfctl that drops `-o none` from its runs: a load then
// goes in with pfctl's default optimizer, which reorders the rules.
type withoutNone struct{ pf pfctl }

func (w withoutNone) run(ctx context.Context, stdin []byte, args ...string) (pfOutput, error) {
	if i := slices.Index(args, "-o"); i >= 0 && i+1 < len(args) && args[i+1] == "none" {
		args = append(args[:i:i], args[i+2:]...)
	}
	return w.pf.run(ctx, stdin, args...)
}

// A load the optimizer reordered is refused: rule 1 is then the
// multicast one, not the one naming an interface.
func TestAnOptimizedLoadIsRefused(t *testing.T) {
	r := newRig(t)
	g := newIPv6Guard(withoutNone{r.pf}, r.store(), time.Hour, ownAddrs)
	const want = `firewall: pf lists the guard's rule 1 as "pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type groupqry no state", without "on"`
	err := g.Apply(context.Background(), exempt(t))
	if err == nil || err.Error() != want {
		t.Fatalf("%v\nwant %q", err, want)
	}
	if r.pf.isOn() {
		t.Error("pf enabled for a refused load")
	}
	// The same load with the optimizer off is the guard, in place.
	if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
}

// Someone else's reference stays theirs: the guard takes its own, and
// leaves theirs when it goes.
func TestTheGuardSharesPfWithOthers(t *testing.T) {
	r := newRig(t)
	theirs := r.pf.takeRef()
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e, theirs)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t, theirs)
	if !r.pf.isOn() {
		t.Error("pf turned off under another enabler")
	}
}

// Applying what is in place only reads it back.
func TestApplyingAgainOnlyReads(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.pf.forget()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	for _, write := range []string{"-f", "-E", "-X", "-F", "-k", "states"} {
		if n := r.pf.ran(write); n != 0 {
			t.Errorf("%s ran %d times", write, n)
		}
	}
	r.whole(t, e)
}

// What changes from outside is put right by the next Apply (and Watch
// sees it, TestWatchSignalsWhenTheGuardBreaks): content, not counts.
func TestApplyRepairsWhatChangedOutside(t *testing.T) {
	edit := func(f func(a *fakeAnchor)) func(r *rig) {
		return func(r *rig) {
			a := r.pf.anchor(GuardAnchor)
			f(a)
			r.pf.setAnchor(GuardAnchor, a)
		}
	}
	for _, c := range []struct {
		name   string
		change func(r *rig)
	}{
		{"an entry added", edit(func(a *fakeAnchor) { a.tables[exemptTable] = append(a.tables[exemptTable], "::/0") })},
		{"an entry replaced", edit(func(a *fakeAnchor) { a.tables[exemptTable][0] = "2000::/3" })},
		{"an entry removed", edit(func(a *fakeAnchor) { a.tables[exemptTable] = a.tables[exemptTable][1:] })},
		{"an upstream's port widened", edit(func(a *fakeAnchor) { a.rules[3] = "pass out quick inet6 proto tcp to 2001:db8:53::1 no state" })},
		{"the block replaced by a pass", edit(func(a *fakeAnchor) { a.rules[len(a.rules)-1] = "pass out quick inet6 all" })},
		{"the tables flushed", edit(func(a *fakeAnchor) { a.tables = map[string][]string{} })},
		{"the anchor flushed", func(r *rig) { r.pf.setAnchor(GuardAnchor, nil) }},
		{"pf disabled", func(r *rig) { r.pf.disable() }},
		{"pf disabled, its references kept", func(r *rig) { r.pf.set(func(f *fakePF) { f.keepRefs = true }); r.pf.disable() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			g := r.guard()
			e := exempt(t)
			if err := g.Apply(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			first := r.pf.references()
			c.change(r)
			if err := g.Apply(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			r.whole(t, e)
			disabled := strings.HasPrefix(c.name, "pf disabled")
			if disabled && (len(r.pf.references()) != 1 || slices.Equal(r.pf.references(), first)) {
				t.Errorf("references %v, want one new one instead of %v", r.pf.references(), first)
			}
			if !disabled && !slices.Equal(r.pf.references(), first) {
				t.Errorf("references %v, want %v kept", r.pf.references(), first)
			}
		})
	}
}

// A new Exempt replaces the tables (narrower too: no `const` to stop the
// reload) and the rules, with the same reference.
func TestApplyingAnotherExemptReplacesIt(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	first := r.pf.references()
	e2 := routetable.Exempt{TUN: "utun9", Direct: set(t, "2001:db8:f0::/44"), Upstreams: aps("[2001:db8:54::1]:5353")}
	if err := g.Apply(context.Background(), e2); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e2)
	a := r.pf.anchor(GuardAnchor)
	if slices.Contains(a.tables[exemptTable], "2001:db8:d0::/48") || slices.ContainsFunc(a.rules, func(r string) bool { return strings.Contains(r, "2001:db8:53::1") }) {
		t.Errorf("the old exempts stayed: %v, %q", a.tables, a.rules)
	}
	if !slices.Contains(a.rules, "pass out quick inet6 proto udp from any to 2001:db8:54::1 port = 5353 no state") {
		t.Errorf("rules %q, want DNS to the upstream's port", a.rules)
	}
	if !slices.Equal(r.pf.references(), first) {
		t.Errorf("references %v, want %v", r.pf.references(), first)
	}
	// Back to the wider set, then narrower again.
	for _, x := range []routetable.Exempt{e, e2} {
		if err := g.Apply(context.Background(), x); err != nil {
			t.Fatal(err)
		}
		r.whole(t, x)
	}
}

// States pf holds would pass without a rule: once the guard is in place,
// those to and from what it doesn't exempt go, the rest stay.
func TestApplyKillsStatesTheGuardRefuses(t *testing.T) {
	r := newRig(t)
	st := func(proto, local, remote string, out bool) fakeState {
		return fakeState{proto, netip.MustParseAddrPort(local), netip.MustParseAddrPort(remote), out}
	}
	foreignOut := st("tcp", "[2001:db8:1::10]:51000", "[2001:db8:ab::7]:443", true)
	foreignIn := st("tcp", "[2001:db8:1::10]:22", "[2001:db8:ab::8]:50000", false)
	direct := st("tcp", "[2001:db8:1::10]:51001", "[2001:db8:d0::5]:443", true)
	upstreamDNS := st("udp", "[2001:db8:1::10]:51002", "[2001:db8:53::1]:53", true)
	upstreamWeb := st("tcp", "[2001:db8:1::10]:51005", "[2001:db8:53::1]:443", true) // not DNS: -k can't tell them apart
	link := st("udp", "[2001:db8:1::10]:5353", "[ff02::fb]:5353", true)
	v4 := st("tcp", "192.0.2.10:51003", "198.51.100.200:443", true)
	loop := st("tcp", "[::1]:51004", "[::1]:8080", true)
	r.pf.states = []fakeState{foreignOut, foreignIn, direct, upstreamDNS, upstreamWeb, link, v4, loop}
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if got, want := r.pf.stateList(), []fakeState{direct, link, v4, loop}; !slices.Equal(got, want) {
		t.Errorf("states %v, want %v", got, want)
	}
	// A state made while pf was off goes when the guard turns it back on.
	r.pf.disable()
	r.pf.set(func(f *fakePF) { f.states = append(f.states, foreignOut) })
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.pf.stateList(), foreignOut) {
		t.Error("a state made while pf was off survived")
	}
	// Re-applying what is in place leaves states alone.
	r.pf.forget()
	if err := g.Apply(context.Background(), exempt(t)); err != nil || r.pf.ran("-k") != 0 {
		t.Errorf("re-apply: %v, %d kills", err, r.pf.ran("-k"))
	}
	// A kill that fails fails the Apply, and the retry kills.
	r.pf.set(func(f *fakePF) { f.states = append(f.states, foreignIn) })
	r.pf.setAnchor(GuardAnchor, nil)
	r.pf.failOn("-k", errFake)
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied with states left")
	}
	r.pf.failOn("-k", nil)
	if err := g.Apply(context.Background(), exempt(t)); err != nil || slices.Contains(r.pf.stateList(), foreignIn) {
		t.Errorf("retry: %v, states %v", err, r.pf.stateList())
	}
}

// States made while the guard failed (a quick pass above the hook keeps
// state by default) go on the next success, even with the anchor intact.
func TestStatesMadeWhileTheGuardFailedAreKilled(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	foreign := fakeState{"tcp", netip.MustParseAddrPort("[2001:db8:1::10]:51000"), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
	r.pf.set(func(f *fakePF) {
		f.main = append([]string{"pass out quick inet6 all"}, stockMain...)
		f.states = append(f.states, foreign)
	})
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied under a quick pass")
	}
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	r.pf.forget()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if r.pf.ran("-f") != 0 {
		t.Error("reloaded an intact anchor")
	}
	if slices.Contains(r.pf.stateList(), foreign) {
		t.Error("a state made under the quick pass survived")
	}
}

// No bypass is known, not unknown: a retry after a failure that let
// nothing past the anchor (pf's status unreadable a while) doesn't kill
// again. A main ruleset without the hook lets anything past, so the
// Apply after the hook is back kills.
func TestOnlyAFailureThatLetIPv6PastKillsAgain(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	port := uint16(51000)
	state := func() fakeState {
		port++
		s := fakeState{"tcp", netip.AddrPortFrom(ownV6, port), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
		r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
		return s
	}
	a := state()
	r.pf.failOn("info", errFake)
	if err := g.Apply(ctx, exempt(t)); err == nil {
		t.Fatal("applied with pf's status unreadable")
	}
	r.pf.failOn("info", nil)
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.pf.stateList(), a) {
		t.Error("the retry after a failure that let nothing past killed again")
	}
	b := state()
	r.pf.set(func(f *fakePF) { f.main = stockMain[:1] })
	if err := g.Apply(ctx, exempt(t)); err == nil {
		t.Fatal("applied without the hook")
	}
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.pf.stateList(), b) {
		t.Error("a state made while the hook was missing survived")
	}
}

// What the poll sees counts as an Apply's check would: a hook missing for
// one poll, a bypass the poll saw, or pf off, kills at the Apply its
// signal brings, even when it is gone by then (pf back on by someone
// else's `pfctl -e`). pf off counts under a persistent bypass too, the
// guard failing and its kill done under that bypass. An unchanged guard's
// polls don't kill.
func TestAChangeOnlyThePollSawKills(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	port := uint16(51000)
	state := func() fakeState {
		port++
		s := fakeState{"tcp", netip.AddrPortFrom(ownV6, port), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
		r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
		return s
	}
	a := state()
	if g.broken(ctx) {
		t.Fatal("the poll broke an intact guard")
	}
	if err := g.Apply(ctx, exempt(t)); err != nil || !slices.Contains(r.pf.stateList(), a) {
		t.Fatalf("after a quiet poll: %v, killed %v", err, !slices.Contains(r.pf.stateList(), a))
	}
	for _, c := range []struct {
		what string
		main []string
	}{
		{"a hook missing", stockMain[:1]},
		{"a quick pass above the hook", append([]string{"pass out quick inet6 all"}, stockMain...)},
	} {
		s := state()
		r.pf.set(func(f *fakePF) { f.main = c.main })
		if !g.broken(ctx) {
			t.Fatalf("the poll missed %s", c.what)
		}
		r.pf.set(func(f *fakePF) { f.main = stockMain })
		if err := g.Apply(ctx, exempt(t)); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(r.pf.stateList(), s) {
			t.Errorf("a state made while the poll saw %s survived", c.what)
		}
	}
	s := state()
	r.pf.disable()
	if !g.broken(ctx) {
		t.Fatal("the poll missed pf off")
	}
	r.pf.set(func(f *fakePF) { f.plainOn = true })
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.pf.stateList(), s) {
		t.Error("a state made while the poll saw pf off survived")
	}
	r.pf.set(func(f *fakePF) { f.main = append([]string{"pass out quick inet6 all"}, stockMain...) })
	notEnforced(t, g.Apply(ctx, exempt(t)), "`pass ... quick` rule above")
	s = state()
	r.pf.disable()
	if !g.broken(ctx) {
		t.Fatal("the poll missed pf off under a bypass")
	}
	r.pf.set(func(f *fakePF) { f.plainOn = true })
	notEnforced(t, g.Apply(ctx, exempt(t)), "`pass ... quick` rule above")
	if slices.Contains(r.pf.stateList(), s) {
		t.Error("a state made while the poll saw pf off under a bypass survived")
	}
}

// A kill that fails fails the Apply, and the bypass it checked is told
// too.
func TestAFailedKillStillTellsTheBypass(t *testing.T) {
	r := newRig(t)
	r.pf.main = append([]string{"pass out quick inet6 all"}, stockMain...)
	r.pf.states = []fakeState{{"tcp", netip.AddrPortFrom(ownV6, 51000), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}}
	r.pf.failOn("-k", errFake)
	err := r.guard().Apply(context.Background(), exempt(t))
	notEnforced(t, err, "-k", "`pass ... quick` rule above")
}

// A check that couldn't read pf kills, but can't vouch for what it killed
// under: the next one that reads pf kills again, though it finds what an
// empty check would (a main ruleset of the hook alone, no bypass).
func TestAStateMadeWhilePfWasUnreadableIsKilled(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.pf.main = stockMain[1:]
	r.pf.failOn("Interfaces", errFake)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err == nil {
		t.Fatal("applied with pf unreadable")
	}
	s := fakeState{"tcp", netip.AddrPortFrom(ownV6, 51000), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
	r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
	r.pf.failOn("Interfaces", nil)
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.pf.stateList(), s) {
		t.Error("a state made while pf was unreadable survived")
	}
}

func TestCloseRemovesTheGuardAndItsReference(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
	if r.pf.isOn() {
		t.Error("pf left on")
	}
	if err := g.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := g.Apply(context.Background(), exempt(t)); !errors.Is(err, errClosed) {
		t.Errorf("Apply after Close: %v", err)
	}
	if _, err := g.Watch(context.Background()); !errors.Is(err, errClosed) {
		t.Errorf("Watch after Close: %v", err)
	}
}

// A crash leaves the anchor and the reference (fail closed); a fresh
// guard's Close, which routetable.Clear calls, removes both.
func TestAFreshGuardClearsACrashedRun(t *testing.T) {
	r := newRig(t)
	theirs := r.pf.takeRef()
	if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	// The process dies: nothing of the guard runs.
	r.whole(t, exempt(t), theirs)
	if err := r.guard().Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t, theirs)
}

// A fresh guard with nothing left to clear: the anchor doesn't exist,
// whether pfctl's flush of it succeeds or answers `Invalid argument`.
func TestAFreshGuardCloseOnACleanHost(t *testing.T) {
	for _, ok := range []bool{false, true} {
		r := newRig(t)
		r.pf.flushMissingOK = ok
		if err := r.guard().Close(); err != nil {
			t.Fatalf("flush of a missing anchor succeeds %v: %v", ok, err)
		}
		r.gone(t)
		if n := r.pf.ran("-X") + r.pf.ran("-E"); n != 0 {
			t.Errorf("references touched %d times", n)
		}
	}
}

// A flush that fails over an anchor that still lists its rules or its
// table fails the Close: the listing after it decides, not what -F
// answered.
func TestAFlushThatFailsIsNoEmptyAnchor(t *testing.T) {
	for _, key := range []string{"-F rules", "-F Tables"} {
		r := newRig(t)
		g := r.guard()
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		r.pf.failOn(key, errors.New("DIOCBEGINRULES: Invalid argument"))
		if err := g.Close(); err == nil {
			t.Fatalf("%s: closed with the anchor in place", key)
		}
		r.pf.failOn(key, nil)
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
	}
}

// A guard that applies after a crash takes the crashed run's reference
// over instead of taking a second one.
func TestApplyTakesACrashedRunsReferenceOver(t *testing.T) {
	r := newRig(t)
	if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	crashed := r.pf.references()
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if refs := r.pf.references(); !slices.Equal(refs, crashed) {
		t.Errorf("references %v, want the crashed run's %v", refs, crashed)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
	if r.pf.isOn() {
		t.Error("pf left on")
	}
}

// A token record that isn't one of ours (a symlink, even to a record of
// this boot naming a live reference; a fifo; garbage) is stale: it
// releases nothing, and it is removed, by a fresh guard's Close and by an
// Apply, which records its own reference instead.
func TestAStaleTokenRecordIsRemovedAndReleasesNothing(t *testing.T) {
	stale := map[string]func(t *testing.T, r *rig, theirs pfToken){
		"a symlink": func(t *testing.T, r *rig, theirs pfToken) {
			target := filepath.Join(r.dir, "elsewhere")
			data := "boot " + thisBoot + "\ntoken " + strconv.FormatUint(theirs.value, 10) + " pid " + strconv.Itoa(theirs.pid) + "\n"
			if err := os.WriteFile(target, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(r.dir, tokenRecord)); err != nil {
				t.Fatal(err)
			}
		},
		"a fifo": func(t *testing.T, r *rig, _ pfToken) {
			if err := unix.Mkfifo(filepath.Join(r.dir, tokenRecord), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"garbage": func(t *testing.T, r *rig, _ pfToken) { r.writeRecord(t, "\x00\x01 not a record\n") },
	}
	for name, plant := range stale {
		for _, how := range []string{"Close", "Apply"} {
			t.Run(name+", "+how, func(t *testing.T) {
				r := newRig(t)
				theirs := r.pf.takeRef()
				plant(t, r, theirs)
				g := r.guard()
				if how == "Apply" {
					if err := g.Apply(context.Background(), exempt(t)); err != nil {
						t.Fatal(err)
					}
					if fi, err := os.Lstat(filepath.Join(r.dir, tokenRecord)); err != nil || !fi.Mode().IsRegular() {
						t.Fatalf("the record after Apply: %v, %v; want a regular file", fi, err)
					}
					r.whole(t, exempt(t), theirs)
				}
				if err := g.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(r.dir, tokenRecord)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the stale record stays: %v", err)
				}
				if refs := r.pf.references(); !slices.Equal(refs, []pfToken{theirs}) {
					t.Errorf("references %v, want theirs alone, %v", refs, theirs)
				}
				if _, err := os.Stat(filepath.Join(r.dir, "elsewhere")); name == "a symlink" && err != nil {
					t.Errorf("the symlink's target: %v", err)
				}
			})
		}
	}
}

// A record of an earlier boot holds nothing: its token value may well be
// someone's now.
func TestARecordOfAnEarlierBootReleasesNothing(t *testing.T) {
	r := newRig(t)
	if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	refs := r.pf.references() // as if another enabler holds the same token and pid this boot
	r.boot = "6F1C0D2E-0000-4000-8000-000000000002"
	r.pf.setAnchor(GuardAnchor, nil) // a reboot took it
	if err := r.guard().Close(); err != nil {
		t.Fatal(err)
	}
	if n := r.pf.ran("-X"); n != 0 {
		t.Errorf("pfctl -X ran %d times", n)
	}
	r.gone(t, refs...)
}

// Never release a reference that isn't the guard's: one pf no longer
// lists, or one listed under the same value but taken by another process.
func TestNeverReleasesAReferenceThatIsntOurs(t *testing.T) {
	t.Run("reused", func(t *testing.T) {
		r := newRig(t)
		if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		ours := r.pf.references()[0]
		r.pf.disable() // pfctl -d drops it ...
		r.pf.set(func(f *fakePF) { f.reuse = ours.value })
		theirs := r.pf.takeRefVia(t) // ... and another program's -E gets the same value
		if theirs.value != ours.value || theirs.pid == ours.pid {
			t.Fatalf("setup: %v, %v", theirs, ours)
		}
		if err := r.guard().Close(); err != nil {
			t.Fatal(err)
		}
		if n := r.pf.ran("-X"); n != 0 {
			t.Errorf("pfctl -X ran %d times", n)
		}
		r.gone(t, theirs)
	})
	t.Run("gone", func(t *testing.T) {
		r := newRig(t)
		if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		r.pf.disable()
		if err := r.guard().Close(); err != nil {
			t.Fatal(err)
		}
		if n := r.pf.ran("-X"); n != 0 {
			t.Errorf("pfctl -X ran %d times", n)
		}
		r.gone(t)
	})
	t.Run("a broken record", func(t *testing.T) {
		r := newRig(t)
		theirs := r.pf.takeRef()
		r.writeRecord(t, "boot "+thisBoot+"\ntoken "+strconv.FormatUint(theirs.value, 10)+"\n") // no pid: not ours to judge
		if err := r.guard().Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t, theirs)
	})
}

// takeRefVia is another program's -E through the fake's own path.
func (f *fakePF) takeRefVia(t *testing.T) pfToken {
	t.Helper()
	out, err := f.run(context.Background(), nil, "-E")
	if err != nil {
		t.Fatal(err)
	}
	v, err := parseToken(out)
	if err != nil {
		t.Fatal(err)
	}
	return pfToken{value: v, pid: out.pid}
}

// A quick pass above the hook ends evaluation before the anchor: the
// guard isn't enforced (an ordinary failure, retried), though in place
// for whatever the pass doesn't match, and is again once it is gone.
func TestAQuickPassAboveTheHookIsNotEnforced(t *testing.T) {
	r := newRig(t)
	r.pf.main = []string{"pass out quick inet6 all no state", `anchor "com.apple/*" all`}
	g := r.guard()
	err := g.Apply(context.Background(), exempt(t))
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want an ordinary failure", err)
	}
	r.whole(t, exempt(t))
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
}

// pf evaluates no rule for an interface `set skip on` names, the guard's
// anchor's neither, and `-s rules` doesn't show it: the guard isn't
// enforced while pf skips one it doesn't pass anyway (an ordinary
// failure, retried), though it is in place for the others; and is again
// once pf skips only lo0 and the utun.
//
// While the same bypass lasts, the retries leave states alone (what it
// lets through needs none, and the anchor lets nothing outgoing make
// one); a change to the bypasses (another one coming, then going) kills
// them, and so does the Apply after the last one ends.
func TestASkippedInterfaceIsNotEnforced(t *testing.T) {
	r := newRig(t)
	r.pf.skip = []string{"en0", "lo0"}
	g := r.guard()
	apply := func(want bool, when string) {
		t.Helper()
		err := g.Apply(context.Background(), exempt(t))
		if want && err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if !want && (err == nil || errors.Is(err, routetable.ErrGuardUnsupported) || !strings.Contains(err.Error(), "en0")) {
			t.Fatalf("%s: %v, want an ordinary failure naming en0", when, err)
		}
	}
	state := func(port uint16) fakeState {
		s := fakeState{"tcp", netip.MustParseAddrPort("[2001:db8:1::10]:51000"), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
		s.local = netip.AddrPortFrom(s.local.Addr(), port)
		r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
		return s
	}
	alive := func(s fakeState) bool { return slices.Contains(r.pf.stateList(), s) }

	apply(false, "en0 skipped")
	r.whole(t, exempt(t)) // en1 is guarded meanwhile
	a := state(51001)
	apply(false, "a retry")
	apply(false, "another retry")
	if !alive(a) {
		t.Error("the retries under the same bypass killed states")
	}
	// Another bypass comes, and goes while the skip lasts.
	r.pf.setAnchor("com.apple/0.before", &fakeAnchor{})
	apply(false, "an anchor before ours too")
	b := state(51002)
	r.pf.set(func(f *fakePF) { delete(f.anchors, "com.apple/0.before") })
	apply(false, "the anchor gone, the skip still there")
	if alive(b) {
		t.Error("a state made while the earlier anchor was there survived it")
	}
	c := state(51003)
	r.pf.set(func(f *fakePF) { f.skip = []string{"lo0", "utun7"} })
	apply(true, "the skip gone")
	r.whole(t, exempt(t))
	if alive(c) {
		t.Error("a state made while en0 was skipped survived")
	}
}

// An anchor under com.apple whose name sorts before the guard's runs
// first, and a quick pass in it ends evaluation there: the guard isn't
// enforced while one is there. One that sorts after it (Apple's own) runs
// after the guard's block.
func TestAnAnchorBeforeOursIsNotEnforced(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	r.pf.setAnchor("com.apple/100.after", &fakeAnchor{rules: []string{"pass out quick inet6 all"}})
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.setAnchor("com.apple/0.before", &fakeAnchor{rules: []string{"pass out quick inet6 all"}})
	err := g.Apply(context.Background(), exempt(t))
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) || !strings.Contains(err.Error(), "com.apple/0.before") {
		t.Fatalf("%v, want an ordinary failure naming the anchor", err)
	}
	r.pf.set(func(f *fakePF) { delete(f.anchors, "com.apple/0.before") })
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
	// A listing pf refuses tells nothing: no anchor before ours isn't
	// what it says.
	r.pf.failOn("Anchors", errors.New("DIOCGETRULESETS: Invalid argument"))
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Error("enforced although pf refused to list the anchors")
	}
}

// A pfctl failure is an ordinary, retried failure, never unsupported; the
// retry finishes the job without a second reference.
func TestPfctlFailuresAreRetried(t *testing.T) {
	for _, key := range []string{"rules", "-f", "show", "info", "-E", "states", "Interfaces", "Anchors"} {
		t.Run(key, func(t *testing.T) {
			r := newRig(t)
			r.pf.states = []fakeState{{"tcp", netip.MustParseAddrPort("[2001:db8:1::10]:1"), netip.MustParseAddrPort("[2001:db8:ab::7]:2"), true}}
			g := r.guard()
			e := exempt(t)
			r.pf.failOn(key, errFake)
			err := g.Apply(context.Background(), e)
			if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
				t.Fatalf("%v, want an ordinary failure", err)
			}
			if !slices.Contains([]string{"-E", "states", "Interfaces", "Anchors"}, key) && r.pf.isOn() {
				t.Error("pf enabled without the guard in place")
			}
			r.pf.failOn(key, nil)
			if err := g.Apply(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			r.whole(t, e)
			if len(r.pf.stateList()) != 0 {
				t.Errorf("states left: %v", r.pf.stateList())
			}
		})
	}
}

// A failed load leaves the guard that was there: pf's load is one
// transaction.
func TestAFailedReloadKeepsTheOldGuard(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.pf.failOn("-f", errFake)
	e2 := e
	e2.Direct = set(t, "2001:db8:f0::/44")
	if err := g.Apply(context.Background(), e2); err == nil {
		t.Fatal("applied")
	}
	r.whole(t, e)
	r.pf.failOn("-f", nil)
	if err := g.Apply(context.Background(), e2); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e2)
}

// A first load pf holds other than as loaded fails the Apply, and stays
// in pf, not flushed (its rules still end in the block). The guard takes
// no reference for it: pf stays off, or on with only another enabler's
// references, which then enforce it.
func TestALoadPfDoesntHoldFails(t *testing.T) {
	for name, hook := range map[string]func(a *fakeAnchor){
		"an entry dropped": func(a *fakeAnchor) { a.tables[exemptTable] = a.tables[exemptTable][1:] },
		"a pass with state": func(a *fakeAnchor) {
			a.rules[0] = strings.Replace(a.rules[0], "no state", "keep state", 1)
		},
		"reordered": func(a *fakeAnchor) { a.rules = reorderLikeBasic(a.rules) },
	} {
		for _, othersOn := range []bool{false, true} {
			r := newRig(t)
			var theirs []pfToken
			if othersOn {
				theirs = append(theirs, r.pf.takeRef())
			}
			r.pf.loadHook = hook
			if err := r.guard().Apply(context.Background(), exempt(t)); err == nil {
				t.Errorf("%s, others on %v: applied", name, othersOn)
			}
			if a := r.pf.anchor(GuardAnchor); len(a.rules) != rulesFor || a.rules[len(a.rules)-1] != "block return out quick inet6 all" {
				t.Errorf("%s, others on %v: rules %q, want the refused load's", name, othersOn, a.rules)
			}
			if r.pf.isOn() != othersOn || !slices.Equal(r.pf.references(), theirs) {
				t.Errorf("%s, others on %v: pf on %v with references %v, want exactly %v", name, othersOn, r.pf.isOn(), r.pf.references(), theirs)
			}
		}
	}
}

// A reload pf took but the guard refuses on reading it back stays in pf,
// not flushed, and pf goes on enforcing it on the guard's reference.
func TestARefusedReloadStaysInPlace(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	before := r.pf.references()
	r.pf.set(func(f *fakePF) { f.loadHook = func(a *fakeAnchor) { a.rules = reorderLikeBasic(a.rules) } })
	e2 := e
	e2.Direct = set(t, "2001:db8:f0::/44")
	if err := g.Apply(context.Background(), e2); err == nil {
		t.Fatal("applied")
	}
	loaded, err := fakeLoad(anchorText(e2.TUN, exemptPrefixes(e2), upstreamTargets(e2)))
	if err != nil {
		t.Fatal(err)
	}
	a := r.pf.anchor(GuardAnchor)
	if !slices.Equal(a.rules, reorderLikeBasic(loaded.rules)) || !slices.Equal(tableOf(a, exemptTable), exemptPrefixes(e2)) {
		t.Errorf("anchor %+v, want the refused load's", a)
	}
	if !r.pf.isOn() || !slices.Equal(r.pf.references(), before) {
		t.Errorf("pf on %v, references %v, want on with %v", r.pf.isOn(), r.pf.references(), before)
	}
}

// routesOnly is a route table's configurator that takes every Apply and
// can't watch: all the guard's warn needs of it.
type routesOnly struct{}

func (routesOnly) Apply(context.Context, netcfg.Config) error { return nil }
func (routesOnly) DefaultRoute(context.Context, netcfg.Family) (netcfg.Route, error) {
	return netcfg.Route{}, netcfg.ErrNoDefaultRoute
}
func (routesOnly) Watch(context.Context) (<-chan struct{}, error) { return nil, errors.ErrUnsupported }
func (routesOnly) Survey(context.Context) (netcfg.Survey, error)  { return netcfg.Survey{}, nil }
func (routesOnly) Close() error                                   { return nil }

// logSink is a log a test reads while the route table's watcher writes.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The route table's warn of a load the guard refuses quotes the rule as
// pf listed it, the shape that tells why, with the addresses redacted:
// here an upstream's DNS rule listed with state.
func TestTheWarnOfARefusedLoadQuotesTheRuleWithoutItsAddresses(t *testing.T) {
	r := newRig(t)
	r.pf.loadHook = func(a *fakeAnchor) {
		for i, l := range a.rules {
			if strings.Contains(l, "port = 53") {
				a.rules[i] = strings.Replace(l, "no state", "keep state", 1)
			}
		}
	}
	var log logSink
	e := routetable.OpenWithGuard(routesOnly{}, r.guard(), slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer func() { _ = e.Close() }()
	w := routetable.Want{TUN: "utun7", Direct: set(t, "2001:db8:d0::/48"), Upstreams: aps("[2001:db8:53::1]:53")}
	if err := e.Enforce(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	const want = `level=WARN msg="route table: applying the leak guard failed, retrying" in=5s ` +
		`err="firewall: pf lists the guard's rule 4 as \"pass out quick inet6 proto tcp from any to <addr> port = 53 keep state\", not stateless"` + "\n"
	got := log.String()
	if !strings.HasSuffix(got, want) || strings.Count(got, "level=WARN") != 1 {
		t.Errorf("logged\n%s\nwant one line ending\n%s", got, want)
	}
	if strings.Contains(got, "2001:db8") {
		t.Errorf("an address in the log: %s", got)
	}
}

// `pfctl -E` that prints no token took a reference all the same: it is
// found by the pfctl's pid and recorded; until it is, the record names the
// pid, Apply fails, no second reference is taken, and Close can't finish.
func TestAnUnreadableTokenIsNotTakenTwice(t *testing.T) {
	t.Run("found by pid", func(t *testing.T) {
		r := newRig(t)
		r.pf.noToken = true
		g := r.guard()
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		r.whole(t, exempt(t))
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
		if r.pf.isOn() {
			t.Error("pf left on")
		}
	})
	t.Run("not found yet", func(t *testing.T) {
		r := newRig(t)
		r.pf.noToken, r.pf.oddReferences = true, true
		g := r.guard()
		for range 2 {
			err := g.Apply(context.Background(), exempt(t))
			if !errors.Is(err, errUnreadToken) {
				t.Fatalf("%v, want the unread token", err)
			}
			if !errors.Is(err, errUnreadReferences) || strings.Count(err.Error(), errUnreadToken.Error()) != 1 {
				t.Errorf("%v: want why pf's listing didn't name it, the token told once", err)
			}
		}
		refs := r.pf.references()
		if len(refs) != 1 {
			t.Fatalf("references %v, want the one", refs)
		}
		if rec := r.record(t); !strings.Contains(rec, "\ntoken unknown pid "+strconv.Itoa(refs[0].pid)+"\n") {
			t.Errorf("record %q", rec)
		}
		if err := g.Close(); err == nil {
			t.Fatal("closed with the reference unknown")
		}
		if !slices.Equal(r.pf.references(), refs) || r.record(t) == "" {
			t.Error("the reference or its record went")
		}
		r.pf.set(func(f *fakePF) { f.oddReferences = false })
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		r.whole(t, exempt(t))
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
	})
	t.Run("a crashed run's", func(t *testing.T) {
		r := newRig(t)
		r.pf.noToken, r.pf.oddReferences = true, true
		if err := r.guard().Apply(context.Background(), exempt(t)); !errors.Is(err, errUnreadToken) {
			t.Fatalf("%v, want the unread token", err)
		}
		r.pf.set(func(f *fakePF) { f.oddReferences = false })
		if err := r.guard().Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
	})
	t.Run("gone meanwhile", func(t *testing.T) {
		r := newRig(t)
		r.pf.noToken, r.pf.oddReferences = true, true
		g := r.guard()
		if err := g.Apply(context.Background(), exempt(t)); !errors.Is(err, errUnreadToken) {
			t.Fatalf("%v, want the unread token", err)
		}
		r.pf.disable()
		r.pf.set(func(f *fakePF) { f.oddReferences, f.noToken = false, false })
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		r.whole(t, exempt(t))
	})
	t.Run("the listing failed", func(t *testing.T) {
		r := newRig(t)
		r.pf.noToken = true
		r.pf.failOn("References", errFake)
		err := r.guard().Apply(context.Background(), exempt(t))
		if !errors.Is(err, errUnreadToken) || !errors.Is(err, errFake) {
			t.Fatalf("%v, want the unread token and why the listing failed", err)
		}
	})
}

// unreadTokenRig is a guard whose pf states the test makes one by one,
// each a state the guard refuses.
func unreadTokenRig(t *testing.T) (*rig, *IPv6Guard, func() fakeState) {
	r := newRig(t)
	port := uint16(51000)
	return r, r.guard(), func() fakeState {
		port++
		s := fakeState{"tcp", netip.AddrPortFrom(ownV6, port), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
		r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
		return s
	}
}

func wantUnreadToken(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errUnreadToken) {
		t.Fatalf("%v, want the unread token", err)
	}
}

// pf turned off under the guard: the Apply that turns it back on kills
// what pf passed meanwhile though the new token can't be read, and tells
// the token after. Its retries, the token still unread, carry on too: one
// that sees nothing change doesn't kill again, one that sees a bypass
// tells it with the token and kills.
func TestAnUnreadTokenStillKills(t *testing.T) {
	ctx := context.Background()
	r, g, state := unreadTokenRig(t)
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.disable()
	a := state()
	r.pf.set(func(f *fakePF) { f.noToken, f.oddReferences = true, true })
	wantUnreadToken(t, g.Apply(ctx, exempt(t)))
	if !r.pf.isOn() {
		t.Fatal("pf left off")
	}
	if slices.Contains(r.pf.stateList(), a) {
		t.Error("the Apply with the token unread left a state pf passed while off")
	}
	b := state()
	wantUnreadToken(t, g.Apply(ctx, exempt(t)))
	if !slices.Contains(r.pf.stateList(), b) {
		t.Error("a retry that saw nothing change killed again")
	}
	c := state()
	r.pf.set(func(f *fakePF) { f.main = append([]string{"pass out quick inet6 all"}, stockMain...) })
	err := g.Apply(ctx, exempt(t))
	wantUnreadToken(t, err)
	notEnforced(t, err, "`pass ... quick` rule above")
	if slices.Contains(r.pf.stateList(), c) {
		t.Error("a retry that saw a bypass appear left a state")
	}
}

// With pf off and the guard's reference known by its pid only, the
// Apply stops at the token: a check and a kill then would vouch for
// states pf goes on passing. Once pf is on again (someone's `pfctl -e`),
// the next Apply kills what pf passed while off, before that Apply and
// after it, though the token is still unread.
func TestAnUnreadTokenWithPfOffStopsTheApply(t *testing.T) {
	ctx := context.Background()
	r, g, state := unreadTokenRig(t)
	r.pf.set(func(f *fakePF) { f.keepRefs, f.noToken, f.oddReferences = true, true, true })
	wantUnreadToken(t, g.Apply(ctx, exempt(t)))
	r.pf.disable()
	a := state()
	wantUnreadToken(t, g.Apply(ctx, exempt(t)))
	if refs := r.pf.references(); len(refs) != 1 {
		t.Fatalf("references %v: a second taken with the guard's unknown", refs)
	}
	b := state()
	r.pf.set(func(f *fakePF) { f.forcedOff, f.plainOn = false, true })
	wantUnreadToken(t, g.Apply(ctx, exempt(t)))
	for _, s := range []fakeState{a, b} {
		if slices.Contains(r.pf.stateList(), s) {
			t.Errorf("state %v, made while pf was off, survived", s)
		}
	}
}

// A reference known by its pid only whose record failed to be written
// is recorded by the next Apply, the token still unread.
func TestAnUnreadTokenIsRecordedOnTheRetry(t *testing.T) {
	r := newRig(t)
	r.pf.noToken, r.pf.oddReferences = true, true
	g := r.guard()
	if err := os.Chmod(r.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied without a record")
	}
	if err := os.Chmod(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantUnreadToken(t, g.Apply(context.Background(), exempt(t)))
	refs := r.pf.references()
	if len(refs) != 1 {
		t.Fatalf("references %v, want the one", refs)
	}
	if rec := r.record(t); !strings.Contains(rec, "\ntoken unknown pid "+strconv.Itoa(refs[0].pid)+"\n") {
		t.Errorf("record %q", rec)
	}
}

// A Close that fails keeps what it couldn't remove, record included, and
// can be tried again.
func TestAFailedCloseCanBeRetried(t *testing.T) {
	for _, key := range []string{"-F", "Tables", "References", "-X"} {
		t.Run(key, func(t *testing.T) {
			r := newRig(t)
			g := r.guard()
			if err := g.Apply(context.Background(), exempt(t)); err != nil {
				t.Fatal(err)
			}
			refs := r.pf.references()
			r.pf.failOn(key, errFake)
			if err := g.Close(); err == nil {
				t.Fatal("closed")
			}
			if !slices.Equal(r.pf.references(), refs) || r.record(t) == "" {
				t.Errorf("reference %v or its record gone after a failed Close", r.pf.references())
			}
			r.pf.failOn(key, nil)
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			r.gone(t)
		})
	}
}

// The guard's reference is never left out of the record: a failed write
// is retried by the next Apply, and Close releases it either way.
func TestTheRecordIsWrittenOnTheRetry(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := os.Chmod(r.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied without a record")
	}
	if err := os.Chmod(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
}

func TestWatchSignalsWhenTheGuardBreaks(t *testing.T) {
	r := newRig(t)
	g := newIPv6Guard(r.pf, r.store(), 10*time.Millisecond, ownAddrs)
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := g.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	quiet := func() {
		t.Helper()
		select {
		case <-ch:
			t.Fatal("signalled for a whole guard")
		case <-time.After(100 * time.Millisecond):
		}
	}
	signalled := func(what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no signal", what)
		}
	}
	apply := func() {
		t.Helper()
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		for len(ch) > 0 { // a poll that ran before the Apply
			<-ch
		}
	}
	// Nothing applied yet: nothing to say.
	quiet()
	// A failed Apply is due a retry.
	r.pf.failOn("-f", errFake)
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied")
	}
	signalled("a failed load")
	r.pf.failOn("-f", nil)
	apply()
	quiet()
	for _, c := range []struct {
		what   string
		change func()
	}{
		{"an entry added", func() {
			a := r.pf.anchor(GuardAnchor)
			a.tables[exemptTable] = append(a.tables[exemptTable], "::/0")
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"a rule replaced", func() {
			a := r.pf.anchor(GuardAnchor)
			a.rules[len(a.rules)-1] = "pass out quick inet6 all"
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"pf disabled", r.pf.disable},
		{"the hook gone", func() { r.pf.set(func(f *fakePF) { f.main = nil }) }},
		{"a quick pass above the hook", func() {
			r.pf.set(func(f *fakePF) { f.main = append([]string{"pass out quick all"}, stockMain...) })
		}},
		{"an interface skipped", func() { r.pf.set(func(f *fakePF) { f.skip = []string{"en0"} }) }},
		{"an anchor before the guard's", func() { r.pf.setAnchor("com.apple/0.before", &fakeAnchor{}) }},
	} {
		c.change()
		signalled(c.what)
		r.pf.set(func(f *fakePF) {
			f.main, f.skip = stockMain, nil
			delete(f.anchors, "com.apple/0.before")
		})
		apply()
		quiet()
	}
	cancel()
	for range ch {
	}
}

// pfctl's stderr past what an error quotes is cut at a word, so an
// address the limit falls inside goes whole, and nothing of it escapes
// the redaction.
func TestDetailNeverCutsThroughAnAddress(t *testing.T) {
	head := strings.Repeat("x", detailMax-7) + " " // the limit falls in "2001:d|b8:..."
	got := path.RedactError(errors.New(detail([]byte(head + "2001:db8:53::1 unknown\n"))))
	if strings.Contains(got, "2001") || !strings.HasSuffix(got, strings.TrimSpace(head)+"...") {
		t.Errorf("detail %q, want it cut before the address", got)
	}
}

// A syntax error pfctl reports keeps the line it names through the
// redaction of addresses, and the addresses still go.
func TestPfctlsInputLineSurvivesRedaction(t *testing.T) {
	err := fmt.Errorf("firewall: pfctl -a %s -f -: exit status 1%s", GuardAnchor,
		detail([]byte(altq+"stdin:5: syntax error\nstdin:7: host 2001:db8:53::1 port 53 unknown\n")))
	const want = "firewall: pfctl -a com.apple/000.thinkpol -f -: exit status 1: stdin line 5: syntax error; stdin line 7: host <addr> port 53 unknown"
	if got := path.RedactError(err); got != want {
		t.Errorf("redacted\n%s\nwant\n%s", got, want)
	}
}

// pfctl runs are bounded, take their input, and name their process; a
// missing pfctl is unsupported. /bin/cat and /bin/sleep stand in for it.
func TestExecPfctl(t *testing.T) {
	out, err := execPfctl{path: "/bin/cat", timeout: 5 * time.Second}.run(context.Background(), []byte("table <x> { }\n"))
	if err != nil || string(out.stdout) != "table <x> { }\n" || out.pid <= 0 {
		t.Errorf("cat: %q, pid %d, %v", out.stdout, out.pid, err)
	}
	start := time.Now()
	_, err = execPfctl{path: "/bin/sleep", timeout: 100 * time.Millisecond}.run(context.Background(), nil, "30")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("sleep: %v after %v", err, time.Since(start))
	}
	out, err = execPfctl{path: "/bin/ls", timeout: 5 * time.Second}.run(context.Background(), nil, "/nonexistent-tp078")
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) || len(out.stderr) == 0 {
		t.Errorf("a failing run: %v, stderr %q", err, out.stderr)
	}
	_, err = execPfctl{path: "/nonexistent-tp078/pfctl", timeout: time.Second}.run(context.Background(), nil, "-s", "info")
	if !errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("no pfctl: %v, want unsupported", err)
	}
	g := newIPv6Guard(execPfctl{path: "/nonexistent-tp078/pfctl", timeout: time.Second}, newRig(t).store(), time.Hour, ownAddrs)
	if err := g.Close(); err != nil {
		t.Errorf("Close without pfctl: %v", err)
	}
}

// TestCloseKeepsAReferenceItCantSeeListed: a References listing the guard
// can't read proves nothing about the reference it holds, so Close fails
// and keeps the record (pf stays enabled on it) rather than forgetting a
// reference pf still lists; once the listing reads again, Close releases
// it.
func TestCloseKeepsAReferenceItCantSeeListed(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	held := r.pf.references()
	if len(held) != 1 {
		t.Fatalf("references %v", held)
	}
	record := r.record(t)
	r.pf.set(func(f *fakePF) { f.oddReferences = true })
	if err := g.Close(); !errors.Is(err, errUnreadReferences) {
		t.Fatalf("Close over an unreadable listing: %v", err)
	}
	if got := r.record(t); got != record || !slices.Equal(r.pf.references(), held) || r.pf.ran("-X") != 0 {
		t.Fatalf("after a failed Close: record %q, references %v, %d releases", got, r.pf.references(), r.pf.ran("-X"))
	}
	r.pf.set(func(f *fakePF) { f.oddReferences = false })
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if r.record(t) != "" || len(r.pf.references()) != 0 {
		t.Fatalf("after Close: record %q, references %v", r.record(t), r.pf.references())
	}
}

// TestParseReferencesByTheHeadersColumns: the token is read where the
// header's TOKEN starts, whatever the name and the timestamp look like; a
// line out of those columns, or no header, is a listing not understood.
func TestParseReferencesByTheHeadersColumns(t *testing.T) {
	head := "TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n"
	refs, understood := parseReferences(pfOutput{stdout: []byte(head +
		"618      Network Filter Daemon 2      9813589183660731843   Thu Oct 22 12:00:01 2026\n" +
		"4130     pfctl                        9000000000000000008   5s\n")})
	if !understood || !slices.Equal(refs, []pfReference{{618, 9813589183660731843}, {4130, 9000000000000000008}}) {
		t.Fatalf("%v, %v", refs, understood)
	}
	for name, l := range map[string]string{
		"a name past its column": "702      A process name much longer than its column 9000000000000000015 0 days\n",
		"no token":               "702      pfctl\n",
		// A number in the name runs across the TOKEN column: its tail
		// there is no token.
		"digits across the column": "702      worker 9999999999999999999999999 9000000000000000015 0 days\n",
		// Shifted by one: no field starts at the column.
		"a token off its column": "702      pfctl                         9000000000000000015  0 days\n",
		"no pid":                 "         pfctl                        9000000000000000015   0 days\n",
	} {
		if _, understood := parseReferences(pfOutput{stdout: []byte(head + l)}); understood {
			t.Errorf("%s: understood", name)
		}
	}
	if _, understood := parseReferences(pfOutput{stdout: []byte("618 socketfilterfw 9813589183660731843 0 days 00:03:31\n")}); understood {
		t.Error("no header: understood")
	}
}

// cannedPfctl answers every run with the same listing.
type cannedPfctl struct{ out []byte }

func (c cannedPfctl) run(context.Context, []byte, ...string) (pfOutput, error) {
	return pfOutput{stdout: c.out}, nil
}

// TestResolveReadsNoTokenFromAListingItCantRead: a listing cut short
// (a line too long to read) lists the pid's reference before the cut, and
// still isn't taken.
func TestResolveReadsNoTokenFromAListingItCantRead(t *testing.T) {
	cut := "TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n" +
		"4130     pfctl                        9000000000000000008   0 days 00:00:05\n" + strings.Repeat("x", 1<<20) + "\n"
	g := newIPv6Guard(cannedPfctl{[]byte(cut)}, newRig(t).store(), time.Hour, ownAddrs)
	if v, ok, err := g.resolve(context.Background(), pfToken{pid: 4130}); ok || v != 0 || !errors.Is(err, errUnreadReferences) {
		t.Fatalf("%d, %v, %v", v, ok, err)
	}
	if err := g.release(context.Background(), pfToken{value: 9000000000000000008, pid: 4130}); !errors.Is(err, errUnreadReferences) {
		t.Fatalf("release: %v", err)
	}
}

// skipped is what checkBypass counts of a `-s Interfaces -v` listing:
// the skipped names but lo0 and tun.
func skipped(ifaces []byte, tun string) []string {
	names, err := skippedNames(ifaces)
	if err != nil {
		return []string{"unreadable: " + err.Error()}
	}
	return slices.DeleteFunc(names, func(n string) bool { return n == "lo0" || n == tun })
}

// TestCutListingsAreUnreadable: a line too long to read cuts a listing,
// and none of the guard's readers takes what came before it as the whole.
func TestCutListingsAreUnreadable(t *testing.T) {
	cut := "\n" + strings.Repeat("x", 1<<20) + "\n"
	if _, err := skippedNames([]byte("en0 (skip)" + cut)); err == nil {
		t.Error("Interfaces")
	}
	if _, err := parseEnabled([]byte("Status: Enabled for 0 days" + cut)); err == nil {
		t.Error("info")
	}
	if _, err := parseTable([]byte("2001:db8::/32" + cut)); err == nil {
		t.Error("table")
	}
	r := newRig(t)
	r.pf.set(func(f *fakePF) { f.main = append(slices.Clone(stockMain), strings.Repeat("x", 1<<20)) })
	if err := r.guard().Apply(context.Background(), exempt(t)); err == nil || errors.Is(err, routetable.ErrGuardUnsupported) || !strings.Contains(err.Error(), "cut") {
		t.Errorf("a cut main ruleset: %v, want an ordinary failure", err)
	}
}

// TestAFailedReleaseOfTheOldReferenceIsTold: pf was turned off while pf
// kept the guard's reference listed; enabling it anew takes a new one, and
// when the old one can't be released (a References listing the guard
// can't read) Apply says so instead of dropping it, the record naming the
// new reference.
func TestAFailedReleaseOfTheOldReferenceIsTold(t *testing.T) {
	r := newRig(t)
	r.pf.set(func(f *fakePF) { f.keepRefs = true })
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	old := r.pf.references()[0]
	r.pf.disable()
	// A state made while pf was off, to a destination the guard refuses:
	// that same Apply still kills it before it tells the failed release.
	foreign := fakeState{"tcp", netip.AddrPortFrom(ownV6, 51000), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
	r.pf.set(func(f *fakePF) {
		f.oddReferences = true
		f.states = append(f.states, foreign)
	})
	err := g.Apply(context.Background(), exempt(t))
	if !errors.Is(err, errUnreadReferences) || !strings.Contains(err.Error(), "releasing the reference it held before") {
		t.Fatalf("Apply: %v", err)
	}
	if slices.Contains(r.pf.stateList(), foreign) {
		t.Fatal("the Apply that told the failed release left a state made while pf was off")
	}
	refs := r.pf.references()
	if len(refs) != 2 || refs[0] != old || !strings.Contains(r.record(t), fmt.Sprintf("token %d pid %d", refs[1].value, refs[1].pid)) {
		t.Fatalf("references %v, record %q", refs, r.record(t))
	}
}

func TestCutStateAndRuleListingsAreUnreadable(t *testing.T) {
	cut := "\n" + strings.Repeat("x", 1<<20) + "\n"
	if _, err := parseStateAddrs([]byte("ALL tcp 2001:db8:1::10[1] -> 2001:db8:ab::7[443] X" + cut)); err == nil {
		t.Error("states")
	}
	r := newRig(t)
	r.pf.setAnchor(GuardAnchor, &fakeAnchor{rules: []string{"block return out quick inet6 all", strings.Repeat("x", 1<<20)}})
	if _, err := r.guard().listRules(context.Background()); err == nil || !strings.Contains(err.Error(), "cut") {
		t.Errorf("the anchor's rules: %v", err)
	}
}

// TestPfctlsNoAnswersAreExact: a missing anchor, a missing table and no
// references are each one answer of pfctl's, alone on its stream but for
// ALTQ chatter. Anything else, another ioctl's "Invalid argument", a
// second line or a listing cut short included, isn't that answer.
func TestPfctlsNoAnswersAreExact(t *testing.T) {
	cut := "\n" + strings.Repeat("x", 1<<20) + "\n"
	for stderr, missing := range map[string]bool{
		"pfctl: DIOCGETRULES: Invalid argument\n":                                        true,
		altq + "pfctl: DIOCGETRULES: Invalid argument\n":                                 true,
		"pfctl: DIOCGETRULES: Invalid argument":                                          true,
		"pfctl: DIOCADDRULE: Invalid argument\n":                                         false,
		"pfctl: DIOCGETRULESETS: Invalid argument\n":                                     false,
		"pfctl: DIOCGETRULE: Invalid argument\n":                                         false,
		"pfctl: pfctl_clear_rules: Invalid argument\n":                                   false,
		"pfctl: Invalid argument.\n":                                                     false,
		"DIOCGETRULES: Invalid argument\n":                                               false,
		"pfctl: DIOCGETRULES: Invalid argument\nmore\n":                                  false,
		"pfctl: DIOCGETRULES: Invalid argument" + cut:                                    false,
		"pfctl: DIOCGETRULES: Invalid argument (anchor)\n":                               false,
		"pfctl: DIOCGETRULES: Invalid argument\npfctl: DIOCGETRULES: Invalid argument\n": false,
		"":   false,
		altq: false,
	} {
		if got := AnchorMissing([]byte(stderr)); got != missing {
			t.Errorf("AnchorMissing(%.60q) = %v", stderr, got)
		}
	}
	for stderr, none := range map[string]bool{
		"pfctl: Table does not exist.\n":                               true,
		altq + "pfctl: Anchor or Ruleset does not exist.\n":            true,
		"pfctl: DIOCRGETADDRS: Invalid argument\n":                     false,
		"pfctl: Invalid argument.\n":                                   false,
		"pfctl: Table does not exist.\npfctl: more\n":                  false,
		"pfctl: Table does not exist." + cut:                           false,
		"pfctl: the table does not exist\n":                            false,
		"pfctl: Table does not exist.\npfctl: Table does not exist.\n": false,
		"": false,
	} {
		if got := noTable([]byte(stderr)); got != none {
			t.Errorf("noTable(%.60q) = %v", stderr, got)
		}
	}
	for stdout, understood := range map[string]bool{
		"No pf starter references held\n":                                true,
		altq + "No pf starter references held\n":                         true,
		"No pf starter references held.\n":                               false,
		"No pf starter references held\nmore\n":                          false,
		"TOKENS:\nNo pf starter references held\n":                       false,
		"No pf starter references held" + cut:                            false,
		"No pf references held\n":                                        false,
		"No pf starter references held\nNo pf starter references held\n": false,
	} {
		if refs, got := parseReferences(pfOutput{stdout: []byte(stdout), stderr: []byte(altq)}); got != understood || len(refs) != 0 {
			t.Errorf("parseReferences(%.60q) = %v, %v", stdout, refs, got)
		}
	}
	// The answer of none held counts only with a quiet stderr.
	for _, stderr := range []string{"pfctl: a warning\n", answerNoReferences + "\n", altq + "x" + strings.Repeat("y", 1<<20) + "\n"} {
		if _, got := parseReferences(pfOutput{stdout: []byte(answerNoReferences + "\n"), stderr: []byte(stderr)}); got {
			t.Errorf("parseReferences with stderr %.60q understood", stderr)
		}
	}
}

// TestAnotherInvalidArgumentIsNoEmptyAnchor: pfctl failing to list an
// anchor that is there with an "Invalid argument" that isn't the missing
// anchor's (DIOCGETRULE, the per-rule ioctl of a rules listing;
// DIOCRGETADDRS, a table's) is an error. A flush that fails and can't be
// checked fails the Close, with both errors, and keeps the anchor, the
// reference and the record; the snapshot says the rules and the table are
// unreadable, not absent.
func TestAnotherInvalidArgumentIsNoEmptyAnchor(t *testing.T) {
	ctx := context.Background()
	listing := map[string]string{
		"rules":  GuardAnchor + " -s rules",
		"Tables": GuardAnchor + " -t " + exemptTable + " -T show",
	}
	// What each fails with: the flush's ioctl and the listing's per-item
	// one, as pfctl names them.
	flushIoctl := map[string]string{"rules": "DIOCBEGINRULES", "Tables": "DIOCRCLRTABLES"}
	listIoctl := map[string]string{"rules": "DIOCGETRULE", "Tables": "DIOCRGETADDRS"}
	for _, what := range []string{"rules", "Tables"} {
		r := newRig(t)
		g := r.guard()
		if err := g.Apply(ctx, exempt(t)); err != nil {
			t.Fatal(err)
		}
		held, record := r.pf.references(), r.record(t)
		r.pf.failOn("-F "+what, errors.New(flushIoctl[what]+": Invalid argument"))
		r.pf.failOn(listing[what], errors.New(listIoctl[what]+": Invalid argument"))
		if err := g.Close(); err == nil {
			t.Fatalf("%s: closed over a listing that failed", what)
		} else if !strings.Contains(err.Error(), flushIoctl[what]+":") || !strings.Contains(err.Error(), listIoctl[what]+":") {
			t.Errorf("%s: the Close's error names the flush's and the listing's failures: %v", what, err)
		}
		if r.record(t) != record || !slices.Equal(r.pf.references(), held) || r.pf.ran("-X") != 0 {
			t.Fatalf("%s: after a failed Close: record %q, references %v", what, r.record(t), r.pf.references())
		}
		if a := r.pf.anchor(GuardAnchor); (what == "rules" && len(a.rules) == 0) || (what == "Tables" && len(a.tables) == 0) {
			t.Fatalf("%s: %+v", what, a)
		}
		got := g.inspect(ctx)
		switch {
		case what == "rules" && (!strings.Contains(got.RulesUnreadable, "DIOCGETRULE:") || !got.PresentUnknown || got.Present):
			t.Errorf("rules: inspect %+v", got)
		case what == "Tables" && (!strings.Contains(got.ExemptUnreadable, "DIOCRGETADDRS:") || got.Exempt != nil):
			t.Errorf("Tables: inspect %+v", got)
		}
		r.pf.failOn("-F "+what, nil)
		r.pf.failOn(listing[what], nil)
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
	}
}

// TestCloseAfterAnOutsideReleaseRemovesTheRecord: someone else released
// the guard's reference (`pfctl -X` with its token), and pf holds none:
// `-s References` prints only "No pf starter references held", as a Mac
// does. That listing is read as no reference: the Close flushes the
// anchor, releases nothing and removes the record, and the snapshot says
// the record's reference isn't held.
func TestCloseAfterAnOutsideReleaseRemovesTheRecord(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.set(func(f *fakePF) { f.refs = nil })
	out, err := r.pf.run(ctx, nil, "-s", "References")
	if err != nil || !bytes.Equal(out.stdout, fixture(t, "recorded-references-none.txt")) {
		t.Fatalf("the fake's References %q, %v; want the recorded listing", out.stdout, err)
	}
	ref := g.inspect(ctx).PF.Reference
	if ref == nil || !ref.Recorded || ref.Held || ref.HeldUnreadable != "" {
		t.Fatalf("inspect: %+v", ref)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
	if n := r.pf.ran("-X"); n != 0 {
		t.Errorf("%d releases of a reference pf doesn't hold", n)
	}
}

// TestARuleLabelledALTQIsSeen: pfctl's ALTQ chatter is two exact lines; a
// rule whose label says "ALTQ", put into the guard's anchor, is a rule
// like any other: the anchor isn't intact, and the next Apply reloads it.
func TestARuleLabelledALTQIsSeen(t *testing.T) {
	ctx := context.Background()
	injected := `pass out quick inet6 all label "ALTQ"`
	if l := lines([]byte(altq + injected + "\n")); !slices.Equal(l, []string{injected}) {
		t.Fatalf("lines: %q", l)
	}
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.set(func(f *fakePF) {
		a := f.anchors[GuardAnchor]
		a.rules = append([]string{injected}, a.rules...)
	})
	if g.intact(ctx, g.applied) {
		t.Fatal("intact with a rule labelled ALTQ added")
	}
	r.pf.forget()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if r.pf.ran("-f") != 1 || slices.Contains(r.pf.anchor(GuardAnchor).rules, injected) {
		t.Errorf("not reloaded: %q", r.pf.anchor(GuardAnchor).rules)
	}
	r.whole(t, exempt(t))
}

// TestAFlushThatSucceedsIsChecked: a -F that answers success but leaves
// the anchor's rules or its table fails the Close, which keeps the
// anchor, the reference and the record.
func TestAFlushThatSucceedsIsChecked(t *testing.T) {
	ctx := context.Background()
	for what, says := range map[string]string{"rules": "still lists", "Tables": "still holds"} {
		r := newRig(t)
		g := r.guard()
		if err := g.Apply(ctx, exempt(t)); err != nil {
			t.Fatal(err)
		}
		held, record := r.pf.references(), r.record(t)
		r.pf.set(func(f *fakePF) { f.flushKeeps = what })
		if err := g.Close(); err == nil || !strings.Contains(err.Error(), says) {
			t.Fatalf("%s: Close over a flush that left it: %v", what, err)
		}
		if r.record(t) != record || !slices.Equal(r.pf.references(), held) || r.pf.ran("-X") != 0 {
			t.Fatalf("%s: after a failed Close: record %q, references %v", what, r.record(t), r.pf.references())
		}
		r.pf.set(func(f *fakePF) { f.flushKeeps = "" })
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		r.gone(t)
	}
}

// TestNoReferencesWithAWarningIsUnread: "No pf starter references held"
// on stdout with something besides ALTQ chatter on stderr isn't pfctl's
// answer of none held: the Close keeps the record, and the snapshot says
// the reference is unreadable.
func TestNoReferencesWithAWarningIsUnread(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	record := r.record(t)
	r.pf.set(func(f *fakePF) {
		f.refs = nil
		f.referencesWarn = "pfctl: DIOCGETSTARTERS: Invalid argument"
	})
	if ref := g.inspect(ctx).PF.Reference; ref == nil || ref.HeldUnreadable == "" {
		t.Errorf("inspect: %+v", ref)
	}
	if err := g.Close(); err == nil {
		t.Fatal("closed over a References listing with a warning")
	}
	if r.record(t) != record {
		t.Fatalf("record %q, want %q", r.record(t), record)
	}
	r.pf.set(func(f *fakePF) { f.referencesWarn = "" })
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
}
