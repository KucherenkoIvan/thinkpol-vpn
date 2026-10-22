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
	refs, understood := parseReferences(listing)
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
	if refs, understood := parseReferences([]byte("TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n")); len(refs) != 0 || !understood {
		t.Errorf("an empty listing: %v, %v", refs, understood)
	}
	for _, odd := range []string{"", "token=5 by pfctl(17013)\n", "17013 pfctl\n", "pfctl 17013 5 0 days\n"} {
		if refs, understood := parseReferences([]byte(odd)); len(refs) != 0 || understood {
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
	got := parseStateAddrs([]byte(altq +
		"ALL tcp 2001:db8:1::10[51000] -> 2001:db8:ab::7[443]       ESTABLISHED:ESTABLISHED\n" +
		"ALL udp 2001:db8:1::10[5353] <- 2001:db8:ab::8[53]       SINGLE:NO_TRAFFIC\n" +
		"en0 tcp 2001:db8:1::10[1] (2001:db8:1::11[2]) -> 2001:db8:ab::9[3]   X\n" +
		"ALL tcp 192.0.2.10:51000 -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED\n" +
		"ALL ipv6-icmp fe80::1%en0[3] -> ff02::1[0]       0:0\n"))
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

// `Invalid argument` from a flush of an anchor that is there isn't an
// empty anchor: the Close fails.
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

// An anchor nothing evaluates guards nothing: without the main ruleset's
// hook the guard is unsupported, and loads and enables nothing.
func TestWithoutTheAppleHookTheGuardIsUnsupported(t *testing.T) {
	for _, main := range [][]string{
		nil, // the main ruleset flushed
		{`scrub-anchor "com.apple/*" all fragment reassemble`},
		{`anchor "com.apple/*" in all`},
		{`pass out all`, `anchor "other/*" all`},
	} {
		r := newRig(t)
		r.pf.main = main
		err := r.guard().Apply(context.Background(), exempt(t))
		if !errors.Is(err, routetable.ErrGuardUnsupported) {
			t.Errorf("%q: %v, want unsupported", main, err)
		}
		if n := r.pf.ran("-f") + r.pf.ran("-E"); n != 0 {
			t.Errorf("%q: loaded or enabled %d times", main, n)
		}
	}
}

// A quick pass above the hook ends evaluation before the anchor: the
// guard isn't enforced (an ordinary failure, retried), and is again once
// it is gone.
func TestAQuickPassAboveTheHookIsNotEnforced(t *testing.T) {
	r := newRig(t)
	r.pf.main = []string{"pass out quick inet6 all no state", `anchor "com.apple/*" all`}
	g := r.guard()
	err := g.Apply(context.Background(), exempt(t))
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want an ordinary failure", err)
	}
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
}

// The hook going away under an applied guard makes it unsupported too;
// Close still removes it all.
func TestTheHookGoingAwayIsUnsupported(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.set(func(f *fakePF) { f.main = nil })
	if err := g.Apply(context.Background(), exempt(t)); !errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("%v, want unsupported", err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
}

// A pfctl failure is an ordinary, retried failure, never unsupported; the
// retry finishes the job without a second reference.
func TestPfctlFailuresAreRetried(t *testing.T) {
	for _, key := range []string{"rules", "-f", "show", "info", "-E", "states"} {
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
			if key != "-E" && key != "states" && r.pf.isOn() {
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
			if err := g.Apply(context.Background(), exempt(t)); !errors.Is(err, errUnreadToken) {
				t.Fatalf("%v, want the unread token", err)
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
	} {
		c.change()
		signalled(c.what)
		r.pf.set(func(f *fakePF) { f.main = stockMain })
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
