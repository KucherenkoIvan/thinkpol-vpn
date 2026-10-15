package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

const thisBoot = "6F1C0D2E-0000-4000-8000-000000000001"

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

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
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
		Upstreams: addrs("2001:db8:53::1", "192.0.2.53"),
	}
}

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

func (r *rig) guard() *IPv6Guard { return newIPv6Guard(r.pf, r.store(), time.Hour) }

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

// whole fails t unless pf holds the guard for e: the anchor's table is
// exactly e's (as prefixes), the rules pass tun and end in the block, pf
// is on with exactly one reference besides others, the record's.
func (r *rig) whole(t *testing.T, e routetable.Exempt, others ...pfToken) {
	t.Helper()
	a := r.pf.anchor(GuardAnchor)
	got := make([]netip.Prefix, 0, len(a.table))
	for _, s := range a.table {
		got = append(got, netip.MustParsePrefix(s))
	}
	if want := exemptTable(e); !slices.Equal(got, want) {
		t.Errorf("table %v, want %v", got, want)
	}
	if len(a.rules) != 13 || !strings.Contains(a.rules[1], " on "+e.TUN+" ") || a.rules[12] != "block return out quick inet6 all" {
		t.Errorf("rules %q", a.rules)
	}
	if !r.pf.isOn() {
		t.Error("pf is off")
	}
	refs := r.pf.references()
	var ours []pfToken
	for _, ref := range refs {
		if !slices.Contains(others, ref) {
			ours = append(ours, ref)
		}
	}
	if len(ours) != 1 {
		t.Fatalf("references %v besides %v, want one of the guard's", ours, others)
	}
	if rec := r.record(t); !strings.Contains(rec, "\nboot "+r.boot+"\n") ||
		!strings.Contains(rec, "\ntoken "+itoa(ours[0].value)+" pid "+itoa(uint64(ours[0].pid))+"\n") {
		t.Errorf("record %q, want %v of boot %s", rec, ours[0], r.boot)
	}
}

// gone fails t unless the guard left nothing: no rule, no table, none of
// its references, no record; others' references untouched.
func (r *rig) gone(t *testing.T, others ...pfToken) {
	t.Helper()
	if a := r.pf.anchor(GuardAnchor); len(a.rules) != 0 || len(a.table) != 0 {
		t.Errorf("anchor left: %+v", a)
	}
	if refs := r.pf.references(); !slices.Equal(refs, others) {
		t.Errorf("references %v, want %v", refs, others)
	}
	if rec := r.record(t); rec != "" {
		t.Errorf("record left: %q", rec)
	}
}

func itoa(v uint64) string { return strconv.FormatUint(v, 10) }

func TestAnchorText(t *testing.T) {
	got := anchorText("utun7", exemptTable(exempt(t)))
	want := `table <thinkpol_exempt6> const persist { \
	2001:db8:e::9/128, \
	2001:db8:53::1/128, \
	2001:db8:d0::/48, \
	fe80::/10, \
	ff02::/16 }
pass out quick on lo0 inet6 all no state
pass out quick on utun7 inet6 all no state
pass out quick inet6 from any to <thinkpol_exempt6> no state
pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state
pass out quick inet6 proto ipv6-icmp all icmp6-type { 130, 131, 132, 143 } no state
block return out quick inet6 all
`
	if got != want {
		t.Errorf("anchor:\n%s\nwant:\n%s", got, want)
	}
}

// The table is the IPv6 exempt destinations as the fewest prefixes; IPv4
// and zones never reach it.
func TestExemptTable(t *testing.T) {
	var b lists.Builder
	_ = b.AddRange(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")) // two prefixes
	_ = b.AddPrefix(netip.MustParsePrefix("2001:db8::4/126"))
	direct, _ := b.Build()
	e := routetable.Exempt{TUN: "utun3", Direct: direct,
		Upstreams: addrs("2001:db8::3", "fe80::1%en0", "::ffff:192.0.2.1", "192.0.2.2", "2001:db8:1::5")}
	want := pfxs("2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/126", "2001:db8:1::5/128", "fe80::/10", "ff02::/16")
	if got := exemptTable(e); !slices.Equal(got, want) {
		t.Errorf("table %v, want %v", got, want)
	}
	if got := exemptTable(routetable.Exempt{TUN: "utun3"}); !slices.Equal(got, routetable.LinkScoped) {
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
		want  bool
	}{
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", true},
		{"anchor \"com.apple/*\"\n", true},
		{"  anchor \"com.apple/*\" all  \n", true},
		{"", false},
		{"scrub-anchor \"com.apple/*\" all fragment reassemble\n", false},
		{"anchor \"com.apple/*\" in all\n", false},
		{"anchor \"com.apple/*\" on en0 all\n", false},
		{"anchor \"com.apple\" all\n", false},
		{"anchor \"com.apple/thinkpol\" all\n", false},
		{"pass out all # anchor \"com.apple/*\" all\n", false},
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
		{"Token : 14715852371098265711\n", "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\n", 14715852371098265711},
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

func TestReferenced(t *testing.T) {
	refs := []byte("TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n" +
		"4012     pfctl                        9000000000000000001   0 days 00:00:05\n" +
		"77       pfctl                        555                   1 days 02:00:00\n")
	for _, c := range []struct {
		t    pfToken
		want reference
	}{
		{pfToken{9000000000000000001, 4012}, refOurs},
		{pfToken{9000000000000000001, 4013}, refForeign}, // the value, reused by another enabler
		{pfToken{555, 4012}, refForeign},
		{pfToken{55, 77}, refGone},     // a prefix of a token isn't one
		{pfToken{4012, 4012}, refGone}, // a pid isn't a token
	} {
		if got := referenced(refs, c.t); got != c.want {
			t.Errorf("%v: %v, want %v", c.t, got, c.want)
		}
	}
}

func TestParseTable(t *testing.T) {
	got, err := parseTable([]byte("   2001:db8:d0::/48\n   2001:db8:53::1\n   ::102:304\n   fe80::/10\n\n"))
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

func TestApplyPutsTheGuardInPlace(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e)
	// The anchor is loaded before pf comes on.
	if f, en := slices.IndexFunc(r.pf.calls, func(c []string) bool { return slices.Contains(c, "-f") }),
		slices.IndexFunc(r.pf.calls, func(c []string) bool { return slices.Equal(c, []string{"-E"}) }); f < 0 || en < f {
		t.Errorf("load at %d, enable at %d", f, en)
	}
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
	for _, write := range []string{"-f", "-E", "-X", "-F"} {
		if n := r.pf.ran(write); n != 0 {
			t.Errorf("%s ran %d times", write, n)
		}
	}
	r.whole(t, e)
}

// What changes from outside is put right by the next Apply (and Watch
// sees it, TestWatchSignalsWhenTheGuardBreaks): content, not counts.
func TestApplyRepairsWhatChangedOutside(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(r *rig)
	}{
		{"an entry added", func(r *rig) {
			a := r.pf.anchor(GuardAnchor)
			a.table = append(a.table, "::/0")
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"an entry replaced", func(r *rig) {
			a := r.pf.anchor(GuardAnchor)
			a.table[0] = "2000::/3"
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"an entry removed", func(r *rig) {
			a := r.pf.anchor(GuardAnchor)
			a.table = a.table[1:]
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"the block replaced by a pass", func(r *rig) {
			a := r.pf.anchor(GuardAnchor)
			a.rules[12] = "pass out quick inet6 all"
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"the anchor flushed", func(r *rig) {
			r.pf.setAnchor(GuardAnchor, &fakeAnchor{})
		}},
		{"pf disabled", func(r *rig) { r.pf.disable() }},
		{"pf disabled, its references kept", func(r *rig) { r.pf.keepRefs = true; r.pf.disable() }},
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

// A new Exempt replaces the table and the rules, with the same reference.
func TestApplyingAnotherExemptReplacesIt(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	first := r.pf.references()
	e2 := routetable.Exempt{TUN: "utun9", Direct: set(t, "2001:db8:f0::/44"), Upstreams: addrs("2001:db8:54::1")}
	if err := g.Apply(context.Background(), e2); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e2)
	if a := r.pf.anchor(GuardAnchor); slices.Contains(a.table, "2001:db8:d0::/48") || slices.Contains(a.table, "2001:db8:53::1/128") {
		t.Errorf("the old exempts stayed: %v", a.table)
	}
	if !slices.Equal(r.pf.references(), first) {
		t.Errorf("references %v, want %v", r.pf.references(), first)
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

// A fresh guard with nothing left to clear only flushes the (empty)
// anchor.
func TestAFreshGuardCloseOnACleanHost(t *testing.T) {
	r := newRig(t)
	if err := r.guard().Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
	if n := r.pf.ran("-X") + r.pf.ran("-E"); n != 0 {
		t.Errorf("references touched %d times", n)
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

// A record of an earlier boot holds nothing: its token value may well be
// someone's now.
func TestARecordOfAnEarlierBootReleasesNothing(t *testing.T) {
	r := newRig(t)
	if err := r.guard().Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	refs := r.pf.references() // as if another enabler holds the same token and pid this boot
	r.boot = "6F1C0D2E-0000-4000-8000-000000000002"
	r.pf.setAnchor(GuardAnchor, &fakeAnchor{}) // a reboot took it
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
		r.pf.reuse = ours.value
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
		r.writeRecord(t, "boot "+thisBoot+"\ntoken "+itoa(theirs.value)+"\n") // no pid: not ours to judge
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

// The hook going away under an applied guard makes it unsupported too;
// Close still removes it all.
func TestTheHookGoingAwayIsUnsupported(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.pf.main = nil
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
	for _, key := range []string{"rules", "-f", "show", "info", "-E"} {
		t.Run(key, func(t *testing.T) {
			r := newRig(t)
			g := r.guard()
			e := exempt(t)
			r.pf.failOn(key, errFake)
			err := g.Apply(context.Background(), e)
			if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
				t.Fatalf("%v, want an ordinary failure", err)
			}
			if key != "-E" && r.pf.isOn() {
				t.Error("pf enabled without the guard in place")
			}
			r.pf.failOn(key, nil)
			if err := g.Apply(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			r.whole(t, e)
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

// pf listing what wasn't loaded fails the Apply.
func TestALoadPfDoesntHoldFails(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	// The fake drops the last table entry on load, as a pf that took the
	// list wrong would.
	orig := fakeLoadHook
	fakeLoadHook = func(a *fakeAnchor) { a.table = a.table[:len(a.table)-1] }
	defer func() { fakeLoadHook = orig }()
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied")
	}
	if r.pf.isOn() {
		t.Error("pf enabled for a guard that isn't in place")
	}
}

// `pfctl -E` that prints no token took a reference all the same: the
// guard doesn't take another on the retry.
func TestAnUnreadableTokenIsNotTakenTwice(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	r.pf.noToken = true
	if err := g.Apply(context.Background(), exempt(t)); err == nil {
		t.Fatal("applied")
	}
	r.pf.noToken = false
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if refs := r.pf.references(); len(refs) != 1 {
		t.Errorf("references %v, want the one", refs)
	}
	// pf turned off meanwhile: that reference is gone too, so a new one.
	r.pf.disable()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
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
	g := newIPv6Guard(r.pf, r.store(), 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := g.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
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
	quiet()
	for _, c := range []struct {
		what   string
		change func()
	}{
		{"an entry added", func() {
			a := r.pf.anchor(GuardAnchor)
			a.table = append(a.table, "::/0")
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"a rule replaced", func() {
			a := r.pf.anchor(GuardAnchor)
			a.rules[12] = "pass out quick inet6 all"
			r.pf.setAnchor(GuardAnchor, a)
		}},
		{"pf disabled", r.pf.disable},
		{"the hook gone", func() { r.pf.mu.Lock(); r.pf.main = nil; r.pf.mu.Unlock() }},
	} {
		c.change()
		signalled(c.what)
		r.pf.mu.Lock()
		r.pf.main = stockMain
		r.pf.mu.Unlock()
		if err := g.Apply(context.Background(), exempt(t)); err != nil {
			t.Fatal(err)
		}
		for len(ch) > 0 { // a poll that ran before the Apply
			<-ch
		}
		quiet()
	}
	cancel()
	for range ch {
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
	_, err = execPfctl{path: "/bin/ls", timeout: 5 * time.Second}.run(context.Background(), nil, "/nonexistent-tp078")
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("a failing run: %v", err)
	}
	_, err = execPfctl{path: "/nonexistent-tp078/pfctl", timeout: time.Second}.run(context.Background(), nil, "-s", "info")
	if !errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("no pfctl: %v, want unsupported", err)
	}
	g := newIPv6Guard(execPfctl{path: "/nonexistent-tp078/pfctl", timeout: time.Second}, newRig(t).store(), time.Hour)
	if err := g.Close(); err != nil {
		t.Errorf("Close without pfctl: %v", err)
	}
}
