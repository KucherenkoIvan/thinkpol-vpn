package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// mainWith is the stock main ruleset with rules before its hook and
// after it.
func mainWith(before []string, after ...string) []string {
	m := slices.Clone(stockMain[:1])
	m = append(m, before...)
	m = append(m, stockMain[1])
	return append(m, after...)
}

// notEnforced fails t unless err is an ordinary failure naming each of
// names.
func notEnforced(t *testing.T, err error, names ...string) {
	t.Helper()
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want an ordinary failure", err)
	}
	for _, n := range names {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("%v, want it to name %q", err, n)
		}
	}
}

// Other VPN and firewall software hangs its own anchors in pf's main
// ruleset. One the main ruleset evaluates before the hook runs first, and
// a quick pass in it ends evaluation there: the guard isn't enforced (an
// ordinary failure, retried) while it lasts, though in place for the
// rest, and is again once the anchor passes nothing outgoing IPv6 can
// match.
func TestAQuickPassInAnEarlierAnchorIsNotEnforced(t *testing.T) {
	r := newRig(t)
	r.pf.main = mainWith([]string{`anchor "vpn" all`})
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"block drop in quick on en0 all", "pass out quick on en0 all no state"}})
	g := r.guard()
	notEnforced(t, g.Apply(context.Background(), exempt(t)), "anchor vpn")
	r.whole(t, exempt(t))
	if r.pf.ran("-a vpn -s rules") == 0 {
		t.Error("the earlier anchor wasn't read")
	}
	// Passes no outgoing IPv6 packet ends at: inbound, IPv4 only, not
	// quick.
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass in quick inet6 all", "pass out quick inet proto udp all", "pass out inet6 all"}})
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
	// An anchor that isn't there holds nothing.
	r.pf.set(func(f *fakePF) { delete(f.anchors, "vpn") })
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	// The poll sees it come back.
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass quick all"}})
	if !g.broken(context.Background()) {
		t.Error("the poll missed a quick pass in an earlier anchor")
	}
}

// pf follows anchors down: through a wildcard's children, a name relative
// to the anchor holding the rule (`../`), an absolute one. A pass that
// ends evaluation at any depth before the hook counts; an anchor that is
// called but missing, or only inbound or IPv4, isn't read.
func TestNestedAnchorsAreFollowedAsPfEvaluatesThem(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		main    []string
		anchors map[string][]string
		want    string // "" enforced; else the anchor the error names
	}{
		{"a wildcard's child", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a": {"block return out quick inet all"}, "vpn/b": {"pass out quick all"}}, "vpn/b"},
		{"under a child", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a": {`anchor "inner" all`}, "vpn/a/inner": {"pass out quick inet6 all"}}, "vpn/a/inner"},
		{"relative upward", []string{`anchor "vpn/a" out all`},
			map[string][]string{"vpn/a": {`anchor "../b/*" all`}, "vpn/b/c": {"pass quick on en0 all"}}, "vpn/b/c"},
		{"absolute", []string{`anchor "vpn" all`},
			map[string][]string{"vpn": {`anchor "/fw" all`}, "fw": {"pass out quick all"}}, "anchor fw"},
		{"a wildcard of nothing", []string{`anchor "gone/*" all`}, nil, ""},
		{"called but missing", []string{`anchor "vpn" all`}, map[string][]string{"vpn": {`anchor "gone" all`}}, ""},
		{"inbound only", []string{`anchor "vpn" in all`}, map[string][]string{"vpn": {"pass quick all"}}, ""},
		{"IPv4 only", []string{`anchor "vpn" out inet all`}, map[string][]string{"vpn": {"pass quick all"}}, ""},
		{"a loop", []string{`anchor "vpn" all`},
			map[string][]string{"vpn": {`anchor "../vpn" all`, `anchor "/vpn" all`, "block out all"}}, ""},
		{"a nested inbound call", []string{`anchor "vpn" all`},
			map[string][]string{"vpn": {`anchor "inner" in all`}, "vpn/inner": {"pass quick all"}}, ""},
		{"a child's name with spaces", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a b": {"pass out quick all"}}, "vpn/a b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.pf.main = mainWith(c.main)
			for name, rules := range c.anchors {
				r.pf.setAnchor(name, &fakeAnchor{rules: rules})
			}
			err := r.guard().Apply(ctx, exempt(t))
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				notEnforced(t, err, c.want)
			}
			r.whole(t, exempt(t))
		})
	}
}

// pf stops after a quick anchor once a rule in it matched: any pass in
// one, quick or not, at any depth below it, ends evaluation there.
func TestAnyPassInAQuickAnchorIsNotEnforced(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{`anchor "inner" all`}})
	r.pf.setAnchor("vpn/inner", &fakeAnchor{rules: []string{"pass out inet6 all keep state"}})
	r.pf.main = mainWith([]string{`anchor "vpn" all`})
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatalf("a pass that isn't quick, in no quick anchor: %v", err)
	}
	r.pf.set(func(f *fakePF) { f.main = mainWith([]string{`anchor "vpn" out quick all`}) })
	notEnforced(t, g.Apply(ctx, exempt(t)), "vpn/inner")
}

// An anchor read once outside a quick anchor holds the same rules inside
// one, but there any pass in it ends evaluation: the second call is read
// again.
func TestAnAnchorCalledAgainWithQuickIsReadAgain(t *testing.T) {
	r := newRig(t)
	r.pf.main = mainWith([]string{`anchor "vpn" all`, `anchor "vpn" quick all`})
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass out inet6 all"}})
	notEnforced(t, r.guard().Apply(context.Background(), exempt(t)), "anchor vpn")
	r.whole(t, exempt(t))
}

// An anchor after the hook runs after the guard's block: no bypass, and
// not even read, so anchors after the hook cost the poll no extra pfctl
// run.
func TestAnAnchorAfterTheHookIsNoBypass(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.pf.main = mainWith(nil, `anchor "vpn" all`, `anchor "fw/*" all`)
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass out quick inet6 all no state"}})
	r.pf.setAnchor("fw/a", &fakeAnchor{rules: []string{"pass out quick inet6 all no state"}})
	g := r.guard()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	r.whole(t, exempt(t))
	r.pf.forget()
	if g.broken(ctx) {
		t.Error("the poll took an anchor after the hook for a bypass")
	}
	if n := r.pf.ran("-a vpn") + r.pf.ran("-a fw"); n != 0 {
		t.Errorf("read the anchors after the hook %d times", n)
	}
	if n := len(r.pf.calls); n != 6 {
		t.Errorf("a poll ran pfctl %d times, want 6: %q", n, r.pf.calls)
	}
}

// The guard's own anchor ends evaluation for every outgoing IPv6 packet
// that reaches it, so a call of com.apple's children above the hook (one
// narrowed to an interface) reads only those before it: Apple's after it
// are never reached that way.
func TestAnEarlierCallOfTheGuardsAnchorStopsThere(t *testing.T) {
	r := newRig(t)
	r.pf.main = mainWith([]string{`anchor "com.apple/*" on en0 all`})
	r.pf.setAnchor("com.apple/250.ApplicationFirewall", &fakeAnchor{rules: []string{"pass out quick all"}})
	g := r.guard()
	if err := g.Apply(context.Background(), exempt(t)); err != nil {
		t.Fatal(err)
	}
	if n := r.pf.ran("-a com.apple/250.ApplicationFirewall -s rules"); n != 0 {
		t.Errorf("read an anchor after the guard's %d times", n)
	}
}

// What the guard can't follow it can't clear: an anchor without a name it
// can place or read (a `*` pfctl's -a would take off), pf refusing to
// list an earlier anchor's rules or children, a child a listing named
// that reads as missing (a name pf prints otherwise than the guard reads
// it), more than it reads. Each leaves the guard not enforced.
func TestAnEarlierAnchorTheGuardCantReadIsNotEnforced(t *testing.T) {
	ctx := context.Background()
	chain := map[string][]string{}
	name := "deep"
	for range 2 * maxEarlierReads {
		chain[name] = []string{`anchor "next" all`}
		name += "/next"
	}
	for _, c := range []struct {
		name          string
		main          []string
		anchors       map[string][]string
		fail, failErr string
		want          string
	}{
		{"anonymous", []string{"anchor out all"}, nil, "", "", "can't name"},
		{"anonymous inside", []string{`anchor "vpn" all`}, map[string][]string{"vpn": {"anchor all"}}, "", "", "anchor vpn calls"},
		{"above the main ruleset", []string{`anchor "../x" all`}, nil, "", "", "can't name"},
		{"a star in a called name", []string{`anchor "vpn/a*" all`}, map[string][]string{"vpn/a": nil}, "", "", "can't name"},
		{"a star in a listed name", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a": nil, "vpn/a*": {"pass out quick all"}}, "", "", `can't read, "vpn/a*"`},
		{"a listed child reads as missing", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a": {"pass out quick all"}}, "vpn/a -s rules", "DIOCGETRULES: Invalid argument", "vpn/a, but it reads as missing"},
		{"rules refused", []string{`anchor "vpn" all`}, map[string][]string{"vpn": {"block all"}}, "vpn -s rules", "DIOCGETRULES: Operation not permitted", "DIOCGETRULES"},
		{"children refused", []string{`anchor "vpn/*" all`}, map[string][]string{"vpn/a": nil}, "vpn -s Anchors", "DIOCGETRULESETS: Operation not permitted", "DIOCGETRULESETS"},
		{"a quote in a called name", []string{`anchor "vpn" all`},
			map[string][]string{"vpn": {`anchor "a"b" all`}, `vpn/a"b`: {"pass out quick all"}}, "", "", "anchor vpn calls"},
		{"a quote in a called name, its tail read as inbound", []string{`anchor "vpn" all`},
			map[string][]string{"vpn": {`anchor "x" in "y" all`}, `vpn/x" in "y`: {"pass out quick all"}}, "", "", "anchor vpn calls"},
		{"a listed name ending in a space", []string{`anchor "vpn/*" all`},
			map[string][]string{"vpn/a": nil, "vpn/a ": {"pass out quick all"}}, "", "", `can't read, "vpn/a "`},
		{"too many", []string{`anchor "deep" all`}, chain, "", "", "at most 16 pfctl runs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.pf.main = mainWith(c.main)
			for name, rules := range c.anchors {
				r.pf.setAnchor(name, &fakeAnchor{rules: rules})
			}
			if c.fail != "" {
				r.pf.failOn(c.fail, errors.New(c.failErr))
			}
			notEnforced(t, r.guard().Apply(ctx, exempt(t)), c.want)
			r.whole(t, exempt(t))
			n := 0
			for _, call := range r.pf.calls {
				if len(call) > 1 && call[0] == "-a" && (strings.HasPrefix(call[1], "deep") || strings.HasPrefix(call[1], "vpn")) {
					n++
				}
			}
			if n > maxEarlierReads {
				t.Errorf("ran pfctl %d times on earlier anchors, want at most %d", n, maxEarlierReads)
			}
		})
	}
}

// The retries under the same bypasses leave states alone, and a change to
// them, or to any rule read up to the hook, kills, even one the error
// words alike: a second quick pass above the hook, an earlier anchor's
// rules changing under its name, a call narrowed to an interface or made
// quick, a block above the pass, a check that couldn't read pf.
func TestABypassChangeKillsEvenWhenTheErrorReadsAlike(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	g := r.guard()
	port := uint16(51000)
	state := func() fakeState {
		port++
		s := fakeState{"tcp", netip.AddrPortFrom(ownV6, port), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true}
		r.pf.set(func(f *fakePF) { f.states = append(f.states, s) })
		return s
	}
	alive := func(s fakeState) bool { return slices.Contains(r.pf.stateList(), s) }
	apply := func(when string) string {
		t.Helper()
		err := g.Apply(ctx, exempt(t))
		if err == nil {
			t.Fatalf("%s: enforced", when)
		}
		return err.Error()
	}

	r.pf.main = mainWith([]string{"pass out quick on en0 all", `anchor "vpn" all`})
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass out quick inet6 to 2001:db8:ab::/48"}})
	said := apply("two bypasses")
	a := state()
	if apply("a retry") != said || !alive(a) {
		t.Fatal("the retry under the same bypasses killed, or said otherwise")
	}
	r.pf.set(func(f *fakePF) {
		f.main = mainWith([]string{"pass out quick on en0 all", "pass out quick on en1 all", `anchor "vpn" all`})
	})
	if apply("another quick pass above the hook") != said || alive(a) {
		t.Error("a second quick pass above the hook, said alike, didn't kill")
	}
	b := state()
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"pass out quick inet6 to 2001:db8:cd::/48"}})
	if apply("the earlier anchor's rules changed") != said || alive(b) {
		t.Error("an earlier anchor's rules changing under its name didn't kill")
	}
	// What the bypass is narrowed: pf's state policy is floating, so a
	// state made over en0 would outlive a call now only on en1.
	narrowed := []struct{ when, call string }{
		{"the call narrowed to an interface", `anchor "vpn" on en1 all`},
		{"the call made quick", `anchor "vpn" quick all`},
	}
	for _, n := range narrowed {
		s := state()
		r.pf.set(func(f *fakePF) {
			f.main = mainWith([]string{"pass out quick on en0 all", "pass out quick on en1 all", n.call})
		})
		if apply(n.when) != said || alive(s) {
			t.Errorf("%s didn't kill", n.when)
		}
	}
	s := state()
	r.pf.setAnchor("vpn", &fakeAnchor{rules: []string{"block out quick proto tcp all", "pass out quick inet6 to 2001:db8:cd::/48"}})
	if apply("a block above the pass") != said || alive(s) {
		t.Error("a block above the pass didn't kill")
	}
	c := state()
	r.pf.failOn("Interfaces", errFake)
	apply("pf unreadable")
	if alive(c) {
		t.Error("a check that couldn't read pf took the bypasses for the same")
	}
	// An anchor under com.apple before the guard's counts by its name; its
	// rules tell it from itself changed.
	r.pf.failOn("Interfaces", nil)
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	r.pf.setAnchor("com.apple/0.before", &fakeAnchor{rules: []string{"pass out quick inet6 to 2001:db8:ab::/48"}})
	said = apply("an anchor before ours")
	d := state()
	if apply("a retry") != said || !alive(d) {
		t.Fatal("the retry under the same anchor before ours killed, or said otherwise")
	}
	r.pf.setAnchor("com.apple/0.before", &fakeAnchor{rules: []string{"pass out quick inet6 to 2001:db8:cd::/48"}})
	if apply("its rules changed") != said || alive(d) {
		t.Error("the rules of an anchor before ours changing under its name didn't kill")
	}
}

func TestEndsEvaluation(t *testing.T) {
	for _, c := range []struct {
		rule          string
		inQuick, want bool
	}{
		{"pass out quick inet6 all", false, true},
		{"pass quick all", false, true},
		{"pass out inet6 all", false, false},
		{"pass out inet6 all", true, true},
		{"pass in inet6 all", true, false},
		{"pass out inet all", true, false},
		{"pass out inet6 all # inet", true, true},
		{"block return out quick inet6 all", true, false},
		{`anchor "vpn" quick all`, true, false},
		// The family comes before proto, from, to and all; the same word
		// after them is something else's (an unquoted tag).
		{"pass out quick all tag inet", false, true},
		{"pass out quick proto tcp from any to any tagged inet", false, true},
		{`pass out quick all label "inet"`, false, true},
		{"pass out quick inet all tag inet6", false, false},
		{"pass out quick on en0 inet6 proto udp all", false, true},
		// pfctl prints log options in parentheses before the family: a
		// `to` there is no address.
		{"pass out log (all, to pflog1) quick inet proto tcp all", false, false},
		{"pass out log (all, to pflog1) quick inet6 proto tcp all", false, true},
	} {
		if got := endsEvaluation(strings.Fields(c.rule), c.inQuick); got != c.want {
			t.Errorf("%q (in a quick anchor %v): %v", c.rule, c.inQuick, got)
		}
	}
}

func TestAnchorRule(t *testing.T) {
	for _, c := range []struct {
		line, name string
		rest       []string
		ok         bool
	}{
		{`anchor "vpn" all`, "vpn", []string{"all"}, true},
		{`anchor "com.apple/*" all`, "com.apple/*", []string{"all"}, true},
		{`anchor "a b" out quick on en0 inet6 all`, "a b", []string{"out", "quick", "on", "en0", "inet6", "all"}, true},
		{`anchor "../x/*"`, "../x/*", nil, true},
		{"anchor out all", "", []string{"out", "all"}, true},
		{"anchor", "", nil, true},
		{`anchor "unclosed all`, "", nil, true},
		// pfctl prints a `"` in a name as it is: the name can't be read.
		{`anchor "a"b" all`, "", nil, true},
		{`anchor "x" in "y" all`, "", nil, true},
		{`anchor "x"`, "x", nil, true},
		{`scrub-anchor "com.apple/*" all fragment reassemble`, "", nil, false},
		{`nat-anchor "vpn" all`, "", nil, false},
		{`anchors "vpn"`, "", nil, false},
		{"pass out quick all", "", nil, false},
	} {
		name, rest, ok := anchorRule(c.line)
		if name != c.name || !slices.Equal(rest, c.rest) || ok != c.ok {
			t.Errorf("%q: %q %q %v, want %q %q %v", c.line, name, rest, ok, c.name, c.rest, c.ok)
		}
	}
}

func TestResolveAnchor(t *testing.T) {
	for _, c := range []struct {
		base, name string
		want       anchorCall
		ok         bool
	}{
		{"", "vpn", anchorCall{"vpn", false}, true},
		{"", "com.apple/*", anchorCall{"com.apple", true}, true},
		{"vpn", "inner", anchorCall{"vpn/inner", false}, true},
		{"vpn", "*", anchorCall{"vpn", true}, true},
		{"vpn/a", "../b", anchorCall{"vpn/b", false}, true},
		{"vpn/a", "../../c/*", anchorCall{"c", true}, true},
		{"vpn", "/fw", anchorCall{"fw", false}, true},
		{"vpn", "/fw/*", anchorCall{"fw", true}, true},
		{"", "", anchorCall{}, false},
		{"vpn", "", anchorCall{}, false},
		{"", "*", anchorCall{}, false},
		{"", "/*", anchorCall{}, false},
		{"", "../x", anchorCall{}, false},
		{"vpn", "../../x", anchorCall{}, false},
		{"", "/", anchorCall{}, false},
		{"", "a//b", anchorCall{}, false},
		{"", "a/./b", anchorCall{}, false},
		{"vpn", "..", anchorCall{}, false},
		{"", "a/*/b", anchorCall{}, false},
		// pf names may hold a `*` (only a trailing `/*` is a wildcard),
		// but pfctl takes a trailing one off -a's name.
		{"", "vpn/a*", anchorCall{}, false},
		{"vpn", "a*", anchorCall{}, false},
		{"vpn", "/fw*/x", anchorCall{}, false},
		{"", "vpn*/*", anchorCall{}, false},
		{"", "a b", anchorCall{"a b", false}, true},
		// White space a listing's line ends in can't be told from the
		// name's.
		{"vpn", "/fw/a ", anchorCall{}, false},
		{"", "vpn/a\t/b", anchorCall{}, false},
		{"", "vpn/ a", anchorCall{"vpn/ a", false}, true},
	} {
		got, ok := resolveAnchor(c.base, c.name)
		if got != c.want || ok != c.ok {
			t.Errorf("%q in %q: %+v %v, want %+v %v", c.name, c.base, got, ok, c.want, c.ok)
		}
	}
}

// `-a PATH -s Anchors`: pfctl's answer for a missing anchor is no
// children whatever the exit status, but only that exact line, for that
// path, with nothing listed.
func TestChildAnchors(t *testing.T) {
	missing := altq + "Anchor 'vpn' not found.\n"
	for _, c := range []struct {
		stdout, stderr string
		runErr         error
		want           []string
		ok             bool
	}{
		{"  vpn/a\n  vpn/b\n", altq, nil, []string{"vpn/a", "vpn/b"}, true},
		{"", altq, nil, nil, true},
		{"", missing, nil, nil, true},
		{"", missing, errFake, nil, true},
		{"", "Anchor 'vpn' not found.", nil, nil, true},
		{"", "Anchor 'vpn/a' not found.\n", nil, nil, false},
		{"", "Anchor 'vpn' not found.\nAnchor 'vpn' not found.\n", nil, nil, false},
		{"", "pfctl: DIOCGETRULESETS: Invalid argument\n", errFake, nil, false},
		{"", "pfctl: DIOCGETRULESETS: Invalid argument\n", nil, nil, false},
		{"", "", errFake, nil, false},
		{"  vpn/a\n", missing, nil, nil, false},
		{"  vpn/a\n", "a warning\n", nil, nil, false},
		{"  vpn/a/b\n", "", nil, nil, false},
		{"  vpnx/a\n", "", nil, nil, false},
		{"  vpn/\n", "", nil, nil, false},
		{"  vpn/a" + strings.Repeat("x", 1<<20) + "\n", "", nil, nil, false},
		// Listed as they are, only pfctl's indent and the line's end off:
		// the walk judges a name it can't read.
		{"  vpn/a b\n  vpn/a*\n", "", nil, []string{"vpn/a b", "vpn/a*"}, true},
		{"  vpn/a \n  vpn/b\r\n", "", nil, []string{"vpn/a ", "vpn/b\r"}, true},
		{"vpn/a\n", "", nil, nil, false},
	} {
		got, err := childAnchors("vpn", pfOutput{stdout: []byte(c.stdout), stderr: []byte(c.stderr)}, c.runErr)
		if !slices.Equal(got, c.want) || (err == nil) != c.ok {
			t.Errorf("%.40q / %.60q / %v: %q, %v", c.stdout, c.stderr, c.runErr, got, err)
		}
	}
}

// What a stock Mac lists under com.apple (recorded) is read as its two
// anchors, as the walk reads a wildcard's children.
func TestChildAnchorsReadsTheRecordedListing(t *testing.T) {
	got, err := childAnchors(appleAnchor, pfOutput{stdout: fixture(t, "recorded-anchors-stock.txt"), stderr: []byte(altq)}, nil)
	if err != nil || !slices.Equal(got, stockApple) {
		t.Errorf("%q, %v, want %q", got, err, stockApple)
	}
}
