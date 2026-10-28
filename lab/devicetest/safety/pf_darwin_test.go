package safety

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// fakePf answers the core's pfctl and scutil commands from a model of pf,
// so the pf code runs in a test with no pfctl run. Loading a ruleset from
// stdin applies its `set skip on X` lines as the kernel does (a name
// ending in a letter is a prefix of names with a number after it, so `lo`
// skips lo0) and its other lines as the main rules; /etc/pf.conf's text
// (what the core appends) loads the stock rules. Loading /etc/pf.conf puts
// back its state, nothing skipped (unless sticky: a skip no reload
// clears), no nat rules. unlisted: `-s Interfaces -v` lists bare names,
// skipped or not, as a Mac did in the 2026-10-24 device run. calls
// records what ran.
type fakePf struct {
	mu       sync.Mutex
	ifaces   []string
	skip     []string
	sticky   bool
	unlisted bool
	rules    string
	nat      string
	airdrop  string
	debug    string
	enabled  bool
	// reloadRules, when set, is what loading /etc/pf.conf loads: a
	// pf.conf changed after it was last loaded.
	reloadRules string
	conf        string
	calls       []string
}

func newFakePf() *fakePf {
	conf, _ := os.ReadFile(pfConfPath)
	return &fakePf{ifaces: []string{"en0", "lo0", "utun3"}, rules: pfMainStock, debug: "Urgent", enabled: true, conf: string(conf)}
}

// skipped are the interfaces `set skip on name` flags, as the kernel
// matches them.
func (f *fakePf) skipped(name string) []string {
	var out []string
	prefix := name != "" && unicode.IsLetter(rune(name[len(name)-1]))
	for _, ifc := range f.ifaces {
		numbered := len(ifc) > len(name) && unicode.IsDigit(rune(ifc[len(name)]))
		if ifc == name || prefix && strings.HasPrefix(ifc, name) && numbered {
			out = append(out, ifc)
		}
	}
	return out
}

// load applies a ruleset given on stdin.
func (f *fakePf) load(text string) {
	f.skip, f.nat = nil, ""
	var rules []string
	rest := text
	for _, l := range strings.Split(text, "\n") {
		if name, found := strings.CutPrefix(l, "set skip on "); found {
			f.skip = append(f.skip, f.skipped(name)...)
			rest = strings.TrimPrefix(rest, l+"\n")
		} else if l != "" {
			rules = append(rules, l)
		}
	}
	if f.conf != "" && rest == f.conf {
		f.rules = pfMainStock
		return
	}
	f.rules = strings.Join(rules, "\n") + "\n"
}

func (f *fakePf) run(_ context.Context, argv []string, stdin []byte) output {
	f.mu.Lock()
	defer f.mu.Unlock()
	args := strings.Join(argv[1:], " ")
	f.calls = append(f.calls, args)
	ok := func(s string) output { return output{Stdout: []byte(s)} }
	switch args {
	case "-s info":
		if f.enabled {
			return ok("Status: Enabled for 0 days 00:00:01           Debug: " + f.debug + "\n")
		}
		return ok("Status: Disabled for 0 days 00:00:00           Debug: " + f.debug + "\n")
	case "-s rules":
		return ok(f.rules)
	case "-s nat":
		return ok(f.nat)
	case "-s Interfaces -v":
		var b strings.Builder
		for _, ifc := range f.ifaces {
			b.WriteString(ifc)
			if slices.Contains(f.skip, ifc) && !f.unlisted {
				b.WriteString(" (skip)")
			}
			b.WriteString("\n")
		}
		return ok(b.String())
	case "-s memory":
		return ok("states        hard limit    10000\nsrc-nodes     hard limit    10000\n")
	case "-s timeouts":
		return ok("tcp.first                   120s\ntcp.established           86400s\n")
	case "-a com.apple/200.AirDrop -s rules":
		return ok(f.airdrop)
	case "-a " + firewall.GuardAnchor + " -s rules":
		return output{Code: 1, Stderr: []byte("pfctl: DIOCGETRULES: Invalid argument\n")}
	case "-n -v -f " + pfConfPath:
		return ok(pfMainStock)
	case "-f -":
		f.load(string(stdin))
		return ok("")
	case "-f " + pfConfPath:
		if !f.sticky {
			f.skip = nil
		}
		f.rules, f.nat = pfMainStock, ""
		if f.reloadRules != "" {
			f.rules = f.reloadRules
		}
		return ok("")
	case "-e":
		f.enabled = true
		return ok("pf enabled\n")
	}
	return ok("") // the Application Firewall anchor, dummynet, references, anchors, scutil --dns
}

func (f *fakePf) ran(args string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, args)
}

func skipSpec(iface string) Spec {
	return Spec{Kind: kindPfSkip, Params: mustJSON(pfSkipAction{Iface: iface})}
}

// pfHost is a host over a run directory of the test's whose pf is pf, the
// baseline taken.
func pfHost(t *testing.T, pf *fakePf, boot, runBoot string) *host {
	t.Helper()
	h := &host{runDir: openDir(t, tempDir(t)), boot: boot, runBoot: runBoot, surfaces: surfaces(), exec: pf.run}
	var err error
	if h.baseline, err = h.snapshot(t.Context(), baselineName); err != nil {
		t.Fatal(err)
	}
	return h
}

// `set skip on lo` loaded (the kernel skips lo0), then undone by a plan's
// UndoLast, then the restore: pf is the baseline's again. The undo goes by
// the skipped interfaces, never by the name, which pf never lists.
func TestTP096sSkipOnLoIsUndoneThoughTheKernelListsLo0(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pf.skip, []string{"lo0"}) {
		t.Fatalf("the load skips %v", pf.skip)
	}
	if _, err := e.undoLast(t.Context()); err != nil || len(pf.skip) != 0 {
		t.Fatalf("UndoLast: %v, pf skips %v", err, pf.skip)
	}
	if en := e.entry(1); en.State != stateUndone {
		t.Errorf("journal: %+v", en)
	}
	if res := e.restore(t.Context(), "test"); res.Verdict != Clean {
		t.Errorf("restore: %+v", res)
	}
}

// journalSkipLoaded journals `set skip on lo` as a run's load leaves it:
// pf's rules and nat the baseline's, lo0 skipped.
func journalSkipLoaded(t *testing.T, j *journal, base *snapshot) {
	t.Helper()
	a := &pfSkipAction{Iface: "lo"}
	seq, err := j.intent(a, mustJSON(a))
	if err == nil {
		loaded := pfSkipAction{Iface: "lo", Loaded: true, Rules: base.Lines["pf-rules"], Nat: base.Lines["pf-nat"], Skips: []string{"lo0"}}
		err = j.mark(seq, stateApplied, mustJSON(loaded), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// The skip pending in a restore, as after a killed helper: the result says
// what the undo did.
func TestAPfSkipUndoSaysWhatItDid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skipped bool
		says    string
	}{{"the skip loaded", true, "loaded /etc/pf.conf"}, {"the skip gone already", false, "nothing to do"}} {
		pf := newFakePf()
		h := pfHost(t, pf, "boot-a", "boot-a")
		j, err := createJournal(h.runDir, "r", "boot-a")
		if err != nil {
			t.Fatal(err)
		}
		journalSkipLoaded(t, j, h.baseline)
		if tc.skipped {
			pf.skip = pf.skipped("lo")
		}
		res := (&engine{h: h, j: j, armed: refuseChanges}).restore(t.Context(), "test")
		if res.Verdict != Clean || len(res.Undone) != 1 || !strings.Contains(res.Undone[0], tc.says) || pf.ran("-f "+pfConfPath) != tc.skipped {
			t.Errorf("%s: %+v (%v)", tc.name, res, pf.calls)
		}
	}
}

// REBOOT means the core's own pf change survived its undo, nothing else:
// another app's rules after a run that changed no pf are LEFT; a skip
// that two loads of pf.conf don't clear is REBOOT.
func TestRebootIsOnlyTheCoresPfChangeSurvivingItsUndo(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	pf.rules = pfMainStock + "pass out quick on en0 all\n" // another app's
	if res := (&engine{h: h, j: j, armed: refuseChanges}).restore(t.Context(), "test"); res.Verdict != Left {
		t.Errorf("another app's rules, no pf change of the core's: %+v", res)
	}

	pf = newFakePf()
	h = pfHost(t, pf, "boot-a", "boot-a")
	if j, err = createJournal(h.runDir, "r", "boot-a"); err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err != nil {
		t.Fatal(err)
	}
	pf.sticky = true
	if res := e.restore(t.Context(), "test"); res.Verdict != Reboot || len(res.Failed) != 1 {
		t.Errorf("a skip two loads don't clear: %+v", res)
	}
}

// `set skip on lo` left pending: in its own boot, its undo loads pf.conf, and
// an AirDrop line changed meanwhile is LEFT with a reboot to do (the
// system's change); in a later boot, with the skip gone with that boot,
// the run is reset by the reboot and nothing is loaded; in a later boot
// with the skip still listed, it is LEFT, nothing loaded, never reset.
func TestAPfSkipRunIsLeftInItsOwnBootAndResetByALaterOne(t *testing.T) {
	for _, tc := range []struct {
		name, boot, want string
		stillSkipped     bool
		loaded           bool
	}{
		{"the run's own boot", "", Left, true, true},
		{"a later boot", "an-earlier-boot", ResetByReboot, false, false},
		{"a later boot, the skip still listed", "an-earlier-boot", Left, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := newFakePf()
			boot := tc.boot
			if boot == "" {
				boot = thisBoot(t)
			}
			f := newPendingRun(t, surfaces(), pf.run, boot)
			journalSkipLoaded(t, f.j, f.h.baseline)
			f.killed()
			if tc.stillSkipped {
				pf.skip = pf.skipped("lo")
			}
			if !tc.stillSkipped || tc.boot == "" {
				pf.airdrop = "pass in quick proto tcp from any to any port 8770\n"
			}
			pf.calls = nil
			res, err := f.restore()
			if err != nil || res.Verdict != tc.want {
				t.Fatalf("restore: %+v %v", res, err)
			}
			if pf.ran("-f "+pfConfPath) != tc.loaded || (f.pointer(leftFile) == "") != (tc.want == ResetByReboot) {
				t.Errorf("pf.conf loaded %v, left %q: %v", pf.ran("-f "+pfConfPath), f.pointer(leftFile), pf.calls)
			}
			if tc.want == Left && tc.boot == "" &&
				(len(res.Left) != 1 || res.Left[0].Surface != "pf-anchor-200.AirDrop" || !strings.Contains(res.Left[0].Next, "reboot")) {
				t.Errorf("left: %+v", res.Left)
			}
		})
	}
}

// pf goes back on only in the run's own boot: in a later one, its state
// is that boot's.
func TestPfIsTurnedBackOnOnlyInTheRunsBoot(t *testing.T) {
	for _, tc := range []struct {
		runBoot string
		on      bool
	}{{"boot-a", true}, {"an-earlier-boot", false}} {
		pf := newFakePf()
		pf.enabled = false
		h := &host{boot: "boot-a", runBoot: tc.runBoot, surfaces: surfaces(), exec: pf.run,
			baseline: &snapshot{Lines: map[string][]string{"pf-info": {"Status: Enabled"}}}}
		notes := pfBackOn(t.Context(), h)
		if pf.ran("-e") != tc.on || pf.enabled != tc.on {
			t.Errorf("run in %s: pfctl -e %v (%v)", tc.runBoot, pf.ran("-e"), notes)
		}
	}
}

// Another app's ruleset loaded after the run's (a kill switch that skips
// lo0 itself) is never wiped: the undo sees pf's rules aren't what the
// run's load left, loads nothing, and fails LEFT.
func TestThePfSkipUndoNeverWipesAnotherAppsRuleset(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err != nil {
		t.Fatal(err)
	}
	pf.run(t.Context(), []string{pfctlPath, "-f", "-"}, []byte("set skip on lo0\nblock drop out all\npass out quick on utun3 all\n"))
	pf.calls = nil
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || pf.ran("-f "+pfConfPath) || !strings.Contains(strings.Join(res.Failed, " "), "another ruleset was loaded since") {
		t.Errorf("restore: %+v (%v)", res, pf.calls)
	}
	if !strings.Contains(pf.rules, "pass out quick on utun3 all") {
		t.Errorf("the app's ruleset was replaced: %q", pf.rules)
	}
}

// pf's settings a load resets are compared (a change is LEFT), and an
// information-only listing that can't be read at either end is no item.
func TestWhatALoadResetsIsComparedAndAnUnreadableInfoListingIsNoItem(t *testing.T) {
	for _, tc := range []struct {
		name, args, stdout string
		debug              string
		left               string
	}{
		{"limits", "-s memory", "states        hard limit    20000\n", "", "pf-limits"},
		{"timeouts", "-s timeouts", "tcp.first                    30s\n", "", "pf-timeouts"},
		{"debug level", "", "", "Loud", "pf-info"},
		{"dummynet unreadable at both ends", "", "", "", ""},
	} {
		pf := newFakePf()
		dummynet := func(ctx context.Context, argv []string, stdin []byte) output {
			if strings.Join(argv[1:], " ") == "-s dummynet" {
				return output{Code: 1, Stderr: []byte("pfctl: Unknown show modifier 'dummynet'\n")}
			}
			return pf.run(ctx, argv, stdin)
		}
		h := &host{runDir: openDir(t, tempDir(t)), boot: "boot-a", runBoot: "boot-a", surfaces: surfaces(), exec: dummynet}
		var err error
		if h.baseline, err = h.snapshot(t.Context(), baselineName); err != nil {
			t.Fatal(err)
		}
		j, err := createJournal(h.runDir, "r", "boot-a")
		if err != nil {
			t.Fatal(err)
		}
		if tc.debug != "" {
			pf.debug = tc.debug
		}
		if tc.args != "" {
			h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
				if strings.Join(argv[1:], " ") == tc.args {
					return output{Stdout: []byte(tc.stdout)}
				}
				return dummynet(ctx, argv, stdin)
			}
		}
		res := (&engine{h: h, j: j, armed: refuseChanges}).restore(t.Context(), "test")
		switch {
		case tc.left == "" && (res.Verdict != Clean || len(res.Info) != 0):
			t.Errorf("%s: %+v", tc.name, res)
		case tc.left != "" && (res.Verdict != Left || len(res.Left) != 1 || res.Left[0].Surface != tc.left):
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
}

// After the loads the skip is gone but pf's rules differ (a pf.conf
// changed since it was last loaded): LEFT, saying which, never REBOOT.
func TestASkipGoneButRulesDifferAfterTheLoadsIsLeft(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err != nil {
		t.Fatal(err)
	}
	pf.reloadRules = pfMainStock + "pass in quick on en0 proto tcp to any port 22\n"
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || len(pf.skip) != 0 || !strings.Contains(strings.Join(res.Failed, " "), "the skip is gone, but [pf-rules] differ") {
		t.Errorf("%+v", res)
	}
}

// skipRun is a TP-096 run whose `set skip on lo` has loaded through the
// engine, over pf.
func skipRun(t *testing.T, pf *fakePf) *engine {
	t.Helper()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err != nil {
		t.Fatal(err)
	}
	return e
}

// Another app's ruleset loaded after the run's with the same rules and nat
// but a skip of its own is never wiped either: the undo compares pf's
// skipped interfaces with what the run's load left too.
func TestThePfSkipUndoNeverWipesAnotherAppsSkip(t *testing.T) {
	pf := newFakePf()
	e := skipRun(t, pf)
	pf.run(t.Context(), []string{pfctlPath, "-f", "-"}, []byte("set skip on lo\nset skip on utun3\n"+pf.conf))
	pf.calls = nil
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || pf.ran("-f "+pfConfPath) || !strings.Contains(strings.Join(res.Failed, " "), "another ruleset was loaded since") {
		t.Errorf("restore: %+v (%v)", res, pf.calls)
	}
	if !slices.Equal(pf.skip, []string{"lo0", "utun3"}) {
		t.Errorf("the app's skips were replaced: %v", pf.skip)
	}
}

// Another app's nat rules loaded after the run's, its main rules the
// same: nothing is loaded, LEFT, the app's nat kept.
func TestThePfSkipUndoNeverWipesAnotherAppsNat(t *testing.T) {
	pf := newFakePf()
	e := skipRun(t, pf)
	pf.nat = "nat on en0 inet from 192.0.2.0/24 to any -> (en0)\n"
	pf.calls = nil
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || pf.ran("-f "+pfConfPath) || !strings.Contains(strings.Join(res.Failed, " "), "another ruleset was loaded since") {
		t.Errorf("restore: %+v (%v)", res, pf.calls)
	}
	if pf.nat == "" {
		t.Error("the app's nat rules were replaced")
	}
}

// The load may have run but what it left was never journaled (the helper
// died, or reading pf after it failed): the undo loads nothing and fails
// LEFT, skip listed or not, since nothing tells this run's ruleset from
// another app's.
func TestALoadNeverJournaledIsLeftAndNothingLoaded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skipped bool
	}{{"the helper died after the load", true}, {"the helper died, nothing listed as skipped", false}} {
		pf := newFakePf()
		h := pfHost(t, pf, "boot-a", "boot-a")
		j, err := createJournal(h.runDir, "r", "boot-a")
		if err != nil {
			t.Fatal(err)
		}
		a := &pfSkipAction{Iface: "lo"}
		if _, err := j.intent(a, mustJSON(a)); err != nil {
			t.Fatal(err)
		}
		if tc.skipped {
			pf.skip = pf.skipped("lo")
		}
		res := (&engine{h: h, j: j, armed: refuseChanges}).restore(t.Context(), "test")
		if res.Verdict != Left || pf.ran("-f "+pfConfPath) || !strings.Contains(strings.Join(res.Failed, " "), "never journaled") {
			t.Errorf("%s: %+v (%v)", tc.name, res, pf.calls)
		}
	}

	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		if strings.Join(argv[1:], " ") == "-s nat" && pf.ran("-f -") {
			return output{Code: 1, Stderr: []byte("pfctl: DIOCGETRULES: Device busy\n")}
		}
		return pf.run(ctx, argv, stdin)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err == nil || !strings.Contains(err.Error(), "never journaled") || pf.ran("-f "+pfConfPath) {
		t.Errorf("reading pf after the load failed: %v (%v)", err, pf.calls)
	}
	// The restore's LEFT names that cause, not a stopped helper.
	res := e.restore(t.Context(), "test")
	failed := strings.Join(res.Failed, " ")
	if res.Verdict != Left || pf.ran("-f "+pfConfPath) ||
		!strings.Contains(failed, "never journaled (reading pf after the load failed: ") ||
		!strings.Contains(failed, "DIOCGETRULES: Device busy") || strings.Contains(failed, "helper stopped") {
		t.Errorf("restore after reading pf failed: %+v (%v)", res, pf.calls)
	}
}

// A Mac whose pfctl lists no skip even right after the load (the
// 2026-10-24 device run's listing): the undo can't show the skip gone, so
// UndoLast loads pf.conf once and fails, and the restore is LEFT, never
// CLEAN.
func TestASkipPfNeverListsIsLeftNeverClean(t *testing.T) {
	pf := newFakePf()
	pf.unlisted = true
	e := skipRun(t, pf)
	pf.calls = nil
	if _, err := e.undoLast(t.Context()); err == nil || !strings.Contains(err.Error(), "listed no skipped interface") || !pf.ran("-f "+pfConfPath) {
		t.Errorf("UndoLast: %v (%v)", err, pf.calls)
	}
	if res := e.restore(t.Context(), "test"); res.Verdict != Left {
		t.Errorf("restore: %+v", res)
	}
}

// The decision after the second load comes from the read right after it:
// a skip that read shows is a REBOOT naming it, even if a later read
// wouldn't show it.
func TestTheReadAfterTheSecondLoadDecides(t *testing.T) {
	pf := newFakePf()
	e := skipRun(t, pf)
	pf.sticky = true
	loads, listed := 0, 0
	e.h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		switch strings.Join(argv[1:], " ") {
		case "-f " + pfConfPath:
			if loads++; loads == 2 {
				pf.sticky = false
			}
		case "-s Interfaces -v":
			if loads == 2 {
				if listed++; listed == 1 {
					return output{Stdout: []byte("en0\nlo0 (skip)\nutun3\n")}
				}
			}
		}
		return pf.run(ctx, argv, stdin)
	}
	res := e.restore(t.Context(), "test")
	if res.Verdict != Reboot || len(res.Failed) != 1 || !strings.Contains(res.Failed[0], "[pf-skip]") {
		t.Errorf("%+v", res)
	}
}

// Another app loads its ruleset between the undo's first load of pf.conf
// and the read after it, the skip gone: the undo loads no second time
// (that could only wipe the app's ruleset), and fails LEFT. When the
// app's ruleset carries a skip of its own as well (a kill switch's `set
// skip on utun3`), rules and skip both differ: still one load, and the
// verdict is REBOOT, the app's rules and skip kept.
func TestTheUndoLoadsASecondTimeOnlyForTheSkipAlone(t *testing.T) {
	pf := newFakePf()
	e := skipRun(t, pf)
	loads := 0
	e.h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		out := pf.run(ctx, argv, stdin)
		if strings.Join(argv[1:], " ") == "-f "+pfConfPath {
			if loads++; loads == 1 {
				pf.run(ctx, []string{pfctlPath, "-f", "-"}, []byte("block drop out all\npass out quick on utun3 all\n"))
			}
		}
		return out
	}
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || loads != 1 || !strings.Contains(strings.Join(res.Failed, " "), "the skip is gone, but [pf-rules] differ") {
		t.Errorf("%d loads: %+v", loads, res)
	}
	if !strings.Contains(pf.rules, "pass out quick on utun3 all") {
		t.Errorf("the app's ruleset was replaced: %q", pf.rules)
	}

	// Rules and skip both differ after the first load.
	pf = newFakePf()
	e = skipRun(t, pf)
	loads = 0
	e.h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		out := pf.run(ctx, argv, stdin)
		if strings.Join(argv[1:], " ") == "-f "+pfConfPath {
			if loads++; loads == 1 {
				pf.run(ctx, []string{pfctlPath, "-f", "-"}, []byte("set skip on utun3\nblock drop out all\npass out quick on utun3 all\n"))
			}
		}
		return out
	}
	res = e.restore(t.Context(), "test")
	if res.Verdict != Reboot || loads != 1 || !strings.Contains(strings.Join(res.Failed, " "), "[pf-rules pf-skip]") {
		t.Errorf("rules and skip after one load: %d loads: %+v", loads, res)
	}
	if !strings.Contains(pf.rules, "pass out quick on utun3 all") || !slices.Equal(pf.skip, []string{"utun3"}) {
		t.Errorf("the app's ruleset was replaced: rules %q, skip %v", pf.rules, pf.skip)
	}

	// The skip alone survives the first load: the second clears it.
	pf = newFakePf()
	e = skipRun(t, pf)
	pf.sticky, loads = true, 0
	e.h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		out := pf.run(ctx, argv, stdin)
		if strings.Join(argv[1:], " ") == "-f "+pfConfPath {
			loads++
			pf.sticky = false
		}
		return out
	}
	if res := e.restore(t.Context(), "test"); res.Verdict != Clean || loads != 2 {
		t.Errorf("the skip alone after one load: %d loads: %+v", loads, res)
	}
}

// The run's load fails (pfctl -f - exits non-zero): the undo loads
// nothing and fails LEFT, and the restore's LEFT names that cause, not a
// stopped helper.
func TestAFailedLoadIsLeftNamingItsCause(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		if strings.Join(argv[1:], " ") == "-f -" {
			return output{Code: 1, Stderr: []byte("pfctl: DIOCXCOMMIT: Device busy\n")}
		}
		return pf.run(ctx, argv, stdin)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), skipSpec("lo")); err == nil {
		t.Fatal("a failed load succeeded")
	}
	res := e.restore(t.Context(), "test")
	failed := strings.Join(res.Failed, " ")
	if res.Verdict != Left || pf.ran("-f "+pfConfPath) ||
		!strings.Contains(failed, "never journaled (the load failed: pfctl -f -: exit 1: pfctl: DIOCXCOMMIT: Device busy)") ||
		strings.Contains(failed, "helper stopped") {
		t.Errorf("restore: %+v (%v)", res, pf.calls)
	}
}

// A Mac whose pfctl lists no skip, across a reboot: in the run's boot the
// undo can't show the skip gone (LEFT); after the reboot, the skips are
// the baseline's (as they always look there), so the change went with its
// boot, nothing is loaded, and the run is reset by the reboot, not left
// for -forget.
func TestASkipPfNeverListsIsResetByTheReboot(t *testing.T) {
	pf := newFakePf()
	pf.unlisted = true
	f := newPendingRun(t, surfaces(), pf.run, "an-earlier-boot")
	f.do(skipSpec("lo"))
	if _, err := (&engine{h: f.h, j: f.j, armed: isArmed}).undoLast(t.Context()); err == nil || !strings.Contains(err.Error(), "listed no skipped interface") {
		t.Fatalf("UndoLast in the run's boot: %v", err)
	}
	f.killed()
	pf.skip = nil                                                      // the reboot
	pf.airdrop = "pass in quick proto tcp from any to any port 8770\n" // the new boot's
	pf.calls = nil
	res, err := f.restore()
	if err != nil || res.Verdict != ResetByReboot || f.pointer(leftFile) != "" {
		t.Fatalf("restore after the reboot: %+v %v, left %q", res, err, f.pointer(leftFile))
	}
	if pf.ran("-f "+pfConfPath) || pf.ran("-f -") || len(res.GoneWithReboot) != 1 {
		t.Errorf("after the reboot: %+v (%v)", res, pf.calls)
	}
}

// A spec naming what only apply learns (a load's outcome, or why it
// failed) is refused before anything loads.
func TestASpecNamingALoadsOutcomeIsRefused(t *testing.T) {
	for _, a := range []pfSkipAction{{Iface: "lo", Loaded: true}, {Iface: "lo", Failed: "the load failed"}} {
		pf := newFakePf()
		h := pfHost(t, pf, "boot-a", "boot-a")
		j, err := createJournal(h.runDir, "r", "boot-a")
		if err != nil {
			t.Fatal(err)
		}
		_, err = (&engine{h: h, j: j, armed: isArmed}).do(t.Context(), Spec{Kind: kindPfSkip, Params: mustJSON(a)})
		if err == nil || !strings.Contains(err.Error(), "names no loaded rules") || pf.ran("-f -") {
			t.Errorf("%+v: %v (%v)", a, err, pf.calls)
		}
	}
}
