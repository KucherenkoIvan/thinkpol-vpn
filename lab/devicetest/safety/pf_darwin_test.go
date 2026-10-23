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
// clears). calls records what ran.
type fakePf struct {
	mu      sync.Mutex
	ifaces  []string
	skip    []string
	sticky  bool
	rules   string
	airdrop string
	debug   string
	enabled bool
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
	f.skip = nil
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
	case "-s Interfaces -v":
		var b strings.Builder
		for _, ifc := range f.ifaces {
			b.WriteString(ifc)
			if slices.Contains(f.skip, ifc) {
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
		f.rules = pfMainStock
		if f.reloadRules != "" {
			f.rules = f.reloadRules
		}
		return ok("")
	case "-e":
		f.enabled = true
		return ok("pf enabled\n")
	}
	return ok("") // nat, the Application Firewall anchor, dummynet, references, anchors, scutil --dns
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
	if err := e.undoLast(t.Context()); err != nil || len(pf.skip) != 0 {
		t.Fatalf("UndoLast: %v, pf skips %v", err, pf.skip)
	}
	if en := e.entry(1); en.State != stateUndone {
		t.Errorf("journal: %+v", en)
	}
	if res := e.restore(t.Context(), "test"); res.Verdict != Clean {
		t.Errorf("restore: %+v", res)
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
		a := &pfSkipAction{Iface: "lo"}
		seq, err := j.intent(a, mustJSON(a))
		if err == nil {
			err = j.mark(seq, stateApplied, nil, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
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
			a := &pfSkipAction{Iface: "lo"}
			seq, err := f.j.intent(a, mustJSON(a))
			if err == nil {
				err = f.j.mark(seq, stateApplied, nil, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
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

// pf's limits and timeouts are compared: loading a ruleset replaces them,
// so an app's `set limit` dropped by the load is left over, not CLEAN.
func TestPfLimitsAndTimeoutsAreCompared(t *testing.T) {
	pf := newFakePf()
	h := pfHost(t, pf, "boot-a", "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	h.exec = func(ctx context.Context, argv []string, stdin []byte) output {
		if strings.Join(argv[1:], " ") == "-s memory" {
			return output{Stdout: []byte("states        hard limit    20000\n")}
		}
		return pf.run(ctx, argv, stdin)
	}
	res := (&engine{h: h, j: j, armed: refuseChanges}).restore(t.Context(), "test")
	if res.Verdict != Left || len(res.Left) != 1 || res.Left[0].Surface != "pf-limits" {
		t.Errorf("%+v", res)
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
