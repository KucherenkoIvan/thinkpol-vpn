package safety

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// fakePf answers the core's pfctl and scutil commands from a model of pf,
// so the pf code runs in a test with no pfctl run: loading /etc/pf.conf
// drops every skip, `-e` turns pf on, and calls records what ran.
type fakePf struct {
	mu      sync.Mutex
	skip    []string
	airdrop string
	enabled bool
	calls   []string
}

func (f *fakePf) run(_ context.Context, argv []string, _ []byte) output {
	f.mu.Lock()
	defer f.mu.Unlock()
	args := strings.Join(argv[1:], " ")
	f.calls = append(f.calls, args)
	ok := func(s string) output { return output{Stdout: []byte(s)} }
	switch args {
	case "-s info":
		if f.enabled {
			return ok("Status: Enabled for 0 days 00:00:01           Debug: Urgent\n")
		}
		return ok("Status: Disabled for 0 days 00:00:00           Debug: Urgent\n")
	case "-s rules":
		return ok(pfMainStock)
	case "-s Interfaces -v":
		s := "en0\nlo0\n"
		for _, n := range f.skip {
			s += n + " (skip)\n"
		}
		return ok(s)
	case "-a com.apple/200.AirDrop -s rules":
		return ok(f.airdrop)
	case "-a " + firewall.GuardAnchor + " -s rules":
		return output{Code: 1, Stderr: []byte("pfctl: DIOCGETRULES: Invalid argument\n")}
	case "-f " + pfConfPath:
		f.skip = nil
		return ok("")
	case "-e":
		f.enabled = true
		return ok("pf enabled\n")
	}
	return ok("") // nat, the Application Firewall anchor, references, anchors, scutil --dns
}

func (f *fakePf) ran(args string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, args)
}

func skipSpec(iface string) Spec {
	return Spec{Kind: kindPfSkip, Params: mustJSON(pfSkipAction{Iface: iface})}
}

// TP-096's skip, left pending: in its own boot an AirDrop line that
// changed meanwhile is LEFT with a reboot to do (the system's change, not
// the core's); in a later boot, with the skip gone with that boot, the
// run is reset by the reboot, and nothing is loaded or turned on.
func TestAPfSkipRunPendingInAnEarlierBootIsResetByTheReboot(t *testing.T) {
	for _, tc := range []struct {
		name, boot, want string
	}{{"the run's own boot", "", Left}, {"a later boot", "an-earlier-boot", ResetByReboot}} {
		t.Run(tc.name, func(t *testing.T) {
			pf := &fakePf{enabled: true}
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
			pf.airdrop = "pass in quick proto tcp from any to any port 8770\n"
			if tc.boot == "" {
				pf.skip = []string{"lo"}
			}
			pf.calls = nil
			res, err := f.restore()
			if err != nil || res.Verdict != tc.want {
				t.Fatalf("restore: %+v %v", res, err)
			}
			if len(res.Left) != 1 || res.Left[0].Surface != "pf-anchor-200.AirDrop" || !strings.Contains(res.Left[0].Next, "reboot") {
				t.Errorf("left: %+v", res.Left)
			}
			if own := tc.boot == ""; pf.ran("-f "+pfConfPath) != own || (f.pointer(leftFile) == "") == own {
				t.Errorf("pf.conf loaded %v, left %q: %v", pf.ran("-f "+pfConfPath), f.pointer(leftFile), pf.calls)
			}
		})
	}
}

// The skip's undo loads /etc/pf.conf only while its own skip is there:
// once a reboot or another app took it, loading pf.conf would replace
// what was loaded since.
func TestThePfSkipUndoReloadsOnlyWhileItsSkipIsThere(t *testing.T) {
	pf := &fakePf{}
	h := &host{surfaces: surfaces(), exec: pf.run}
	var err error
	if h.baseline, err = h.snapshot0(t); err != nil {
		t.Fatal(err)
	}
	a, err := decode(skipSpec("lo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.undo(t.Context(), h); err != nil || pf.ran("-f "+pfConfPath) {
		t.Errorf("undo with the skip gone: %v %v", err, pf.calls)
	}
	pf.skip = []string{"lo"}
	if err := a.undo(t.Context(), h); err != nil || !pf.ran("-f "+pfConfPath) || len(pf.skip) != 0 {
		t.Errorf("undo with the skip there: %v %v", err, pf.calls)
	}
}

// snapshot0 is the host's surfaces now, as a baseline, without a run
// directory.
func (h *host) snapshot0(t *testing.T) (*snapshot, error) {
	t.Helper()
	s := &snapshot{Lines: map[string][]string{}}
	for _, sf := range h.surfaceList() {
		if sf.norm == nil {
			continue
		}
		lines, err := h.readSurface(t.Context(), sf.name)
		if err != nil {
			return nil, err
		}
		s.Lines[sf.name] = lines
	}
	return s, nil
}

// pf goes back on only in the run's own boot: in a later one, its state
// is that boot's.
func TestPfIsTurnedBackOnOnlyInTheRunsBoot(t *testing.T) {
	for _, tc := range []struct {
		runBoot string
		on      bool
	}{{"boot-a", true}, {"an-earlier-boot", false}} {
		pf := &fakePf{}
		h := &host{boot: "boot-a", runBoot: tc.runBoot, surfaces: surfaces(), exec: pf.run,
			baseline: &snapshot{Lines: map[string][]string{"pf-info": {"Status: Enabled"}}}}
		notes := pfBackOn(t.Context(), h)
		if pf.ran("-e") != tc.on || pf.enabled != tc.on {
			t.Errorf("run in %s: pfctl -e %v (%v)", tc.runBoot, pf.ran("-e"), notes)
		}
	}
}
