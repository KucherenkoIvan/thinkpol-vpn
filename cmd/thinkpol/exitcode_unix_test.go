//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
)

// exitNode is a device with status st whose every change fails with err
// (nil: succeeds). Each change it is asked for counts in exitNodeChanges.
type exitNode struct {
	st  agent.Status
	err error
}

// exitNodeChanges counts the changes any exitNode was asked for: a row
// that moves it ran a command that changes the node.
var exitNodeChanges atomic.Int64

func (n *exitNode) change() error { exitNodeChanges.Add(1); return n.err }

func (n *exitNode) Status() agent.Status                        { return n.st }
func (n *exitNode) Connect(context.Context) error               { return n.change() }
func (n *exitNode) Disconnect(context.Context) error            { return n.change() }
func (n *exitNode) SetRulePreset(context.Context, string) error { return n.change() }
func (n *exitNode) SetConnectOnBoot(bool) error                 { return n.change() }
func (n *exitNode) SetKillSwitch(context.Context, bool) error   { return n.change() }
func (n *exitNode) SetAllowLAN(context.Context, bool) error     { return n.change() }
func (n *exitNode) Diagnose(context.Context, bool) agent.Diagnostics {
	return agent.Diagnostics{Status: n.st}
}

// failingMembership is an OS whose group lookups fail with err.
type failingMembership struct{ err error }

func (m failingMembership) IsMember(context.Context, uint32, uint32) (bool, error) {
	return false, m.err
}

// exitRow is one command line and the code it exits with; stdout and
// stderr, when set, are patterns its output must match. A failure with
// no stdout pattern prints nothing to stdout. outcome marks a change
// that fails after reaching the node, which prints the status.
type exitRow struct {
	name           string
	args           []string
	code           int
	stdout, stderr string
	outcome        bool
}

// partial is a change the node took and failed at, or did in part: the
// node's error, the API's code for it, and the status the node is left
// with, which the command prints (stdout, the pattern; "" for the
// connected status).
type partial struct {
	err    error
	code   string
	st     *agent.KillSwitchStatus
	stdout string
}

// apiCommandLine is a local API command: its path, then its values, and,
// for a change, how the node fails it. A root-only call is refused by
// who the caller is alone: no group is asked.
type apiCommandLine struct {
	path, values []string
	partials     []partial
	rootOnly     bool
}

// Every command exits by sysexits (docs/design/api-overview.md,
// "Verdicts"), in each case that applies to it: success 0, bad arguments
// 64, a missing input 66, the service down 69, busy 75, permission denied
// 77, a bad configuration 78, and 1, printing the status, when the state
// wasn't reached or was in part (a kill switch toggle kept while the
// kill switch isn't enforced among them). Every visible command has rows
// here, and every command that changes the node has a row where the
// change fails at the node and the status is printed.
func TestEveryCommandExitsBySysexits(t *testing.T) {
	unsetTHINKPOL(t)
	keepUpGlobals(t)
	root := os.Geteuid() == 0
	me := uint32(os.Geteuid())
	device := connectedDevice(t).st
	socket := func(err error, ks *agent.KillSwitchStatus) string {
		st := device
		if ks != nil {
			st.KillSwitch = *ks
		}
		return serveAPI(t, &exitNode{st: st, err: err}, localapi.Policy{ServiceUID: me})
	}
	ok := socket(nil, nil)
	denied := serveAPI(t, &exitNode{st: device}, localapi.Policy{ServiceUID: me + 1})
	// A group none of this process's groups is: the OS is asked, and
	// doesn't answer in time, or fails.
	group := func(m localapi.Membership) string {
		return serveAPI(t, &exitNode{st: device}, localapi.Policy{ServiceUID: me + 1, Group: 4242, HasGroup: true, Membership: m})
	}
	membershipTimedOut := group(failingMembership{fmt.Errorf("no answer within 3s: %w", context.DeadlineExceeded)})
	membershipFailed := group(failingMembership{errors.New("dsmemberutil: exit status 1")})
	const down = "/nonexistent/thinkpol-api/api.sock"
	const status = `state: +connected`
	applyFailed := &agent.KillSwitchStatus{On: true, Active: true, Error: agent.KillSwitchApplyFailed}
	removeFailed := &agent.KillSwitchStatus{Error: agent.KillSwitchRemoveFailed}
	notEnforced := func(reason agent.KillSwitchError, st *agent.KillSwitchStatus) partial {
		return partial{&agent.KillSwitchNotEnforcedError{Reason: reason}, "kill_switch_not_enforced", st, `kill switch: .*\(not enforced: ` + string(reason)}
	}
	serverMode := partial{err: agent.ErrServerMode, code: "server_mode"}

	var rows []exitRow
	for _, c := range []apiCommandLine{
		{path: []string{"status"}},
		{path: []string{"spaces"}},
		{path: []string{"logs"}, rootOnly: true},
		{path: []string{"diag"}},
		{path: []string{"kill-switch"}},
		{path: []string{"allow-lan"}},
		{path: []string{"connect-on-boot"}},
		{path: []string{"connect"}, partials: []partial{{err: agent.ErrDNSUnprotected, code: "dns_not_protected"}}},
		{path: []string{"disconnect"}, partials: []partial{serverMode}},
		{path: []string{"kill-switch"}, values: []string{"on"}, partials: []partial{serverMode, notEnforced(agent.KillSwitchApplyFailed, applyFailed)}},
		{path: []string{"kill-switch"}, values: []string{"off"}, partials: []partial{notEnforced(agent.KillSwitchRemoveFailed, removeFailed)}},
		{path: []string{"allow-lan"}, values: []string{"off"}, partials: []partial{serverMode, notEnforced(agent.KillSwitchApplyFailed, applyFailed)}},
		{path: []string{"connect-on-boot"}, values: []string{"on"}, partials: []partial{serverMode}},
		{path: []string{"rules", "preset"}, values: []string{"everything"}, partials: []partial{
			{err: agent.ErrPresetUnavailable, code: "rule_preset_unavailable"},
			{err: fmt.Errorf("%w: laying out failed", agent.ErrPresetNotEnforced), code: "rule_preset_not_enforced"},
			{err: fmt.Errorf("%w: laying out failed", agent.ErrPresetIncomplete), code: "rule_preset_incomplete"},
		}},
	} {
		line := func(flags ...string) []string { return slices.Concat(c.path, flags, c.values) }
		name := strings.Join(line(), " ")
		rows = append(rows,
			exitRow{name: name + ": success", args: line("-socket", ok), code: exitOK},
			exitRow{name: name + ": bad arguments", args: line("-socket", ok, "-bogus"), code: exitUsage, stderr: "flag provided but not defined"},
			exitRow{name: name + ": service down", args: line("-socket", down), code: exitUnavailable, stderr: `\[service_down\]`},
		)
		// Root may always call: no group is asked, nothing refused.
		if !root {
			refused := "permission_denied"
			if c.rootOnly {
				refused = "root_only"
			} else {
				rows = append(rows,
					exitRow{name: name + ": membership unknown, try again", args: line("-socket", membershipTimedOut), code: exitTempFail, stderr: `\[membership_unknown\]`},
					exitRow{name: name + ": membership check failed", args: line("-socket", membershipFailed), code: exitFailure, stderr: `\[membership_check_failed\]`},
				)
			}
			rows = append(rows, exitRow{name: name + ": permission denied", args: line("-socket", denied), code: exitNoPerm, stderr: `\[` + refused + `\]`})
		}
		if len(c.partials) > 0 {
			rows = append(rows, exitRow{name: name + ": node not running", args: line("-socket", socket(agent.ErrNotRunning, nil)), code: exitUnavailable, stderr: `\[not_running\]`})
		}
		for _, p := range c.partials {
			out := status
			if p.stdout != "" {
				out = p.stdout
			}
			rows = append(rows, exitRow{name: name + ": not reached, or in part: " + p.code, args: line("-socket", socket(p.err, p.st)), code: exitFailure, stdout: out, stderr: `\[` + p.code + `\]`, outcome: true})
		}
	}
	rows = append(rows, exitRow{name: "rules preset: no such preset", args: []string{"rules", "preset", "-socket", socket(agent.ErrUnknownPreset, nil), "sometimes"}, code: exitUsage, stderr: `\[unknown_rule_preset\]`})

	state, keys := m0State(t, "device-a")
	dir := tempDir(t)
	spec, mapFile, missing := "../../lab/maps/m0.yaml", filepath.Join(dir, "map.bin"), filepath.Join(dir, "missing.csv")
	noMap := tempDir(t)
	for _, name := range []string{agent.NodeKeyFile, agent.TrustFile} {
		if err := os.WriteFile(filepath.Join(noMap, name), readTestFile(t, filepath.Join(state, name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Key directories that lack one file each: a file directly in a named
	// directory is a named input, whichever it is.
	without := func(file string) string {
		d := tempDir(t)
		entries, err := os.ReadDir(keys)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if e.Name() != file {
				if err := os.WriteFile(filepath.Join(d, e.Name()), readTestFile(t, filepath.Join(keys, e.Name())), info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
			}
		}
		return d
	}
	source := filepath.Join(dir, "dbip.csv")
	if err := os.WriteFile(source, []byte(dbipFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	rows = append(rows,
		exitRow{name: "no command", args: nil, code: exitUsage},
		exitRow{name: "unknown command", args: []string{"nope"}, code: exitUsage},
		exitRow{name: "help", args: []string{"help"}, code: exitOK},
		exitRow{name: "version: success", args: []string{"version"}, code: exitOK},
		exitRow{name: "version: bad arguments", args: []string{"version", "now"}, code: exitUsage},
		exitRow{name: "up: help", args: []string{"up", "-h"}, code: exitOK},
		exitRow{name: "up: bad arguments", args: []string{"up", "-state", state, "now"}, code: exitUsage},
		exitRow{name: "up: bad configuration", args: []string{"up", "-state", state, "-mode", "auto"}, code: exitConfig},
		exitRow{name: "up: missing map", args: []string{"up", "-state", noMap}, code: exitNoInput},
		exitRow{name: "up: missing state directory", args: []string{"up", "-state", filepath.Join(dir, "nostate")}, code: exitNoInput},
		exitRow{name: "rollback: bad arguments", args: []string{"rollback", "now"}, code: exitUsage},
		exitRow{name: "service install: bad arguments", args: []string{"service", "install", "now"}, code: exitUsage},
		exitRow{name: "service install: a removed flag", args: []string{"service", "install", "-connect-on-boot", "on"}, code: exitUsage, stderr: `thinkpol connect-on-boot \[on\|off\]`},
		exitRow{name: "service uninstall: bad arguments", args: []string{"service", "uninstall", "now"}, code: exitUsage},
		exitRow{name: "service connect-on-boot: removed", args: []string{"service", "connect-on-boot", "on"}, code: exitUsage, stderr: `thinkpol connect-on-boot \[on\|off\]`},
		exitRow{name: "dev keygen space: success", args: []string{"dev", "keygen", "space", "-out", filepath.Join(dir, "keys")}, code: exitOK},
		exitRow{name: "dev keygen space: bad arguments", args: []string{"dev", "keygen", "space", "now"}, code: exitUsage},
		exitRow{name: "dev keygen node: success", args: []string{"dev", "keygen", "node", "-out", filepath.Join(dir, "keys"), "device-c"}, code: exitOK},
		exitRow{name: "dev keygen node: bad arguments", args: []string{"dev", "keygen", "node"}, code: exitUsage},
		exitRow{name: "dev map build: success", args: []string{"dev", "map", "build", "-keys", keys, "-out", mapFile, spec}, code: exitOK},
		exitRow{name: "dev map build: bad arguments", args: []string{"dev", "map", "build", "-keys", keys}, code: exitUsage},
		exitRow{name: "dev map build: missing spec", args: []string{"dev", "map", "build", "-keys", keys, "-out", mapFile, missing}, code: exitNoInput},
		exitRow{name: "dev map build: missing key directory", args: []string{"dev", "map", "build", "-keys", filepath.Join(dir, "nokeys"), "-out", mapFile, spec}, code: exitNoInput},
		exitRow{name: "dev map build: missing space key", args: []string{"dev", "map", "build", "-keys", without(devmap.SpaceKeyFile), "-out", mapFile, spec}, code: exitNoInput},
		exitRow{name: "dev map build: missing node key", args: []string{"dev", "map", "build", "-keys", without(devmap.NodePublicFile("device-b")), "-out", mapFile, spec}, code: exitNoInput},
		exitRow{name: "dev map build: missing output directory", args: []string{"dev", "map", "build", "-keys", keys, "-out", filepath.Join(dir, "nodir", "map.bin"), spec}, code: exitFailure},
		exitRow{name: "dev map rotate: success", args: []string{"dev", "map", "rotate", "-keys", keys, "-out", mapFile, spec}, code: exitOK},
		exitRow{name: "dev map rotate: bad arguments", args: []string{"dev", "map", "rotate", "-keys", keys}, code: exitUsage},
		exitRow{name: "dev map rotate: missing map", args: []string{"dev", "map", "rotate", "-keys", keys, "-out", missing, spec}, code: exitNoInput},
		exitRow{name: "dev map inspect: success", args: []string{"dev", "map", "inspect", "-keys", keys, mapFile}, code: exitOK},
		exitRow{name: "dev map inspect: bad arguments", args: []string{"dev", "map", "inspect", "-keys", keys}, code: exitUsage},
		exitRow{name: "dev map inspect: missing map", args: []string{"dev", "map", "inspect", "-keys", keys, missing}, code: exitNoInput},
		exitRow{name: "dev map spec: success", args: []string{"dev", "map", "spec"}, code: exitOK},
		exitRow{name: "dev map spec: bad arguments", args: []string{"dev", "map", "spec", "now"}, code: exitUsage},
		exitRow{name: "dev lists build: success", args: []string{"dev", "lists", "build", "-only", "RU", "-out", filepath.Join(dir, "lists"), source}, code: exitOK},
		exitRow{name: "dev lists build: bad arguments", args: []string{"dev", "lists", "build"}, code: exitUsage},
		exitRow{name: "dev lists build: missing source", args: []string{"dev", "lists", "build", "-out", filepath.Join(dir, "lists"), missing}, code: exitNoInput},
	)
	// Root reads whatever it is refused by its mode.
	if !root {
		unreadable, _ := m0State(t, "device-a")
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
		rows = append(rows, exitRow{name: "up: unreadable state directory", args: []string{"up", "-state", unreadable}, code: exitNoPerm, stderr: "permission denied"})
	}
	// Root (a lab node) would act on the host; an OS without a service
	// manager refuses as unsupported first.
	if !root && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
		rows = append(rows,
			exitRow{name: "rollback: permission denied", args: []string{"rollback"}, code: exitNoPerm, stderr: "as root"},
			exitRow{name: "service install: permission denied", args: []string{"service", "install"}, code: exitNoPerm, stderr: "as root"},
			exitRow{name: "service uninstall: permission denied", args: []string{"service", "uninstall"}, code: exitNoPerm, stderr: "as root"},
		)
	}

	tested, changes, outcomes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		c, _, ok := matchCommand(r.args)
		before := exitNodeChanges.Load()
		t.Run(r.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, r.args...)
			var broke []string
			if code != r.code {
				broke = append(broke, fmt.Sprintf("exit %d, want %d", code, r.code))
			}
			// A failure prints to stdout only what its row expects: the
			// status after a change that failed at the node.
			if r.code != exitOK && r.stdout == "" && stdout != "" {
				broke = append(broke, "a failure printed to stdout")
			}
			if !regexp.MustCompile(r.stdout).MatchString(stdout) {
				broke = append(broke, fmt.Sprintf("stdout doesn't match %q", r.stdout))
			}
			if !regexp.MustCompile(r.stderr).MatchString(stderr) {
				broke = append(broke, fmt.Sprintf("stderr doesn't match %q", r.stderr))
			}
			if len(broke) > 0 {
				t.Errorf("%q: %s\nstdout:\n%s\nstderr:\n%s", r.args, strings.Join(broke, "; "), stdout, stderr)
			}
		})
		if ok {
			tested[c.path] = true
			changes[c.path] = changes[c.path] || exitNodeChanges.Load() != before
			outcomes[c.path] = outcomes[c.path] || r.outcome
		}
	}
	for path, c := range commands {
		if !c.hidden && !testOnly[path] && !tested[path] {
			t.Errorf("thinkpol %s has no rows", path)
		}
	}
	// A command that changes the node prints how the change ended, the
	// status on a 1 too (printOutcome): one that returned its error
	// directly would pass every row but these.
	for path := range changes {
		if changes[path] && !outcomes[path] {
			t.Errorf("thinkpol %s changes the node, but has no row where the change fails at the node", path)
		}
	}
}

// brokenWriter fails every write.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is gone") }

// A change that ends in 1 returns the status's printing error with its
// own: neither hides the other.
func TestAFailedChangeKeepsTheStatusWriteError(t *testing.T) {
	socket := serveStatus(t, &exitNode{st: connectedDevice(t).st, err: agent.ErrDNSUnprotected})
	err := runConnect(context.Background(), env{stdin: strings.NewReader(""), stdout: brokenWriter{}, stderr: io.Discard}, []string{"-socket", socket})
	if !errors.Is(err, localapi.ErrDNSUnprotected) || err == nil || !strings.Contains(err.Error(), "stdout is gone") {
		t.Fatalf("got %v; want dns_not_protected and the write's error", err)
	}
	if code := exitCode(err); code != exitFailure {
		t.Errorf("exit %d, want %d", code, exitFailure)
	}
}
