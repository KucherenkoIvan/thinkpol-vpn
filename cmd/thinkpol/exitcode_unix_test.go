//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

// exitNode is a device with status st whose every change fails with err
// (nil: succeeds).
type exitNode struct {
	st  agent.Status
	err error
}

func (n *exitNode) Status() agent.Status                        { return n.st }
func (n *exitNode) Connect(context.Context) error               { return n.err }
func (n *exitNode) Disconnect(context.Context) error            { return n.err }
func (n *exitNode) SetRulePreset(context.Context, string) error { return n.err }
func (n *exitNode) SetConnectOnBoot(bool) error                 { return n.err }
func (n *exitNode) SetKillSwitch(context.Context, bool) error   { return n.err }
func (n *exitNode) SetAllowLAN(context.Context, bool) error     { return n.err }
func (n *exitNode) Diagnose(context.Context, bool) agent.Diagnostics {
	return agent.Diagnostics{Status: n.st}
}

// unknownMembership is an OS that can't say who is in the group.
type unknownMembership struct{}

func (unknownMembership) IsMember(context.Context, uint32, uint32) (bool, error) {
	return false, errors.New("no answer")
}

// exitRow is one command line and the code it exits with; stdout and
// stderr, when set, are patterns its output must match. A failure with
// no stdout pattern prints nothing to stdout.
type exitRow struct {
	name           string
	args           []string
	code           int
	stdout, stderr string
}

// apiCommandLine is a local API command: its path, then its values. A
// change has refusal, the node's error that leaves it undone or done in
// part, and the API's code for it. A root-only call is refused by who
// the caller is alone: no group is asked.
type apiCommandLine struct {
	path, values []string
	refusal      error
	code         string
	rootOnly     bool
}

// Every command exits by sysexits (docs/design/api-overview.md,
// "Verdicts"), in each case that applies to it: success 0, bad arguments
// 64, a missing input 66, the service down 69, busy 75, permission denied
// 77, a bad configuration 78, and 1, printing the status, when the state
// wasn't reached or was in part. Every visible command has rows here.
func TestEveryCommandExitsBySysexits(t *testing.T) {
	unsetTHINKPOL(t)
	keepUpGlobals(t)
	root := os.Geteuid() == 0
	me := uint32(os.Geteuid())
	device := connectedDevice(t).st
	socket := func(err error) string {
		return serveAPI(t, &exitNode{st: device, err: err}, localapi.Policy{ServiceUID: me})
	}
	ok := socket(nil)
	denied := serveAPI(t, &exitNode{st: device}, localapi.Policy{ServiceUID: me + 1})
	// A group none of this process's groups is: the OS is asked, and
	// can't say.
	busy := serveAPI(t, &exitNode{st: device}, localapi.Policy{ServiceUID: me + 1, Group: 4242, HasGroup: true, Membership: unknownMembership{}})
	const down = "/nonexistent/thinkpol-api/api.sock"
	status := `state: +connected`

	var rows []exitRow
	for _, c := range []apiCommandLine{
		{path: []string{"status"}},
		{path: []string{"spaces"}},
		{path: []string{"logs"}, rootOnly: true},
		{path: []string{"diag"}},
		{path: []string{"kill-switch"}},
		{path: []string{"allow-lan"}},
		{path: []string{"connect-on-boot"}},
		{path: []string{"connect"}, refusal: agent.ErrDNSUnprotected, code: "dns_not_protected"},
		{path: []string{"disconnect"}, refusal: agent.ErrServerMode, code: "server_mode"},
		{path: []string{"kill-switch"}, values: []string{"on"}, refusal: agent.ErrServerMode, code: "server_mode"},
		{path: []string{"allow-lan"}, values: []string{"off"}, refusal: agent.ErrServerMode, code: "server_mode"},
		{path: []string{"connect-on-boot"}, values: []string{"on"}, refusal: agent.ErrServerMode, code: "server_mode"},
		{path: []string{"rules", "preset"}, values: []string{"everything"}, refusal: agent.ErrPresetUnavailable, code: "rule_preset_unavailable"},
	} {
		line := func(flags ...string) []string { return slices.Concat(c.path, flags, c.values) }
		name := strings.Join(line(), " ")
		rows = append(rows,
			exitRow{name: name + ": success", args: line("-socket", ok), code: exitOK},
			exitRow{name: name + ": bad arguments", args: line("-socket", ok, "-bogus"), code: exitUsage, stderr: "flag provided but not defined"},
			exitRow{name: name + ": service down", args: line("-socket", down), code: exitUnavailable, stderr: `\[service_down\]`},
		)
		refused := "permission_denied"
		if c.rootOnly {
			refused = "root_only"
		} else {
			rows = append(rows, exitRow{name: name + ": busy", args: line("-socket", busy), code: exitTempFail, stderr: `\[membership_unknown\]`})
		}
		if !root { // root may always call
			rows = append(rows, exitRow{name: name + ": permission denied", args: line("-socket", denied), code: exitNoPerm, stderr: `\[` + refused + `\]`})
		}
		if c.refusal != nil {
			rows = append(rows,
				exitRow{name: name + ": node not running", args: line("-socket", socket(agent.ErrNotRunning)), code: exitUnavailable, stderr: `\[not_running\]`},
				exitRow{name: name + ": not reached, or in part", args: line("-socket", socket(c.refusal)), code: exitFailure, stdout: status, stderr: `\[` + c.code + `\]`},
			)
		}
	}
	rows = append(rows, exitRow{name: "rules preset: no such preset", args: []string{"rules", "preset", "-socket", socket(agent.ErrUnknownPreset), "sometimes"}, code: exitUsage, stderr: `\[unknown_rule_preset\]`})

	state, keys := m0State(t, "device-a")
	dir := tempDir(t)
	spec, mapFile, missing := "../../lab/maps/m0.yaml", filepath.Join(dir, "map.bin"), filepath.Join(dir, "missing.csv")
	noMap := tempDir(t)
	for _, name := range []string{agent.NodeKeyFile, agent.TrustFile} {
		if err := os.WriteFile(filepath.Join(noMap, name), readTestFile(t, filepath.Join(state, name)), 0o600); err != nil {
			t.Fatal(err)
		}
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
		exitRow{name: "up: bad arguments", args: []string{"up", "-state", state, "now"}, code: exitUsage},
		exitRow{name: "up: bad configuration", args: []string{"up", "-state", state, "-mode", "auto"}, code: exitConfig},
		exitRow{name: "up: missing map", args: []string{"up", "-state", noMap}, code: exitNoInput},
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
	// Root (a lab node) would act on the host; an OS without a service
	// manager refuses as unsupported first.
	if !root && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
		rows = append(rows,
			exitRow{name: "rollback: permission denied", args: []string{"rollback"}, code: exitNoPerm, stderr: "as root"},
			exitRow{name: "service install: permission denied", args: []string{"service", "install"}, code: exitNoPerm, stderr: "as root"},
			exitRow{name: "service uninstall: permission denied", args: []string{"service", "uninstall"}, code: exitNoPerm, stderr: "as root"},
		)
	}

	tested := map[string]bool{}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, r.args...)
			// Only a failure that says where it left the node prints.
			quiet := r.code == exitOK || r.stdout != "" || stdout == ""
			if code != r.code || !quiet || !regexp.MustCompile(r.stdout).MatchString(stdout) || !regexp.MustCompile(r.stderr).MatchString(stderr) {
				t.Errorf("%q: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", r.args, code, r.code, stdout, stderr)
			}
		})
		if c, _, ok := matchCommand(r.args); ok {
			tested[c.path] = true
		}
	}
	for path, c := range commands {
		if !c.hidden && !strings.HasPrefix(path, "t ") && !tested[path] {
			t.Errorf("thinkpol %s has no rows", path)
		}
	}
}
