//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// signalAgent sends sig to the agent's process alone, as a crash or a
// SIGQUIT reaches it, and waits until every worker it had is gone. Not to
// the whole unit: systemd 252 (the image's) then walks the unit's
// cgroup.procs, and on Linux 7.0 that walk fails with EIO while a
// SIGKILLed agent exits, though the signal landed. The workers end anyway:
// each has PR_SET_PDEATHSIG, and with KillMode=mixed systemd kills what is
// left in the unit's cgroup once the agent is gone, before the restart.
func signalAgent(t *testing.T, n *lab.Node, sig string) {
	t.Helper()
	workers := agentWorkers(t, n)
	n.MustExec(t, "systemctl", "kill", "--kill-whom=main", "-s", sig, "thinkpol.service")
	lab.Eventually(t, 10*time.Second, func() error {
		var alive []string
		for _, pid := range agentWorkers(t, n) {
			if slices.Contains(workers, pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) > 0 {
			return fmt.Errorf("SIG%s to the agent: of its workers %v, %v still run", sig, workers, alive)
		}
		return nil
	})
}

// agentWorkers lists the pids of the server workers running in n.
func agentWorkers(t *testing.T, n *lab.Node) []string {
	t.Helper()
	res, err := execResult(n, pollTimeout, "pgrep", "-f", "^thinkpol worker( |$)")
	if err != nil && res.ExitCode != 1 { // pgrep's 1: none
		t.Fatalf("pgrep workers on %s: %v\n%s", n.Name, err, res.Stderr)
	}
	return strings.Fields(res.Stdout)
}

// TestServiceUnderSystemd installs device-a as a service in a node that
// runs systemd, and checks what PRD D5 and the crash posture ask of it:
// it starts at boot, connect-on-boot is off until alice, a member of the
// group and not root, turns it on (and off again), a reinstall
// over the running agent and a crash both come back as the member left it
// in that boot, a Go crash's trace is kept and shown by the restarted
// agent, and uninstall, right after a crash, leaves nothing of the
// service but its group, also across a reboot. A reboot is the node's
// restart: a fresh /run, systemd booting again (the kernel's boot id is
// the Docker VM's and stays), the node checked sealed again. A drop-in for
// the unit, unsupported, shows in diag.
func TestServiceUnderSystemd(t *testing.T) {
	t.Parallel()
	topo := lab.Topology{
		Networks: []lab.Network{{Name: lab.NetDevices}, {Name: lab.NetServers}},
		Nodes: []lab.NodeSpec{
			{Name: lab.Router, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
			{Name: lab.DeviceA, Networks: []string{lab.NetDevices}, Gateway: lab.Router, Systemd: true},
			{Name: lab.Server1, Networks: []string{lab.NetServers}, Gateway: lab.Router, Forward: true},
			{Name: lab.Internet, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		},
	}
	l := lab.Start(t, topo)
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := dev.WaitBooted(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			// A device's agent under the service logs only to its ring; the
			// journal has systemd's lines.
			res, _ := execResult(dev, execTimeout, "thinkpol", "logs", "-n", "500")
			t.Logf("device-a's agent log:\n%s%s", res.Stdout, res.Stderr)
			res, _ = execResult(dev, execTimeout, "journalctl", "-u", "thinkpol.service", "--no-pager", "-o", "short-precise")
			t.Logf("device-a's journal for thinkpol.service:\n%s", res.Stdout)
		}
	})

	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	up := server.Start(t, "thinkpol", "up", "-mode", "server")
	waitLog(t, up, `worker space=\S+ .*msg="map applied"`)
	s4, _ := space.overlay(1)
	dev.MustExec(t, "useradd", "-M", "-u", aliceUID, "alice")
	resolvConf := dev.MustExec(t, "cat", "/etc/resolv.conf")

	// What systemd answers a stop of a unit it doesn't have at all: exit
	// 5, "not loaded", which the installer reads as stopped.
	if res, err := execResult(dev, execTimeout, "systemctl", "stop", "thinkpol.service"); err == nil || res.ExitCode != 5 || !strings.Contains(res.Stderr, " not loaded") {
		t.Fatalf("stopping a unit systemd doesn't have: exit %d, %v\n%s", res.ExitCode, err, res.Stderr)
	}
	// A unit file an install wrote and then died before starting: on
	// disk, never daemon-reloaded. systemd 252 loads it for the stop and
	// answers 0 (the image is pinned by digest, so a systemd that answers
	// otherwise is a change to notice here, and the installer's reading
	// of "not loaded" to check); the install below stops it the same way.
	dev.WriteFile(t, "/etc/systemd/system/thinkpol.service", []byte("[Service]\nExecStart=/bin/true\n"))
	if res, err := execResult(dev, execTimeout, "systemctl", "stop", "thinkpol.service"); err != nil {
		t.Fatalf("stopping a unit never reloaded: exit %d, %v\n%s", res.ExitCode, err, res.Stderr)
	}

	// alice ran sudo: she joins the group.
	out := dev.MustExec(t, "env", "SUDO_USER=alice", "/opt/thinkpol/bin/thinkpol", "service", "install")
	t.Logf("install:\n%s", out)
	unit := dev.MustExec(t, "cat", "/etc/systemd/system/thinkpol.service")
	if strings.Contains(unit, "THINKPOL_") || !strings.Contains(unit, "ExecStart=/usr/local/bin/thinkpol up -service\n") ||
		!strings.Contains(unit, "StandardError=append:"+stateDir+"/crash-trace\n") {
		t.Fatalf("the unit:\n%s", unit)
	}
	if got := dev.MustExec(t, "systemctl", "is-enabled", "thinkpol.service"); got != "enabled\n" {
		t.Fatalf("is-enabled: %q", got)
	}
	if got := dev.MustExec(t, "stat", "-c", "%a %U", "/usr/local/bin/thinkpol"); got != "755 root\n" {
		t.Fatalf("the binary: %q", got)
	}
	// A reload is SIGHUP to the agent: it reads the map again, and runs on.
	dev.MustExec(t, "systemctl", "reload", "thinkpol.service")
	for prop, want := range map[string]string{"NRestarts": "0\n", "ActiveState": "active\n"} {
		if got := dev.MustExec(t, "systemctl", "show", "-p", prop, "--value", "thinkpol.service"); got != want {
			t.Fatalf("after a reload, %s %q", prop, got)
		}
	}

	// alice reaches the local API through the group install gave her.
	asAlice := func(args ...string) []string {
		return append([]string{"setpriv", "--reuid", "alice", "--regid", "alice", "--init-groups", "/usr/local/bin/thinkpol"}, args...)
	}
	state := func(want string) {
		t.Helper()
		lab.Eventually(t, 90*time.Second, func() error {
			res, err := execResult(dev, pollTimeout, asAlice("status")...)
			if err != nil {
				return fmt.Errorf("%w\n%s%s", err, res.Stdout, res.Stderr)
			}
			if !regexp.MustCompile(`state: +` + want + `\n`).MatchString(res.Stdout) {
				return fmt.Errorf("want %s:\n%s", want, res.Stdout)
			}
			return nil
		})
	}
	state("disconnected")
	noPing(t, dev, "-c", "2", "-W", "1", s4.String())
	// alice's toggle, through the local API: off until she turns it on.
	onBoot := func(args ...string) string {
		t.Helper()
		res, err := execResult(dev, execTimeout, asAlice(append([]string{"connect-on-boot"}, args...)...)...)
		if err != nil {
			t.Fatalf("connect-on-boot %v: %v\n%s%s", args, err, res.Stdout, res.Stderr)
		}
		return res.Stdout
	}
	if got := onBoot(); got != "connect-on-boot: off\n" {
		t.Fatalf("connect-on-boot: %q", got)
	}
	if res, err := execResult(dev, execTimeout, asAlice("connect")...); err != nil {
		t.Fatalf("connect: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	ping(t, dev, s4)

	// The runbook's binary update: installed again over the running,
	// connected agent, which comes back connected.
	out = dev.MustExec(t, "/opt/thinkpol/bin/thinkpol", "service", "install")
	t.Logf("reinstall:\n%s", out)
	state("connected")
	ping(t, dev, s4)

	// A crash: systemd restarts the agent, connected as alice left it.
	restarts := func() string {
		t.Helper()
		return dev.MustExec(t, "systemctl", "show", "-p", "NRestarts", "--value", "thinkpol.service")
	}
	crash := func() {
		t.Helper()
		before := restarts()
		signalAgent(t, dev, "KILL")
		lab.Eventually(t, 60*time.Second, func() error {
			if got := restarts(); got == before {
				return fmt.Errorf("NRestarts still %q", got)
			}
			return nil
		})
	}
	crash()
	state("connected")
	ping(t, dev, s4)

	// The crash trace (PRD S2's device exception): a kill leaves nothing on
	// stderr, so the restarted agent shows no crash. A Go crash (SIGQUIT:
	// the runtime's trace, exit 2) leaves its trace in the file, root's
	// 0600; the restarted agent shows it (alice's status the line, root's
	// diag the trace, alice's diag only that it is root's) and empties the
	// file, where its log never goes.
	lastRun := func(crashed bool) {
		t.Helper()
		lab.Eventually(t, 90*time.Second, func() error {
			res, err := execResult(dev, pollTimeout, asAlice("status")...)
			if err != nil {
				return fmt.Errorf("%w\n%s%s", err, res.Stdout, res.Stderr)
			}
			if got := strings.Contains(res.Stdout, "\nlast run:"); got != crashed {
				return fmt.Errorf("want the last run crashed %v:\n%s", crashed, res.Stdout)
			}
			return nil
		})
	}
	lastRun(false)
	before := restarts()
	signalAgent(t, dev, "QUIT")
	lab.Eventually(t, 60*time.Second, func() error {
		if got := restarts(); got == before {
			return fmt.Errorf("NRestarts still %q", got)
		}
		return nil
	})
	lastRun(true)
	state("connected")
	if got := dev.MustExec(t, "stat", "-c", "%a %U %s", stateDir+"/crash-trace"); got != "600 root 0\n" {
		t.Fatalf("the crash trace after the restart: %q", got)
	}
	res, err := execResult(dev, execTimeout, "thinkpol", "diag")
	if err != nil || !regexp.MustCompile(`"last_run":\s*\{\s*"unreadable":\s*"",\s*"lines":\s*\[\s*"SIGQUIT: quit",`).MatchString(res.Stdout) {
		t.Fatalf("root's diag: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	res, err = execResult(dev, execTimeout, asAlice("diag")...)
	if err != nil || !regexp.MustCompile(`"last_run":\s*\{\s*"unreadable":\s*"root only[^"]*",\s*"lines":\s*\[\]`).MatchString(res.Stdout) {
		t.Fatalf("alice's diag: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	// A disconnect is kept across a crash too.
	if res, err := execResult(dev, execTimeout, asAlice("disconnect")...); err != nil {
		t.Fatalf("disconnect: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	crash()
	state("disconnected")
	lastRun(false)
	// A clean stop (systemd's SIGTERM) writes nothing on stderr either.
	dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	state("disconnected")
	lastRun(false)

	// A reboot starts the service, disconnected: connect-on-boot is off,
	// whatever alice did before it.
	if res, err := execResult(dev, execTimeout, asAlice("connect")...); err != nil {
		t.Fatalf("connect: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	reboot := func() {
		t.Helper()
		if err := dev.Restart(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reboot()
	state("disconnected")
	lastRun(false) // the stop at the reboot was clean
	noPing(t, dev, "-c", "2", "-W", "1", s4.String())

	// alice's toggle, without root: connected from the next boot on. The
	// service stores it in device.json; the unit doesn't change.
	if out := onBoot("on"); !regexp.MustCompile(`connect-on-boot: +on\n`).MatchString(out) {
		t.Fatalf("connect-on-boot on:\n%s", out)
	}
	if got := onBoot(); got != "connect-on-boot: on\n" {
		t.Fatalf("connect-on-boot: %q", got)
	}
	if got := dev.MustExec(t, "stat", "-c", "%a %U", stateDir+"/device.json"); got != "600 root\n" {
		t.Fatalf("device.json: %q", got)
	}
	if got := dev.MustExec(t, "cat", "/etc/systemd/system/thinkpol.service"); got != unit {
		t.Fatalf("the unit changed:\n%s", got)
	}
	state("disconnected") // not before it
	reboot()
	state("connected")
	ping(t, dev, s4)
	// Off again: the next boot stays down.
	onBoot("off")
	state("connected") // not before it
	reboot()
	state("disconnected")
	noPing(t, dev, "-c", "2", "-W", "1", s4.String())
	if got := onBoot(); got != "connect-on-boot: off\n" {
		t.Fatalf("connect-on-boot after the reboot: %q", got)
	}

	// A drop-in for the unit is unsupported: diag reports it, to the
	// group too.
	dropIn := "/etc/systemd/system/thinkpol.service.d/lab-diag.conf"
	dev.WriteFile(t, dropIn, []byte("[Service]\nEnvironment=THINKPOL_LOG_LEVEL=debug\n"))
	res, err = execResult(dev, execTimeout, asAlice("diag")...)
	if err != nil || !regexp.MustCompile(`"service_drop_ins":\s*\{\s*"unreadable":\s*"",\s*"paths":\s*\[\s*"`+regexp.QuoteMeta(dropIn)+`"\s*\]`).MatchString(res.Stdout) {
		t.Fatalf("diag: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	dev.MustExec(t, "rm", "-r", "/etc/systemd/system/thinkpol.service.d")
	if res, err := execResult(dev, execTimeout, asAlice("diag")...); err != nil || !regexp.MustCompile(`"service_drop_ins":\s*\{\s*"unreadable":\s*"",\s*"paths":\s*\[\]`).MatchString(res.Stdout) {
		t.Fatalf("diag without the drop-in: %v\n%s%s", err, res.Stdout, res.Stderr)
	}

	// Connected for the uninstall below, which meets what a crash left.
	if res, err := execResult(dev, execTimeout, asAlice("connect")...); err != nil {
		t.Fatalf("connect: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	ping(t, dev, s4)

	// Uninstalled at once after a crash, before systemd restarts the
	// agent: what the dead agent left (its guard, routes and resolver
	// configuration) is undone. Nothing of the service is left, nor after
	// a reboot.
	// The restart is held off (a drop-in of the test's, in /run, removed
	// right after the uninstall, before the checks), so the uninstall
	// meets the dead agent's leftovers rather than a restarted agent that
	// took them down itself.
	dev.WriteFile(t, "/run/systemd/system/thinkpol.service.d/lab-hold.conf", []byte("[Service]\nRestartSec=1h\n"))
	dev.MustExec(t, "systemctl", "daemon-reload")
	signalAgent(t, dev, "KILL")
	lab.Eventually(t, 30*time.Second, func() error {
		got, err := execRead(dev, pollTimeout, "systemctl", "show", "-p", "SubState", "--value", "thinkpol.service")
		if err != nil || got != "auto-restart\n" {
			return fmt.Errorf("SubState %q: %v", got, err)
		}
		return nil
	})
	if err := wantGuard(dev, execTimeout, guardPresent); err != nil {
		t.Fatalf("no guard left by the crash: the uninstall below proves nothing: %v", err)
	}
	out = dev.MustExec(t, "thinkpol", "service", "uninstall")
	t.Logf("uninstall:\n%s", out)
	dev.MustExec(t, "rm", "-r", "/run/systemd/system/thinkpol.service.d")
	dev.MustExec(t, "systemctl", "daemon-reload")
	wantNoService := func() {
		t.Helper()
		for _, p := range []string{"/etc/systemd/system/thinkpol.service", "/usr/local/bin/thinkpol", "/run/thinkpol", "/run/thinkpol-api", stateDir + "/crash-trace"} {
			if res, err := execResult(dev, execTimeout, "test", "!", "-e", p); err != nil {
				t.Errorf("%s is left: %v %s", p, err, res.Stderr)
			}
		}
		if res, _ := execResult(dev, execTimeout, "systemctl", "list-unit-files", "--no-legend", "thinkpol.service"); strings.TrimSpace(res.Stdout) != "" {
			t.Errorf("systemd still knows the unit: %s", res.Stdout)
		}
		// The group stays (it may be older than the service).
		dev.MustExec(t, "getent", "group", "thinkpol")
		if res, err := execResult(dev, execTimeout, "pgrep", "-x", "thinkpol"); err == nil {
			t.Errorf("thinkpol runs: %s", res.Stdout)
		}
		if err := wantTUNGone(dev, execTimeout); err != nil {
			t.Error(err)
		}
		if err := wantGuard(dev, execTimeout, guardAbsent); err != nil {
			t.Error(err)
		}
		if v4, v6, err := policyRules(dev, execTimeout); err != nil || routeTableRulesUp(v4, v6) || strings.Contains(v4+v6, "5301") {
			t.Errorf("policy rules left (%v):\n%s%s", err, v4, v6)
		}
		if conf := dev.MustExec(t, "cat", "/etc/resolv.conf"); conf != resolvConf {
			t.Errorf("resolv.conf not restored:\n%s", conf)
		}
		// The node's keys and map stay.
		dev.MustExec(t, "test", "-s", stateDir+"/node.key")
	}
	wantNoService()
	reboot()
	wantNoService()
}
