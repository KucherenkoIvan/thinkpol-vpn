//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestServiceUnderSystemd installs device-a as a service in a node that
// runs systemd, and checks what PRD D5 and the crash posture ask of it:
// it starts at boot, connect-on-boot is off until turned on, a reinstall
// over the running agent and a crash both come back as the member left it
// in that boot, and uninstall, right after a crash, leaves nothing of the
// service but its group, also across a reboot. A reboot is the node's
// restart: a fresh /run, systemd booting again (the kernel's boot id is
// the Docker VM's and stays), the node checked sealed again.
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
			res, _ := execResult(dev, execTimeout, "journalctl", "-u", "thinkpol.service", "--no-pager", "-o", "short-precise")
			t.Logf("device-a's journal for thinkpol.service:\n%s", res.Stdout)
		}
	})

	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	up := server.Start(t, "thinkpol", "up")
	waitLog(t, up, `worker space=\S+ .*msg="map applied"`)
	s4, _ := space.overlay(1)
	dev.MustExec(t, "useradd", "-M", "-u", aliceUID, "alice")
	resolvConf := dev.MustExec(t, "cat", "/etc/resolv.conf")

	// alice ran sudo: she joins the group.
	out := dev.MustExec(t, "env", "SUDO_USER=alice", "/opt/thinkpol/bin/thinkpol", "service", "install")
	t.Logf("install:\n%s", out)
	unit := dev.MustExec(t, "cat", "/etc/systemd/system/thinkpol.service")
	if !strings.Contains(unit, "Environment=THINKPOL_CONNECT_ON_BOOT=off\n") || !strings.Contains(unit, "ExecStart=/usr/local/bin/thinkpol up\n") {
		t.Fatalf("the unit:\n%s", unit)
	}
	if got := dev.MustExec(t, "systemctl", "is-enabled", "thinkpol.service"); got != "enabled\n" {
		t.Fatalf("is-enabled: %q", got)
	}
	if got := dev.MustExec(t, "stat", "-c", "%a %U", "/usr/local/bin/thinkpol"); got != "755 root\n" {
		t.Fatalf("the binary: %q", got)
	}
	if got := dev.MustExec(t, "thinkpol", "service", "connect-on-boot"); got != "connect-on-boot: off\n" {
		t.Fatalf("connect-on-boot: %q", got)
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
		dev.MustExec(t, "systemctl", "kill", "-s", "KILL", "thinkpol.service")
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
	// A disconnect is kept across a crash too.
	if res, err := execResult(dev, execTimeout, asAlice("disconnect")...); err != nil {
		t.Fatalf("disconnect: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	crash()
	state("disconnected")

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
	noPing(t, dev, "-c", "2", "-W", "1", s4.String())

	// The toggle: connected from the next boot on.
	dev.MustExec(t, "thinkpol", "service", "connect-on-boot", "on")
	if got := dev.MustExec(t, "thinkpol", "service", "connect-on-boot"); got != "connect-on-boot: on\n" {
		t.Fatalf("connect-on-boot: %q", got)
	}
	state("disconnected") // not before it
	reboot()
	state("connected")
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
	dev.MustExec(t, "systemctl", "kill", "-s", "KILL", "thinkpol.service")
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
		for _, p := range []string{"/etc/systemd/system/thinkpol.service", "/usr/local/bin/thinkpol", "/run/thinkpol", "/run/thinkpol-api"} {
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
