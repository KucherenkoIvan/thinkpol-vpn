//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// serverEgressSpec is the M0 map with server-1 an exit: its space's
// egress makes its supervisor turn the root namespace's forwarding on.
const serverEgressSpec = `nodes:
  - name: server-1
    kind: server
    endpoints:
      - udp://${SERVER_1_IPV4}:4500
    ingress: true
    egress: true
  - name: device-a
    kind: device

paths:
  - [device-a, server-1]
`

// TestServiceUninstallAfterAServerCrash installs server-1 as a service in
// a node that runs systemd and doesn't forward of its own, has device-a
// connect through it, kills it, and uninstalls it at once, before systemd
// restarts it: what the dead supervisor left in the root namespace (the
// forwarding of both families it turned on, the uplink's accept_ra, its
// tables, the spaces' veths) is undone, and nothing of the service is
// left. The supervisor applies no routes of its own, so none of its are
// looked for beyond the spaces' links.
func TestServiceUninstallAfterAServerCrash(t *testing.T) {
	t.Parallel()
	topo := lab.Topology{
		Networks: []lab.Network{{Name: lab.NetDevices}, {Name: lab.NetServers}},
		Nodes: []lab.NodeSpec{
			{Name: lab.Router, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
			{Name: lab.DeviceA, Networks: []string{lab.NetDevices}, Gateway: lab.Router},
			{Name: lab.Server1, Networks: []string{lab.NetServers}, Gateway: lab.Router, Systemd: true},
			{Name: lab.Internet, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		},
	}
	l := lab.Start(t, topo)
	server, dev, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := server.WaitBooted(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			res, _ := execResult(server, execTimeout, "journalctl", "-u", "thinkpol.service", "--no-pager", "-o", "short-precise")
			t.Logf("server-1's journal for thinkpol.service:\n%s", res.Stdout)
		}
	})
	// A systemd node boots forwarding (the lab's own setup); a host that
	// doesn't is the one whose forwarding the supervisor turns on.
	server.MustExec(t, "sysctl", "-qw", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0")
	// The lab's IPv6 is unique local, which isn't an uplink's IPv6: a
	// global address makes it one, so the supervisor turns IPv6
	// forwarding on too, and the uplink's accept_ra 1 to 2 before it.
	uplink := server.Interface(lab.NetServers)
	acceptRA := "net.ipv6.conf." + uplink + ".accept_ra"
	server.MustExec(t, "ip", "-6", "addr", "add", "2001:db8:132::2/64", "dev", uplink, "nodad")
	server.MustExec(t, "sysctl", "-qw", acceptRA+"=1")

	space := newM0Space(t, inet, server)
	inet.WriteFile(t, "/tmp/m0/server-egress.yaml", []byte(serverEgressSpec))
	space.spec = "/tmp/m0/server-egress.yaml"
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	t.Logf("install:\n%s", server.MustExec(t, "/opt/thinkpol/bin/thinkpol", "service", "install"))
	dev.Start(t, "thinkpol", "up")
	s4, _ := space.overlay(1)
	ping(t, dev, s4)

	// What a serving supervisor has set up, which the kill leaves.
	leftovers := func() (string, error) {
		var b strings.Builder
		for _, cmd := range [][]string{
			{"sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", acceptRA},
			{"nft", "list", "tables"},
			{"ip", "-o", "link", "show"},
			{"ip", "route", "show", "table", "all"},
			{"ip", "-6", "route", "show", "table", "all"},
		} {
			out, err := execRead(server, pollTimeout, cmd...)
			if err != nil {
				return "", fmt.Errorf("%s: %w", strings.Join(cmd, " "), err)
			}
			b.WriteString(out)
		}
		return b.String(), nil
	}
	set := []string{"net.ipv4.ip_forward = 1\n", "net.ipv6.conf.all.forwarding = 1\n", acceptRA + " = 2\n"}
	ours := func(state string) []string {
		var found []string
		for _, line := range strings.SplitAfter(state, "\n") {
			if slices.Contains(set, line) || strings.Contains(line, "thinkpol-supervisor") || strings.Contains(line, "tp-space") {
				found = append(found, strings.TrimSuffix(line, "\n"))
			}
		}
		return found
	}
	setUp := func(state string) bool {
		for _, s := range append(set, "inet thinkpol-supervisor\n") {
			if !strings.Contains(state, s) {
				return false
			}
		}
		return true
	}
	serving, err := leftovers()
	if err != nil {
		t.Fatal(err)
	}
	if !setUp(serving) || !strings.Contains(serving, "arp thinkpol-supervisor-arp\n") {
		t.Fatalf("the serving supervisor hasn't set up its forwarding and tables: the uninstall below proves nothing:\n%s", serving)
	}

	// Killed, its restart held off as TestServiceUnderSystemd's is.
	server.WriteFile(t, "/run/systemd/system/thinkpol.service.d/lab-hold.conf", []byte("[Service]\nRestartSec=1h\n"))
	server.MustExec(t, "systemctl", "daemon-reload")
	server.MustExec(t, "systemctl", "kill", "-s", "KILL", "thinkpol.service")
	lab.Eventually(t, 30*time.Second, func() error {
		got, err := execRead(server, pollTimeout, "systemctl", "show", "-p", "SubState", "--value", "thinkpol.service")
		if err != nil || got != "auto-restart\n" {
			return fmt.Errorf("SubState %q: %v", got, err)
		}
		return nil
	})
	crashed, err := leftovers()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("left by the kill: %q", ours(crashed))
	if !setUp(crashed) {
		t.Fatalf("the kill left no forwarding or tables: the uninstall below proves nothing:\n%s", crashed)
	}

	out := server.MustExec(t, "thinkpol", "service", "uninstall")
	t.Logf("uninstall:\n%s", out)
	for _, want := range []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "inet thinkpol-supervisor", "arp thinkpol-supervisor-arp"} {
		if !strings.Contains(out, want) {
			t.Errorf("uninstall doesn't say it undid %s", want)
		}
	}
	server.MustExec(t, "rm", "-r", "/run/systemd/system/thinkpol.service.d")
	server.MustExec(t, "systemctl", "daemon-reload")
	after, err := leftovers()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(after, "net.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\n"+acceptRA+" = 1\n") {
		t.Errorf("the forwarding sysctls aren't as they were before the install:\n%s", after)
	}
	if left := ours(after); len(left) > 0 {
		t.Errorf("left of the supervisor after the uninstall: %q\n%s", left, after)
	}
	for _, p := range []string{"/etc/systemd/system/thinkpol.service", "/usr/local/bin/thinkpol", "/run/thinkpol", "/run/thinkpol-api"} {
		if res, err := execResult(server, execTimeout, "test", "!", "-e", p); err != nil {
			t.Errorf("%s is left: %v %s", p, err, res.Stderr)
		}
	}
	if res, err := execResult(server, execTimeout, "pgrep", "-x", "thinkpol"); err == nil {
		t.Errorf("thinkpol runs: %s", res.Stdout)
	}
}
