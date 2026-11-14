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

// TestRollbackPutsTheHostBackAfterACrashAndTheRestartStaysDown runs
// device-a's agent as the service under the "everything" preset (the
// crash posture: the kill switch in place while meant up, its toggle
// off), connected, then kills it (SIGKILL, the restart held off): what
// the dead agent left (the route table's routes, rules and leak guard,
// the kill switch's table, resolv.conf pointing at the node) is still
// there. `thinkpol rollback` is refused while the agent runs (exit 75),
// changing nothing; after the kill it puts the host back as it was
// before the service was installed (routes and rules of both families,
// nftables, resolv.conf, links), what isn't thinkpol's (an nftables
// table, policy rules and routes of both families, added before the
// install) kept, and traffic goes direct. The restarted agent then comes
// up disconnected, as rollback recorded, and puts no kill switch back.
func TestRollbackPutsTheHostBackAfterACrashAndTheRestartStaysDown(t *testing.T) {
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
	server, dev, internet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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

	space := newM0Space(t, internet, server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	up := server.Start(t, "thinkpol", "up", "-mode", "server")
	waitLog(t, up, `worker space=\S+ .*msg="map applied"`)
	s4, _ := space.overlay(1)
	foreign := internet.IPv4(lab.NetServers)

	// hostState is what an agent changes on the host and rollback must put
	// back: resolv.conf, the policy rules and routes of both families (the
	// TUN's went with it), nftables, and the links.
	hostState := func() string {
		t.Helper()
		return dev.MustExec(t, "sh", "-c", "cat /etc/resolv.conf; ip rule; ip -6 rule; "+
			"ip route show table all; ip -6 route show table all; nft list ruleset; ip -br link")
	}
	// What isn't thinkpol's, which rollback must leave: a table of
	// nftables, and a policy rule and a route of each family.
	notOurs := []string{
		"nft add table inet lab-foreign", "nft add chain inet lab-foreign keep",
		"ip rule add pref 32001 to 198.51.100.77 lookup main", "ip -6 rule add pref 32001 to 2001:db8:77::/48 lookup main",
		"ip route add blackhole 198.51.100.77/32", "ip -6 route add blackhole 2001:db8:77::/48",
	}
	for _, cmd := range notOurs {
		dev.MustExec(t, strings.Fields(cmd)...)
	}
	foreignKept := func() string {
		t.Helper()
		var gone []string
		for _, c := range [][]string{
			{"nft", "list", "chain", "inet", "lab-foreign", "keep"},
			{"sh", "-c", "ip rule show pref 32001 | grep -q 198.51.100.77"},
			{"sh", "-c", "ip -6 rule show pref 32001 | grep -q 2001:db8:77::/48"},
			{"sh", "-c", "ip route show 198.51.100.77/32 | grep -q blackhole"},
			{"sh", "-c", "ip -6 route show 2001:db8:77::/48 | grep -q blackhole"},
		} {
			if _, err := execResult(dev, execTimeout, c...); err != nil {
				gone = append(gone, strings.Join(c, " "))
			}
		}
		return strings.Join(gone, "; ")
	}
	if gone := foreignKept(); gone != "" {
		t.Fatalf("the foreign state isn't in place, so its survival proves nothing: %s", gone)
	}
	before := hostState()

	dev.MustExec(t, "/opt/thinkpol/bin/thinkpol", "service", "install")
	thinkpol := func(args ...string) string {
		t.Helper()
		res, err := execResult(dev, execTimeout, append([]string{"thinkpol"}, args...)...)
		if err != nil {
			t.Fatalf("thinkpol %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
		}
		return res.Stdout
	}
	state := func(want string) {
		t.Helper()
		lab.Eventually(t, 90*time.Second, func() error {
			res, err := execResult(dev, pollTimeout, "thinkpol", "status")
			if err != nil {
				return fmt.Errorf("%w\n%s%s", err, res.Stdout, res.Stderr)
			}
			if !regexp.MustCompile(`state: +` + want + `\n`).MatchString(res.Stdout) {
				return fmt.Errorf("want %s:\n%s", want, res.Stdout)
			}
			return nil
		})
	}
	killSwitch := func() bool {
		_, err := execResult(dev, execTimeout, "nft", "list", "table", "inet", "thinkpol-killswitch")
		return err == nil
	}
	// left says what of a connected agent is on the host, "" when all is.
	left := func() string {
		var missing []string
		v4, v6, err := policyRules(dev, pollTimeout)
		if err != nil || !routeTableRulesUp(v4, v6) {
			missing = append(missing, fmt.Sprintf("the route table's rules (%v)", err))
		}
		if err := wantGuard(dev, pollTimeout, guardPresent); err != nil {
			missing = append(missing, err.Error())
		}
		if !killSwitch() {
			missing = append(missing, "the kill switch's table")
		}
		if conf, err := execRead(dev, pollTimeout, "cat", "/etc/resolv.conf"); err != nil || !strings.Contains(conf, "# thinkpol:") {
			missing = append(missing, fmt.Sprintf("resolv.conf pointing at the node (%v)", err))
		}
		return strings.Join(missing, "; ")
	}

	state("disconnected")
	thinkpol("rules", "preset", "everything")
	thinkpol("connect")
	ping(t, dev, s4)
	lab.Eventually(t, 30*time.Second, func() error {
		if m := left(); m != "" {
			return fmt.Errorf("connected, missing: %s", m)
		}
		return nil
	})

	// Refused while the agent runs: nothing of it changes. What the
	// running agent changes by itself is left out: the countdowns of the
	// direct destinations it renews, and the firewall's counters.
	volatile := regexp.MustCompile(` (expires \S+|counter packets \d+ bytes \d+)`)
	steady := func() string { t.Helper(); return volatile.ReplaceAllString(hostState(), "") }
	running := steady()
	res, err := execResult(dev, execTimeout, "thinkpol", "rollback")
	if err == nil || res.ExitCode != 75 || !strings.Contains(res.Stderr, "another thinkpol process holds the host") || res.Stdout != "" {
		t.Errorf("rollback while the agent runs: %v (exit %d)\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr)
	}
	if after := steady(); after != running {
		t.Errorf("rollback while the agent runs changed the host:\n%s\nbefore it:\n%s", after, running)
	}
	ping(t, dev, s4)

	// Killed, its restart held off as TestKillSwitchUnderSystemd's is.
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
	if m := left(); m != "" {
		t.Fatalf("the kill left less than a connected agent holds, so rollback proves nothing: missing %s\n%s", m, hostState())
	}

	out := thinkpol("rollback")
	t.Logf("rollback:\n%s", out)
	for _, want := range []string{
		"none left: the kill switch (the nftables table inet thinkpol-killswitch)\n",
		"none left: the route table's routes and policy rules, and its IPv6 leak guard\n",
		"none left: the OS's resolver configuration",
		"recorded: disconnected",
		"the host has no tunnel: traffic goes direct, and stays so at a service's next start in this boot: the kill switch's toggle is off\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rollback doesn't say %q", want)
		}
	}
	if after := hostState(); after != before {
		t.Errorf("the host after rollback:\n%s\nbefore the install:\n%s", after, before)
	}
	if gone := foreignKept(); gone != "" {
		t.Errorf("rollback removed what isn't thinkpol's: %s", gone)
	}
	if answered, out, err := pingAnswers(dev, pingNoReplyOrRoute, "-c", "1", "-W", "2", foreign.String()); err != nil || !answered {
		t.Errorf("after rollback %v doesn't answer directly (%v):\n%s", foreign, err, out)
	}

	// The restarted agent comes up disconnected, as recorded, and the
	// crash posture puts nothing back.
	dev.MustExec(t, "rm", "-r", "/run/systemd/system/thinkpol.service.d")
	dev.MustExec(t, "systemctl", "daemon-reload")
	dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	state("disconnected")
	if killSwitch() {
		t.Error("the restarted agent put the kill switch back: rollback's disconnect wasn't recorded")
	}
	if answered, out, err := pingAnswers(dev, pingNoReplyOrRoute, "-c", "1", "-W", "2", foreign.String()); err != nil || !answered {
		t.Errorf("after the restart %v doesn't answer directly (%v):\n%s", foreign, err, out)
	}
}
