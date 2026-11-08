//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestKillSwitchUnderSystemd runs device-a's agent as the service and
// checks the kill switch (TP-048, PRD D4) with real traffic, both
// families, from unbound sockets and sockets bound to the physical
// interface (TP-057): with the switch on and the tunnel down nothing
// leaves but traffic to the entries (server-1), or with allow-LAN the
// lab's private networks; a deliberate disconnect keeps it with the
// switch on and removes it with the switch off; an agent killed (SIGKILL,
// the restart held off) leaves it in place, the switch on, or off under
// the "everything" preset (the crash posture, which node.json opts out
// of), until the restarted agent is connected again; uninstall removes
// it.
func TestKillSwitchUnderSystemd(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := dev.WaitBooted(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			res, _ := execResult(dev, execTimeout, "thinkpol", "logs", "-n", "500")
			t.Logf("device-a's agent log:\n%s%s", res.Stdout, res.Stderr)
			res, _ = execResult(dev, execTimeout, "nft", "list", "ruleset")
			t.Logf("device-a's nftables:\n%s%s", res.Stdout, res.Stderr)
		}
	})

	space := newM0Space(t, internet, server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	up := server.Start(t, "thinkpol", "up", "-mode", "server")
	waitLog(t, up, `worker space=\S+ .*msg="map applied"`)
	s4, _ := space.overlay(1)
	eth := dev.Interface(lab.NetDevices)
	foreign := []netip.Addr{internet.IPv4(lab.NetServers), internet.IPv6(lab.NetServers)}
	entries := []netip.Addr{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}
	// A listener on each foreign address, so a refused connect can only be
	// device-a's own kill switch.
	const port = 8080
	for _, a := range foreign {
		internet.Start(t, "nc", ncFamily(a), "-k", "-l", "-s", a.String(), "-p", fmt.Sprint(port))
	}

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
	// table says whether the kill switch's table is there, and whether
	// its chain passes the TUN (the connected shape).
	table := func() (present, connected bool) {
		t.Helper()
		res, err := execResult(dev, execTimeout, "nft", "list", "table", "inet", "thinkpol-killswitch")
		if err != nil {
			return false, false
		}
		return true, strings.Contains(res.Stdout, `oifname "thinkpol0" accept`)
	}
	wantTable := func(when string, present, connected bool) {
		t.Helper()
		lab.Eventually(t, 30*time.Second, func() error {
			if p, c := table(); p != present || p && c != connected {
				return fmt.Errorf("%s: kill switch table present %v connected %v, want %v %v", when, p, c, present, connected)
			}
			return nil
		})
	}
	// reaches says whether ping from device-a, unbound or bound to its
	// physical interface, gets an answer from dst.
	reaches := func(dst netip.Addr, bound bool) bool {
		t.Helper()
		args := []string{"-c", "1", "-W", "2"}
		if bound {
			args = append(args, "-I", eth)
		}
		answered, _, err := pingAnswers(dev, pingNoReplyOrRoute, append(args, dst.String())...)
		if err != nil {
			t.Fatal(err)
		}
		return answered
	}
	// confined checks that nothing but the entries (and, lan, the lab's
	// private networks) leaves device-a, both families, bound or not.
	confined := func(when string, lan bool) {
		t.Helper()
		for _, bound := range []bool{false, true} {
			for _, dst := range foreign {
				if got := reaches(dst, bound); got != lan {
					t.Errorf("%s: ping %v (bound %v) answered %v, want %v", when, dst, bound, got, lan)
				}
			}
			for _, dst := range entries {
				if !reaches(dst, bound) {
					t.Errorf("%s: ping the entry %v (bound %v) unanswered", when, dst, bound)
				}
			}
		}
		for _, dst := range foreign {
			if got, err := tcpReaches(dev, dst, port, 3); err != nil || got != lan {
				t.Errorf("%s: TCP to %v connected %v (%v), want %v", when, dst, got, err, lan)
			}
			if lan {
				continue
			}
			start := time.Now()
			url := "http://" + netip.AddrPortFrom(dst, port).String() + "/"
			connected, out, err := curlFrom(dev, 5*time.Second, "--interface", eth, url)
			if err != nil || connected || time.Since(start) > 3*time.Second {
				t.Errorf("%s: curl bound to %s: connected %v after %v, %v\n%s", when, eth, connected, time.Since(start), err, out)
			}
		}
	}
	open := func(when string) {
		t.Helper()
		for _, dst := range foreign {
			if !reaches(dst, true) {
				t.Errorf("%s: ping %v bound to %s unanswered: traffic doesn't flow direct", when, dst, eth)
			}
			if got, err := tcpReaches(dev, dst, port, 3); err != nil || !got {
				t.Errorf("%s: TCP to %v doesn't connect (%v): traffic doesn't flow direct", when, dst, err)
			}
		}
	}
	// crashHeld kills the agent with systemd's restart held off, runs
	// check while it is dead, then lets systemd start it again.
	crashHeld := func(check func()) {
		t.Helper()
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
		check()
		dev.MustExec(t, "rm", "-r", "/run/systemd/system/thinkpol.service.d")
		dev.MustExec(t, "systemctl", "daemon-reload")
		dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	}

	state("disconnected")
	wantTable("installed, off", false, false)
	open("installed, kill switch off")

	// On: in place at once, the tunnel down.
	if got := thinkpol("kill-switch", "on"); !regexp.MustCompile(`kill switch: +on, allow-LAN off \(in place\)\n`).MatchString(got) {
		t.Fatalf("kill-switch on:\n%s", got)
	}
	if got := thinkpol("kill-switch"); got != "kill-switch: on, allow-LAN off (in place)\n" {
		t.Fatalf("kill-switch: %q", got)
	}
	wantTable("on, disconnected", true, false)
	confined("on, disconnected", false)
	thinkpol("allow-lan", "on")
	confined("on, disconnected, allow-LAN", true)
	thinkpol("allow-lan", "off")
	confined("on, disconnected, allow-LAN off again", false)

	// Connected, the TUN passes; a disconnect keeps the switch.
	thinkpol("connect")
	ping(t, dev, s4)
	wantTable("on, connected", true, true)
	thinkpol("disconnect")
	wantTable("on, disconnected again", true, false)
	confined("on, after a disconnect", false)

	// A crash, connected: the dead agent's table holds; the restarted one
	// connects again.
	thinkpol("connect")
	ping(t, dev, s4)
	crashHeld(func() {
		wantTable("on, crashed", true, true)
		confined("on, crashed", false)
	})
	state("connected")
	ping(t, dev, s4)
	wantTable("on, restarted", true, true)

	// Off, connected: nothing under the space preset; a disconnect leaves
	// traffic direct.
	thinkpol("kill-switch", "off")
	wantTable("off, space preset", false, false)
	thinkpol("disconnect")
	open("off, disconnected")

	// The crash posture: off under "everything", in place while meant up,
	// held across a crash, removed by a deliberate disconnect.
	thinkpol("rules", "preset", "everything")
	thinkpol("connect")
	ping(t, dev, s4)
	wantTable("everything, connected", true, true)
	crashHeld(func() {
		wantTable("everything, crashed", true, true)
		confined("everything, crashed", false)
	})
	state("connected")
	ping(t, dev, s4)
	thinkpol("disconnect")
	wantTable("everything, disconnected", false, false)
	open("everything, disconnected")

	// node.json opts out: a crash leaves traffic direct.
	dev.WriteFile(t, stateDir+"/node.json", []byte(`{"fail_closed_after_crash": false}`))
	dev.MustExec(t, "chmod", "600", stateDir+"/node.json")
	dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	state("disconnected")
	thinkpol("connect")
	ping(t, dev, s4)
	crashHeld(func() {
		wantTable("opted out, crashed", false, false)
		open("opted out, crashed")
	})
	state("connected")
	dev.MustExec(t, "rm", stateDir+"/node.json")

	// Uninstall removes it, whatever left it.
	thinkpol("kill-switch", "on")
	wantTable("on before the uninstall", true, true)
	dev.MustExec(t, "thinkpol", "service", "uninstall")
	wantTable("uninstalled", false, false)
	open("uninstalled")
}
