//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
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
// it. A stop leaves the down shape as a crash would; the live agent
// renews the direct destinations and repairs its table within a re-apply
// period.
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
	// diagShows checks `thinkpol diag`'s kill switch against nft: no
	// table, or the table with both chains, every rule (the TUN's passing
	// only connected) and each set's size as nft lists them.
	diagShows := func(when string, present, connected bool) {
		t.Helper()
		lab.Eventually(t, 30*time.Second, func() error {
			var d struct {
				KillSwitch diagKillSwitch `json:"kill_switch"`
			}
			out := thinkpol("diag")
			if err := json.Unmarshal([]byte(out), &d); err != nil {
				return fmt.Errorf("%s: diag's JSON: %w\n%s", when, err, out)
			}
			k := d.KillSwitch
			if k.Unreadable != "" || k.Where != "nftables table inet thinkpol-killswitch" || k.Present == nil || *k.Present != present ||
				k.Rules.Unreadable != "" || k.Sets.Unreadable != "" {
				return fmt.Errorf("%s: diag's kill switch, want present %v:\n%s", when, present, out)
			}
			if !present {
				if len(k.Rules.Rules) != 0 || len(k.Sets.Sets) != 0 {
					return fmt.Errorf("%s: no table, but diag lists:\n%s", when, out)
				}
				return nil
			}
			var chains []string
			for _, c := range k.Nftables.Chains {
				chains = append(chains, fmt.Sprintf("%s %s %d %s", c.Name, c.Hook, c.Priority, c.Policy))
			}
			if want := []string{"output output 2147483647 accept", "forward forward 2147483647 accept"}; k.Nftables.Dormant || !slices.Equal(chains, want) {
				return fmt.Errorf("%s: chains %q, want %q", when, chains, want)
			}
			perChain := map[string]int{}
			tun := false
			for _, r := range k.Rules.Rules {
				perChain[r.Chain]++
				tun = tun || r.Text == `meta oifname "thinkpol0" accept`
			}
			for _, chain := range []string{"output", "forward"} {
				listed, err := execRead(dev, execTimeout, "nft", "-a", "list", "chain", "inet", "thinkpol-killswitch", chain)
				if err != nil {
					return err
				}
				if n := nftRuleLines(listed); perChain[chain] != n {
					return fmt.Errorf("%s: chain %s: diag lists %d rules, nft %d", when, chain, perChain[chain], n)
				}
			}
			if tun != connected {
				return fmt.Errorf("%s: the TUN passes %v, want %v:\n%s", when, tun, connected, out)
			}
			sizes, nftSizes := map[string]int{}, map[string]int{}
			for _, set := range k.Sets.Sets {
				if set.Unreadable != "" {
					return fmt.Errorf("%s: set %s unreadable: %s", when, set.Name, set.Unreadable)
				}
				sizes[set.Name] = set.Entries
				listed, err := execRead(dev, execTimeout, "nft", "-j", "list", "set", "inet", "thinkpol-killswitch", set.Name)
				if err != nil {
					return err
				}
				var l struct {
					Nftables []struct {
						Set *struct {
							Elem []json.RawMessage `json:"elem"`
						} `json:"set"`
					} `json:"nftables"`
				}
				if err := json.Unmarshal([]byte(listed), &l); err != nil {
					return err
				}
				for _, o := range l.Nftables {
					if o.Set != nil {
						nftSizes[set.Name] = len(o.Set.Elem)
					}
				}
			}
			if !maps.Equal(sizes, nftSizes) || len(sizes) != 6 || sizes["allow4"] == 0 || sizes["allow6"] == 0 || (sizes["direct4"] > 0) != connected {
				return fmt.Errorf("%s: set sizes %v, nft %v", when, sizes, nftSizes)
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
	// expired waits for a dead agent's direct destinations to expire
	// (firewall.DirectTimeout): the lab's networks are private, so every
	// preset sends them direct while connected.
	expired := func(when string) {
		t.Helper()
		lab.Eventually(t, 60*time.Second, func() error {
			if reaches(foreign[0], false) {
				return fmt.Errorf("%s: %v still answers", when, foreign[0])
			}
			return nil
		})
	}
	// crashHeld kills the agent with systemd's restart held off, runs
	// check while it is dead, then lets systemd start it again.
	crashHeld := func(check func()) {
		t.Helper()
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
		check()
		dev.MustExec(t, "rm", "-r", "/run/systemd/system/thinkpol.service.d")
		dev.MustExec(t, "systemctl", "daemon-reload")
		dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	}

	state("disconnected")
	wantTable("installed, off", false, false)
	diagShows("installed, off", false, false)
	open("installed, kill switch off")

	// On: in place at once, the tunnel down.
	if got := thinkpol("kill-switch", "on"); !regexp.MustCompile(`kill switch: +on, allow-LAN off \(in place\)\n`).MatchString(got) {
		t.Fatalf("kill-switch on:\n%s", got)
	}
	if got := thinkpol("kill-switch"); got != "kill-switch: on, allow-LAN off (in place)\n" {
		t.Fatalf("kill-switch: %q", got)
	}
	wantTable("on, disconnected", true, false)
	diagShows("on, disconnected", true, false)
	confined("on, disconnected", false)
	thinkpol("allow-lan", "on")
	confined("on, disconnected, allow-LAN", true)
	thinkpol("allow-lan", "off")
	confined("on, disconnected, allow-LAN off again", false)

	// Connected, the TUN passes; a disconnect keeps the switch.
	thinkpol("connect")
	ping(t, dev, s4)
	wantTable("on, connected", true, true)
	diagShows("on, connected", true, true)
	thinkpol("disconnect")
	wantTable("on, disconnected again", true, false)
	confined("on, after a disconnect", false)

	// A crash, connected: the dead agent's table holds; the restarted one
	// connects again.
	thinkpol("connect")
	ping(t, dev, s4)
	crashHeld(func() {
		wantTable("on, crashed", true, true)
		expired("on, crashed")
		confined("on, crashed", false)
	})
	state("connected")
	ping(t, dev, s4)
	wantTable("on, restarted", true, true)

	// A stop is not a disconnect: the stopped agent leaves the down shape,
	// and the started one comes back connected.
	dev.MustExec(t, "systemctl", "stop", "thinkpol.service")
	wantTable("on, stopped", true, false)
	confined("on, stopped", false)
	dev.MustExec(t, "systemctl", "start", "thinkpol.service")
	state("connected")
	ping(t, dev, s4)
	wantTable("on, started again", true, true)

	// Off, connected: nothing under the space preset; a disconnect leaves
	// traffic direct.
	thinkpol("kill-switch", "off")
	wantTable("off, space preset", false, false)
	diagShows("off, space preset", false, false)
	thinkpol("disconnect")
	open("off, disconnected")

	// The crash posture: off under "everything", in place while meant up,
	// held across a crash, removed by a deliberate disconnect.
	thinkpol("rules", "preset", "everything")
	thinkpol("connect")
	ping(t, dev, s4)
	wantTable("everything, connected", true, true)

	// The live agent renews the direct destinations well within their
	// timeout (firewall.DirectTimeout, 30 s): one bound to eth0 still
	// answers after 45 s.
	time.Sleep(45 * time.Second)
	if !reaches(foreign[0], true) {
		t.Errorf("everything, connected 45 s: the direct destination %v bound to %s unanswered: its renewal lapsed", foreign[0], eth)
	}
	// Removed from outside, the table is back by the next re-apply tick,
	// 10 s apart. Removed again just after a re-apply put it back, it
	// must be back within 11 s, not skip a tick. (The table alone, not
	// `nft flush ruleset`, which would take the container's own rules
	// with it.)
	backIn := func() time.Duration {
		t.Helper()
		dev.MustExec(t, "nft", "delete", "table", "inet", "thinkpol-killswitch")
		start := time.Now()
		for p, _ := table(); !p; p, _ = table() {
			if time.Since(start) > 30*time.Second {
				t.Fatal("the kill switch's table removed from outside isn't back within 30 s")
			}
			time.Sleep(100 * time.Millisecond)
		}
		return time.Since(start)
	}
	backIn()
	for i := range 3 {
		if d := backIn(); d > 11*time.Second {
			t.Errorf("everything, connected: the table removed from outside (%d) was back after %v, want within 11 s", i, d)
		}
	}
	wantTable("everything, re-applied", true, true)
	crashHeld(func() {
		wantTable("everything, crashed", true, true)
		expired("everything, crashed")
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

// diagKillSwitch is the part of `thinkpol diag`'s kill switch the lab
// checks.
type diagKillSwitch struct {
	Unreadable string `json:"unreadable"`
	Where      string `json:"where"`
	Present    *bool  `json:"present"`
	Rules      struct {
		Unreadable string `json:"unreadable"`
		Rules      []struct {
			Chain string `json:"chain"`
			Text  string `json:"text"`
		} `json:"rules"`
	} `json:"rules"`
	Sets struct {
		Unreadable string `json:"unreadable"`
		Sets       []struct {
			Name       string `json:"name"`
			Unreadable string `json:"unreadable"`
			Entries    int    `json:"entries"`
		} `json:"sets"`
	} `json:"sets"`
	Nftables struct {
		Dormant bool `json:"dormant"`
		Chains  []struct {
			Name     string `json:"name"`
			Hook     string `json:"hook"`
			Priority int    `json:"priority"`
			Policy   string `json:"policy"`
		} `json:"chains"`
	} `json:"nftables"`
}

// nftRuleLines counts the rules in `nft -a list chain`'s output: the
// lines with a handle that open no block (the table's and the chain's
// lines have one too).
func nftRuleLines(listed string) int {
	n := 0
	for _, l := range strings.Split(listed, "\n") {
		if strings.Contains(l, "# handle") && !strings.Contains(l, "{") {
			n++
		}
	}
	return n
}
