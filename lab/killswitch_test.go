//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestKillSwitchUnderSystemd runs device-a's agent as the service and
// checks the kill switch (TP-048, PRD D4) with real traffic, both
// families, from unbound sockets and sockets bound to the physical
// interface (TP-057). Each part proves one behaviour on an agent of its
// own, in a lab of its own, the parts in parallel, so that no lab is held
// for the whole sequence (TP-248): with the switch on and the tunnel down
// nothing leaves but traffic to the entries (server-1), or with allow-LAN
// the lab's private networks, a deliberate disconnect keeps it, and with
// the switch off a disconnect leaves traffic direct (down); an agent
// killed (SIGKILL, the restart held off) leaves it in place until the
// restarted agent is connected again, and a stop leaves the down shape as
// a crash would (crash-and-stop); the live agent renews the direct
// destinations and repairs its table within a re-apply period, and
// uninstall removes the switch (live-agent); with the switch off the
// "everything" preset holds it across a crash (the crash posture), a
// disconnect removes it, and node.json opts out of it (crash-posture).
func TestKillSwitchUnderSystemd(t *testing.T) {
	t.Parallel()
	for _, part := range []struct {
		name string
		run  func(*killSwitchLab)
	}{
		{"down", killSwitchDown},
		{"crash-and-stop", killSwitchCrashAndStop},
		{"live-agent", killSwitchLiveAgent},
		{"crash-posture", killSwitchCrashPosture},
	} {
		t.Run(part.name, func(t *testing.T) {
			t.Parallel()
			part.run(startKillSwitchLab(t))
		})
	}
}

// killSwitchDown: off once installed; on, in place at once with the
// tunnel down, allow-LAN opening the lab's private networks; connected,
// the TUN passes; a deliberate disconnect keeps the switch. Off,
// connected: nothing under the space preset, and a disconnect leaves
// traffic direct.
func killSwitchDown(k *killSwitchLab) {
	t := k.t
	k.wantTable("installed, off", false, false)
	k.diagShows("installed, off", false, false)
	k.open("installed, kill switch off")

	if got := k.thinkpol("kill-switch", "on"); !regexp.MustCompile(`kill switch: +on, allow-LAN off \(in place\)\n`).MatchString(got) {
		t.Fatalf("kill-switch on:\n%s", got)
	}
	if got := k.thinkpol("kill-switch"); got != "kill-switch: on, allow-LAN off (in place)\n" {
		t.Fatalf("kill-switch: %q", got)
	}
	k.wantTable("on, disconnected", true, false)
	k.diagShows("on, disconnected", true, false)
	k.confined("on, disconnected", false)
	k.thinkpol("allow-lan", "on")
	k.confined("on, disconnected, allow-LAN", true)
	k.thinkpol("allow-lan", "off")
	k.confined("on, disconnected, allow-LAN off again", false)

	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.wantTable("on, connected", true, true)
	k.diagShows("on, connected", true, true)
	k.thinkpol("disconnect")
	k.wantTable("on, disconnected again", true, false)
	k.confined("on, after a disconnect", false)

	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.thinkpol("kill-switch", "off")
	k.wantTable("off, space preset", false, false)
	k.diagShows("off, space preset", false, false)
	k.thinkpol("disconnect")
	k.open("off, disconnected")
}

// killSwitchCrashAndStop: with the switch on, a crash while connected
// leaves the dead agent's table holding, its direct destinations expiring,
// and the restarted agent connects again; a stop is not a disconnect: the
// stopped agent leaves the down shape and the started one comes back
// connected.
func killSwitchCrashAndStop(k *killSwitchLab) {
	t := k.t
	k.thinkpol("kill-switch", "on")
	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.crashHeld(func() {
		k.wantTable("on, crashed", true, true)
		k.expired("on, crashed")
		k.confined("on, crashed", false)
	})
	k.state("connected")
	ping(t, k.dev, k.s4)
	k.wantTable("on, restarted", true, true)

	k.dev.MustExec(t, "systemctl", "stop", "thinkpol.service")
	k.wantTable("on, stopped", true, false)
	k.confined("on, stopped", false)
	k.dev.MustExec(t, "systemctl", "start", "thinkpol.service")
	k.state("connected")
	ping(t, k.dev, k.s4)
	k.wantTable("on, started again", true, true)
}

// killSwitchLiveAgent: under "everything", connected, the live agent
// renews the direct destinations well within their timeout and puts its
// table back within a re-apply period when it is removed from outside.
// Then uninstall removes the switch, turned on while connected: the state
// this part leaves the agent in.
func killSwitchLiveAgent(k *killSwitchLab) {
	t := k.t
	k.thinkpol("rules", "preset", "everything")
	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.wantTable("everything, connected", true, true)

	// The expiry moves later at the re-apply ticks, and one bound to eth0
	// still answers past a whole timeout. A read's expiry lies between the
	// times before and after its docker exec plus what nft said was left:
	// a renewal counts only when the earliest the expiry can now be is
	// past the latest it could have been, so a slow exec neither hides one
	// for good nor makes one up.
	start, renewals, latest := time.Now(), 0, time.Time{}
	lab.Eventually(t, 8*killSwitchDirectTimeout, func() error {
		before := time.Now()
		left, ok, err := k.directExpires()
		after := time.Now()
		if err != nil {
			return err
		}
		if !ok {
			t.Fatalf("everything, connected: the direct destinations expired %v in, renewed %d times", time.Since(start), renewals)
		}
		if !latest.IsZero() && before.Add(left).After(latest) {
			renewals++
		}
		latest = after.Add(left)
		if renewals < 2 || time.Since(start) <= killSwitchDirectTimeout {
			return fmt.Errorf("everything, connected: the direct destinations renewed %d times in %v, expiring in %v", renewals, time.Since(start), left)
		}
		return nil
	})
	if !k.reaches(k.foreign[0], true) {
		t.Errorf("everything, connected %v: the direct destination %v bound to %s unanswered: its renewal lapsed", time.Since(start), k.foreign[0], k.eth)
	}
	// Removed from outside, the table is back by the next re-apply tick,
	// reapply apart. Removed again just after a re-apply put it back, it
	// must be back within one and a half periods, not skip a tick. (The
	// table alone, not `nft flush ruleset`, which would take the
	// container's own rules with it.) The four removals and waits run in
	// one exec, timed by the node's clock: a loaded host's docker exec
	// would stretch the wait and the gap before the next removal alike.
	out := k.dev.MustExec(t, "sh", "-ec", `for i in 0 1 2 3; do
	nft delete table inet thinkpol-killswitch
	start=$(date +%s%N)
	until nft list table inet thinkpol-killswitch >/dev/null 2>&1; do
		[ $(($(date +%s%N) - start)) -lt 30000000000 ] || { echo never; exit 0; }
		sleep 0.1
	done
	echo $(($(date +%s%N) - start))
done`)
	backIn := strings.Fields(out)
	if slices.Contains(backIn, "never") || len(backIn) != 4 {
		t.Fatalf("the kill switch's table removed from outside isn't back within 30 s: %q", out)
	}
	for i, ns := range backIn[1:] {
		n, err := strconv.ParseInt(ns, 10, 64)
		if err != nil {
			t.Fatalf("the table's time back %q: %v", ns, err)
		}
		if d := time.Duration(n); d > killSwitchReapply*3/2 {
			t.Errorf("everything, connected: the table removed from outside (%d) was back after %v, want within %v", i, d, killSwitchReapply*3/2)
		}
	}
	k.wantTable("everything, re-applied", true, true)

	k.thinkpol("kill-switch", "on")
	k.wantTable("on before the uninstall", true, true)
	k.dev.MustExec(t, "thinkpol", "service", "uninstall")
	k.wantTable("uninstalled", false, false)
	k.open("uninstalled")
}

// killSwitchCrashPosture: the switch off under "everything" is in place
// while the tunnel is meant up, held across a crash until the restarted
// agent is connected, and removed by a deliberate disconnect; node.json's
// opt-out makes a crash leave traffic direct.
func killSwitchCrashPosture(k *killSwitchLab) {
	t := k.t
	k.thinkpol("rules", "preset", "everything")
	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.wantTable("everything, connected", true, true)
	k.crashHeld(func() {
		k.wantTable("everything, crashed", true, true)
		k.expired("everything, crashed")
		k.confined("everything, crashed", false)
	})
	k.state("connected")
	ping(t, k.dev, k.s4)
	k.thinkpol("disconnect")
	k.wantTable("everything, disconnected", false, false)
	k.open("everything, disconnected")

	k.dev.WriteFile(t, stateDir+"/node.json", []byte(`{"fail_closed_after_crash": false}`))
	k.dev.MustExec(t, "chmod", "600", stateDir+"/node.json")
	k.dev.MustExec(t, "systemctl", "restart", "thinkpol.service")
	k.state("disconnected")
	k.thinkpol("connect")
	ping(t, k.dev, k.s4)
	k.crashHeld(func() {
		k.wantTable("opted out, crashed", false, false)
		k.open("opted out, crashed")
	})
	k.state("connected")
	k.dev.MustExec(t, "rm", stateDir+"/node.json")
}

// The agent's kill-switch timers, sped up (cmd/thinkpol,
// labKillSwitchReapply): re-applied every 2 s, not 10 s, the direct
// destinations expiring three periods after the last, as with the
// defaults (firewall.DirectTimeout).
const killSwitchReapply, killSwitchDirectTimeout = 2 * time.Second, 6 * time.Second

// killSwitchPort is where a listener waits on each foreign address, so a
// refused connect can only be device-a's own kill switch.
const killSwitchPort = 8080

// killSwitchLab is one part's lab: server-1 up, device-a's agent installed
// as the service and disconnected, its kill switch off.
type killSwitchLab struct {
	t                     *testing.T
	dev, server, internet *lab.Node
	s4                    netip.Addr // server-1's overlay address
	eth                   string     // device-a's physical interface
	foreign, entries      []netip.Addr
}

func startKillSwitchLab(t *testing.T) *killSwitchLab {
	t.Helper()
	topo := lab.Topology{
		Networks: []lab.Network{{Name: lab.NetDevices}, {Name: lab.NetServers}},
		Nodes: []lab.NodeSpec{
			{Name: lab.Router, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
			{Name: lab.DeviceA, Networks: []string{lab.NetDevices}, Gateway: lab.Router, Systemd: true},
			{Name: lab.Server1, Networks: []string{lab.NetServers}, Gateway: lab.Router, Forward: true},
			{Name: lab.Internet, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		},
	}
	asked := time.Now()
	l := lab.StartOwnSlot(t, topo)
	up := time.Now()
	// What the part held the lab for, the start (a runner's shared
	// overhead) apart.
	t.Cleanup(func() {
		t.Logf("in use %v, after a lab start of %v", time.Since(up).Round(100*time.Millisecond), up.Sub(asked).Round(100*time.Millisecond))
	})
	k := &killSwitchLab{t: t, dev: l.Node(lab.DeviceA), server: l.Node(lab.Server1), internet: l.Node(lab.Internet)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := k.dev.WaitBooted(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			res, _ := execResult(k.dev, execTimeout, "thinkpol", "logs", "-n", "500")
			t.Logf("device-a's agent log:\n%s%s", res.Stdout, res.Stderr)
			res, _ = execResult(k.dev, execTimeout, "nft", "list", "ruleset")
			t.Logf("device-a's nftables:\n%s%s", res.Stdout, res.Stderr)
		}
	})

	space := newM0Space(t, k.internet, k.server)
	envelope, _ := space.build(t)
	space.install(t, k.server, "server-1", envelope)
	space.install(t, k.dev, "device-a", envelope)
	waitLog(t, startUp(t, k.server), workerApplied(""))
	k.s4, _ = space.overlay(1)
	k.eth = k.dev.Interface(lab.NetDevices)
	k.foreign = []netip.Addr{k.internet.IPv4(lab.NetServers), k.internet.IPv6(lab.NetServers)}
	k.entries = []netip.Addr{k.server.IPv4(lab.NetServers), k.server.IPv6(lab.NetServers)}
	for _, a := range k.foreign {
		k.internet.Start(t, "nc", ncFamily(a), "-k", "-l", "-s", a.String(), "-p", fmt.Sprint(killSwitchPort))
	}

	k.dev.WriteFile(t, dropIns+"/lab-timing.conf", []byte(fmt.Sprintf("[Service]\nEnvironment=THINKPOL_LAB=1 THINKPOL_LAB_KILL_SWITCH_REAPPLY=%s\n", killSwitchReapply)))
	k.dev.MustExec(t, "/opt/thinkpol/bin/thinkpol", "service", "install")
	k.state("disconnected")
	return k
}

func (k *killSwitchLab) thinkpol(args ...string) string {
	k.t.Helper()
	res, err := execResult(k.dev, execTimeout, append([]string{"thinkpol"}, args...)...)
	if err != nil {
		k.t.Fatalf("thinkpol %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
	return res.Stdout
}

func (k *killSwitchLab) state(want string) {
	k.t.Helper()
	waitStatusFor(k.t, k.dev, 90*time.Second, nil, connection(want))
}

// table says whether the kill switch's table is there, and whether its
// chain passes the TUN (the connected shape).
func (k *killSwitchLab) table() (present, connected bool) {
	k.t.Helper()
	res, err := execResult(k.dev, execTimeout, "nft", "list", "table", "inet", "thinkpol-killswitch")
	if err != nil {
		return false, false
	}
	return true, strings.Contains(res.Stdout, `oifname "thinkpol0" accept`)
}

func (k *killSwitchLab) wantTable(when string, present, connected bool) {
	k.t.Helper()
	lab.Eventually(k.t, 30*time.Second, func() error {
		if p, c := k.table(); p != present || p && c != connected {
			return fmt.Errorf("%s: kill switch table present %v connected %v, want %v %v", when, p, c, present, connected)
		}
		return nil
	})
}

// directExpires is how long the first element of the kill switch's
// direct4 set has left (nft's "expires"), and whether there is one.
func (k *killSwitchLab) directExpires() (time.Duration, bool, error) {
	k.t.Helper()
	out, err := execRead(k.dev, execTimeout, "nft", "list", "set", "inet", "thinkpol-killswitch", "direct4")
	if err != nil {
		return 0, false, err
	}
	m := nftExpires.FindStringSubmatch(out)
	if m == nil {
		return 0, false, nil
	}
	left, err := time.ParseDuration(m[1])
	if err != nil {
		k.t.Fatalf("direct4's expiry %q: %v", m[1], err)
	}
	return left, true, nil
}

// diagShows checks `thinkpol diag`'s kill switch against nft: no table, or
// the table with both chains, every rule (the TUN's passing only
// connected) and each set's size as nft lists them.
func (k *killSwitchLab) diagShows(when string, present, connected bool) {
	k.t.Helper()
	lab.Eventually(k.t, 30*time.Second, func() error {
		var d struct {
			KillSwitch diagKillSwitch `json:"kill_switch"`
		}
		out := k.thinkpol("diag")
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			return fmt.Errorf("%s: diag's JSON: %w\n%s", when, err, out)
		}
		ks := d.KillSwitch
		if ks.Unreadable != "" || ks.Where != "nftables table inet thinkpol-killswitch" || ks.Present == nil || *ks.Present != present ||
			ks.Rules.Unreadable != "" || ks.Sets.Unreadable != "" {
			return fmt.Errorf("%s: diag's kill switch, want present %v:\n%s", when, present, out)
		}
		if !present {
			if len(ks.Rules.Rules) != 0 || len(ks.Sets.Sets) != 0 {
				return fmt.Errorf("%s: no table, but diag lists:\n%s", when, out)
			}
			return nil
		}
		var chains []string
		for _, c := range ks.Nftables.Chains {
			chains = append(chains, fmt.Sprintf("%s %s %d %s", c.Name, c.Hook, c.Priority, c.Policy))
		}
		if want := []string{"output output 2147483647 accept", "forward forward 2147483647 accept"}; ks.Nftables.Dormant || !slices.Equal(chains, want) {
			return fmt.Errorf("%s: chains %q, want %q", when, chains, want)
		}
		perChain := map[string]int{}
		tun := false
		for _, r := range ks.Rules.Rules {
			perChain[r.Chain]++
			tun = tun || r.Text == `meta oifname "thinkpol0" accept`
		}
		chainNames := []string{"output", "forward"}
		reads := make([][]string, 0, len(chainNames)+len(ks.Sets.Sets))
		for _, chain := range chainNames {
			reads = append(reads, []string{"nft", "-a", "list", "chain", "inet", "thinkpol-killswitch", chain})
		}
		for _, set := range ks.Sets.Sets {
			reads = append(reads, []string{"nft", "-j", "list", "set", "inet", "thinkpol-killswitch", set.Name})
		}
		listings, err := k.readAll(reads)
		if err != nil {
			return err
		}
		for i, chain := range chainNames {
			if n := nftRuleLines(listings[i]); perChain[chain] != n {
				return fmt.Errorf("%s: chain %s: diag lists %d rules, nft %d", when, chain, perChain[chain], n)
			}
		}
		if tun != connected {
			return fmt.Errorf("%s: the TUN passes %v, want %v:\n%s", when, tun, connected, out)
		}
		sizes, nftSizes := map[string]int{}, map[string]int{}
		for i, set := range ks.Sets.Sets {
			if set.Unreadable != "" {
				return fmt.Errorf("%s: set %s unreadable: %s", when, set.Name, set.Unreadable)
			}
			sizes[set.Name] = set.Entries
			listed := listings[len(chainNames)+i]
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

// readAll runs the reads on device-a at once (each exec is slow on a
// loaded host) and returns their outputs in order, or the first error.
func (k *killSwitchLab) readAll(reads [][]string) ([]string, error) {
	outs, errs := make([]string, len(reads)), make([]error, len(reads))
	var wg sync.WaitGroup
	for i, args := range reads {
		wg.Go(func() { outs[i], errs[i] = execRead(k.dev, execTimeout, args...) })
	}
	wg.Wait()
	return outs, errors.Join(errs...)
}

// pings says whether ping from device-a, unbound or bound to its physical
// interface, gets an answer from dst.
func (k *killSwitchLab) pings(dst netip.Addr, bound bool) (bool, error) {
	args := []string{"-c", "1", "-W", "2"}
	if bound {
		args = append(args, "-I", k.eth)
	}
	answered, _, err := pingAnswers(k.dev, pingNoReplyOrRoute, append(args, dst.String())...)
	return answered, err
}

func (k *killSwitchLab) reaches(dst netip.Addr, bound bool) bool {
	k.t.Helper()
	answered, err := k.pings(dst, bound)
	if err != nil {
		k.t.Fatal(err)
	}
	return answered
}

// confined checks that nothing but the entries (and, lan, the lab's
// private networks) leaves device-a, both families, bound or not. The
// probes run at once: each is a flow of its own, which the kill switch
// judges alone, and each is timed inside the node.
func (k *killSwitchLab) confined(when string, lan bool) {
	t := k.t
	t.Helper()
	var wg sync.WaitGroup
	for _, bound := range []bool{false, true} {
		for _, dst := range k.foreign {
			wg.Go(func() {
				if got, err := k.pings(dst, bound); err != nil || got != lan {
					t.Errorf("%s: ping %v (bound %v) answered %v (%v), want %v", when, dst, bound, got, err, lan)
				}
			})
		}
		for _, dst := range k.entries {
			wg.Go(func() {
				if got, err := k.pings(dst, bound); err != nil || !got {
					t.Errorf("%s: ping the entry %v (bound %v) unanswered (%v)", when, dst, bound, err)
				}
			})
		}
	}
	for _, dst := range k.foreign {
		wg.Go(func() {
			if got, err := tcpReaches(k.dev, dst, killSwitchPort, 3); err != nil || got != lan {
				t.Errorf("%s: TCP to %v connected %v (%v), want %v", when, dst, got, err, lan)
			}
		})
		if lan {
			continue
		}
		wg.Go(func() {
			if err := k.refused(dst); err != nil {
				t.Errorf("%s: %v", when, err)
			}
		})
	}
	wg.Wait()
}

// refused checks that a curl bound to the physical interface is refused,
// not dropped: curl gives up at once by its own clock (time_total), which
// a loaded host's docker exec doesn't stretch.
func (k *killSwitchLab) refused(dst netip.Addr) error {
	url := "http://" + netip.AddrPortFrom(dst, killSwitchPort).String() + "/"
	connected, out, err := curlFrom(k.dev, 5*time.Second, "--interface", k.eth, "-w", "time_total=%{time_total}\n", url)
	took, ok := curlTook(out)
	if err != nil || connected || !ok || took > 3*time.Second {
		return fmt.Errorf("curl bound to %s: connected %v after %v (read %v), %v\n%s", k.eth, connected, took, ok, err, out)
	}
	return nil
}

// open checks that traffic to the foreign addresses flows direct, the
// probes at once as in confined.
func (k *killSwitchLab) open(when string) {
	t := k.t
	t.Helper()
	var wg sync.WaitGroup
	for _, dst := range k.foreign {
		wg.Go(func() {
			if got, err := k.pings(dst, true); err != nil || !got {
				t.Errorf("%s: ping %v bound to %s unanswered (%v): traffic doesn't flow direct", when, dst, k.eth, err)
			}
		})
		wg.Go(func() {
			if got, err := tcpReaches(k.dev, dst, killSwitchPort, 3); err != nil || !got {
				t.Errorf("%s: TCP to %v doesn't connect (%v): traffic doesn't flow direct", when, dst, err)
			}
		})
	}
	wg.Wait()
}

// expired waits for a dead agent's direct destinations to expire
// (killSwitchDirectTimeout): the lab's networks are private, so every
// preset sends them direct while connected.
func (k *killSwitchLab) expired(when string) {
	k.t.Helper()
	lab.Eventually(k.t, 60*time.Second, func() error {
		if k.reaches(k.foreign[0], false) {
			return fmt.Errorf("%s: %v still answers", when, k.foreign[0])
		}
		return nil
	})
}

// crashHeld kills the agent with systemd's restart held off, runs check
// while it is dead, then lets systemd start it again.
func (k *killSwitchLab) crashHeld(check func()) {
	t := k.t
	t.Helper()
	k.dev.MustExec(t, "sh", "-ec", `printf '[Service]\nRestartSec=1h\n' >"$1" && systemctl daemon-reload`, "sh", dropIns+"/lab-hold.conf")
	signalAgent(t, k.dev, "KILL", 0)
	lab.Eventually(t, 30*time.Second, func() error {
		got, err := execRead(k.dev, pollTimeout, "systemctl", "show", "-p", "SubState", "--value", "thinkpol.service")
		if err != nil || got != "auto-restart\n" {
			return fmt.Errorf("SubState %q: %v", got, err)
		}
		return nil
	})
	check()
	k.dev.MustExec(t, "sh", "-ec", `rm "$1" && systemctl daemon-reload && systemctl restart thinkpol.service`, "sh", dropIns+"/lab-hold.conf")
}

// dropIns is where the kill-switch test's drop-ins for the service go:
// systemd's runtime directory, gone at a reboot.
const dropIns = "/run/systemd/system/thinkpol.service.d"

// curlTook is curl's own time_total (-w "time_total=%{time_total}\n") in
// its output.
func curlTook(out string) (time.Duration, bool) {
	m := curlTimeTotal.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	d, err := time.ParseDuration(m[1] + "s")
	return d, err == nil
}

var curlTimeTotal = regexp.MustCompile(`time_total=([0-9]+(?:\.[0-9]+)?)`)

// nftExpires is an nftables set element's time left.
var nftExpires = regexp.MustCompile(`expires ((?:[0-9]+[hms]+)+)`)

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
