package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The kill switch is in place while its toggle is on, or under the crash
// posture (everything, all-but-domestic) while the connection is meant
// up, unless opted out; its rules are the entries, the direct
// destinations and the TUN while connected, and the LAN with allow-LAN.
func TestKillSwitchSettingsDecide(t *testing.T) {
	for _, c := range []struct {
		name    string
		s       killSwitchSettings
		meantUp bool
		want    bool
	}{
		{"off", killSwitchSettings{failClosed: true}, true, false},
		{"on, down on purpose", killSwitchSettings{on: true}, false, true},
		{"everything, meant up", killSwitchSettings{failClosed: true, preset: rules.PresetEverything}, true, true},
		{"all-but-domestic, meant up", killSwitchSettings{failClosed: true, preset: rules.PresetAllButDomestic}, true, true},
		{"everything, disconnected", killSwitchSettings{failClosed: true, preset: rules.PresetEverything}, false, false},
		{"everything, opted out", killSwitchSettings{preset: rules.PresetEverything}, true, false},
		{"space, meant up", killSwitchSettings{failClosed: true, preset: rules.PresetSpace}, true, false},
	} {
		if got := c.s.active(c.meantUp); got != c.want {
			t.Errorf("%s: active %v, want %v", c.name, got, c.want)
		}
	}

	entry := netip.MustParseAddr("203.0.113.50")
	direct := mustSet(t, "198.51.100.0/24", "2001:db8:d0::/48")
	up := &routetable.Exempt{TUN: "thinkpol0", Mark: routetable.Mark, Direct: direct, Upstreams: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}
	down := killSwitchSettings{}.rules(killSwitchView{entries: []netip.Addr{entry}})
	if down.TUN != "" || down.Mark != routetable.Mark || !down.Allow.Equal(mustSet(t, "203.0.113.50/32")) || down.Upstreams != nil {
		t.Errorf("down shape %+v %v", down, down.Allow.Prefixes())
	}
	conn := killSwitchSettings{allowLAN: true}.rules(killSwitchView{entries: []netip.Addr{entry}, connected: up, tun: "thinkpol0"})
	for _, a := range []string{"203.0.113.50", "10.1.2.3", "fe80::1", "ff02::fb"} {
		if !conn.Allow.Contains(netip.MustParseAddr(a)) {
			t.Errorf("the connected shape with allow-LAN doesn't let %s out", a)
		}
	}
	if !conn.Direct.Equal(direct) || conn.Allow.Contains(netip.MustParseAddr("198.51.100.7")) {
		t.Errorf("the direct destinations aren't the connected shape's Direct alone: %v, %v", conn.Direct.Prefixes(), conn.Allow.Prefixes())
	}
	if conn.Allow.Contains(netip.MustParseAddr("203.0.113.7")) || conn.TUN != "thinkpol0" || len(conn.Upstreams) != 1 {
		t.Errorf("connected shape %+v %v", conn, conn.Allow.Prefixes())
	}
	// Multicast of link-local and site-local scope only: mDNS and SSDP,
	// not what may be routed beyond the LAN.
	for a, want := range map[string]bool{
		"224.0.0.251": true, "239.255.255.250": true, "255.255.255.255": true, "ff02::fb": true, "ff02::c": true, "ff05::c": true,
		"224.0.1.1": false, "233.252.0.1": false, "239.1.2.3": false, "ff0e::1": false, "ff08::1": false, "ff15::1": false,
	} {
		if got := conn.Allow.Contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("allow-LAN lets %s out: %v, want %v", a, got, want)
		}
	}
	if !conn.NoDNS.IsEmpty() || !down.NoDNS.IsEmpty() {
		t.Errorf("DNS refused connected (%v) or down without allow-LAN (%v)", conn.NoDNS.Prefixes(), down.NoDNS.Prefixes())
	}
	// Down with allow-LAN, DNS to the LAN is refused, but to an entry on
	// it (its transport may use port 53).
	lanEntry := netip.MustParseAddr("192.168.1.10")
	downLAN := killSwitchSettings{allowLAN: true}.rules(killSwitchView{entries: []netip.Addr{entry, lanEntry}})
	for a, want := range map[string]bool{"10.1.2.3": true, "192.168.1.11": true, "fe80::1": true, "fd00::53": true, "192.168.1.10": false, "203.0.113.50": false} {
		if got := downLAN.NoDNS.Contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("down with allow-LAN: DNS to %s refused %v, want %v", a, got, want)
		}
	}
	if !downLAN.Allow.Contains(lanEntry) || !downLAN.Allow.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("down with allow-LAN lets out %v", downLAN.Allow.Prefixes())
	}
}

func mustSet(t *testing.T, prefixes ...string) *lists.Set {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

// withKillSwitch runs device b on host's kill switch, with the node's
// kill switch defaults as given.
func withKillSwitch(host *memKillSwitches, set func(*Config)) deviceOpt {
	return deviceOpt{prepare: func(c *Config, p *Platform) {
		p.NewKillSwitch = host.new
		c.FailClosedAfterCrash = true
		if set != nil {
			set(c)
		}
	}}
}

// withPreset starts device b with its device file's preset.
func withPreset(p rules.Preset) deviceOpt {
	return deviceOpt{node: func(n *Node) { n.device.Rules.Preset = p }}
}

// inPlace waits until host's kill switch holds what want says: nothing
// (nil), the down shape (TUN "") or the connected one.
func inPlace(t *testing.T, host *memKillSwitches, want string) *firewall.KillSwitchRules {
	t.Helper()
	var r *firewall.KillSwitchRules
	eventually(t, func() bool {
		r = host.rules()
		switch want {
		case "none":
			return r == nil
		case "down":
			return r != nil && r.TUN == ""
		}
		return r != nil && r.TUN != ""
	})
	return r
}

// The toggle puts the kill switch in place at once and keeps it across
// a disconnect; connected it lets the TUN and the direct destinations
// out too; off removes it. The toggles go into the device file.
func TestTheKillSwitchFollowsItsToggle(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	host := &memKillSwitches{}
	b := startDevice(t, s, reg, false, withKillSwitch(host, nil))
	ctx := context.Background()

	b.connection(t, Disconnected)
	if host.rules() != nil {
		t.Fatal("a kill switch in place with the toggle off, disconnected")
	}
	if err := b.node.SetKillSwitch(ctx, true); err != nil {
		t.Fatal(err)
	}
	down := inPlace(t, host, "down")
	if !down.Allow.Contains(s.listen.Addr()) || len(down.Allow.Ranges()) != 1 {
		t.Errorf("the down shape lets out %v, want the entry %v alone", down.Allow.Prefixes(), s.listen.Addr())
	}
	if st := b.node.Status().KillSwitch; !st.On || !st.Active || !st.Enforced {
		t.Errorf("status %+v", st)
	}
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if up := inPlace(t, host, "connected"); !up.Allow.Contains(s.listen.Addr()) {
		t.Errorf("connected shape %+v", up)
	}
	if err := b.node.SetAllowLAN(ctx, true); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		r := host.rules()
		return r != nil && r.Allow.Contains(netip.MustParseAddr("192.168.1.1"))
	})
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	inPlace(t, host, "down")
	if err := b.node.SetKillSwitch(ctx, false); err != nil {
		t.Fatal(err)
	}
	inPlace(t, host, "none")
	data, err := os.ReadFile(filepath.Join(b.node.cfg.StateDir, DeviceFile))
	if err != nil || !strings.Contains(string(data), `"kill_switch": false`) || !strings.Contains(string(data), `"allow_lan": true`) {
		t.Errorf("device file %s, %v", data, err)
	}
}

// Under the everything preset with the toggle off, the kill switch is in
// place while the connection is meant up, so a crash or a stop leaves it
// (in the down shape for a stop); a deliberate disconnect removes it.
// Opted out, it never goes in.
func TestTheCrashPostureHoldsWhileMeantUp(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	ctx := context.Background()

	host := &memKillSwitches{}
	b := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything))
	b.connection(t, Connected)
	inPlace(t, host, "connected")
	if st := b.node.Status().KillSwitch; st.On || !st.Active {
		t.Errorf("status %+v, want held by the posture", st)
	}
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	inPlace(t, host, "none")
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	inPlace(t, host, "connected")
	b.stop()
	select {
	case <-b.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the node didn't stop")
	}
	b.done <- nil // for the cleanup
	if r := host.rules(); r == nil || r.TUN != "" {
		t.Errorf("a stop left %+v, want the down shape", r)
	}
	if !strings.Contains(b.log.String(), KillSwitchStopNote) {
		t.Errorf("the stop left the kill switch in place without warning:\n%s", b.log)
	}

	out := &memKillSwitches{}
	o := startDevice(t, s, reg, true, withKillSwitch(out, func(c *Config) { c.FailClosedAfterCrash = false }), withPreset(rules.PresetEverything))
	o.connection(t, Connected)
	time.Sleep(100 * time.Millisecond)
	if st := o.node.Status().KillSwitch; out.rules() != nil || st.Active {
		t.Errorf("opted out, the kill switch went in: %+v", st)
	}
}

// A start narrows what a crashed run left to the down shape before it
// connects, so it fails closed until connected again; a start that comes
// up disconnected with nothing meant removes it.
func TestAStartTakesOverACrashedRunsKillSwitch(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	crashed := &firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: mustSet(t, "0.0.0.0/0")}

	host := &memKillSwitches{}
	host.put(crashed)
	b := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything),
		deviceOpt{prepare: func(_ *Config, p *Platform) {
			p.NewTUN = func(string, int) (wgtun.Device, error) { return nil, errors.New("no TUN today") }
		}})
	select {
	case err := <-b.done:
		if err == nil {
			t.Fatal("the start didn't fail")
		}
		b.done <- nil // for the cleanup
	case <-time.After(10 * time.Second):
		t.Fatal("the start didn't return")
	}
	if r := host.rules(); r == nil || r.TUN != "" || r.Allow.Contains(netip.MustParseAddr("203.0.113.7")) || !r.Allow.Contains(s.listen.Addr()) {
		t.Errorf("after a failed start the kill switch holds %+v", r)
	}

	host2 := &memKillSwitches{}
	host2.put(crashed)
	startDevice(t, s, reg, false, withKillSwitch(host2, nil), withPreset(rules.PresetEverything))
	inPlace(t, host2, "none")
}

// A kill switch that can't be applied is reported and retried; it never
// fails a connect.
func TestAFailingKillSwitchIsReportedAndRetried(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	host := &memKillSwitches{}
	host.failWith(errors.New("nftables says no"))
	b := startDevice(t, s, reg, true, withKillSwitch(host, func(c *Config) { c.KillSwitch = true }))
	b.connection(t, Connected)
	eventually(t, func() bool {
		st := b.node.Status().KillSwitch
		return !st.Enforced && st.Error == KillSwitchApplyFailed
	})
	if h := b.node.Status().Health(); !slices.Contains(h.Problems, ProblemKillSwitch) {
		t.Errorf("health %+v, want %s", h, ProblemKillSwitch)
	}
	host.failWith(nil)
	if err := b.node.SetAllowLAN(context.Background(), false); err != nil { // any change retries at once
		t.Fatal(err)
	}
	inPlace(t, host, "connected")
	eventually(t, func() bool { return b.node.Status().KillSwitch.Enforced })
}

// The node file's kill switch keys are the defaults until a member sets a
// toggle; the device file keeps a member's toggles, and writes them only
// once set.
func TestKillSwitchSettingsComeFromTheNodeThenTheMember(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, NodeFile), []byte(`{"kill_switch": true, "allow_lan": true, "fail_closed_after_crash": false}`), 0o600)
	cfg := testConfig(dir)
	cfg.FailClosedAfterCrash = true
	if err := ApplyNodeFile(&cfg, nil); err != nil {
		t.Fatal(err)
	}
	if !cfg.KillSwitch || !cfg.AllowLAN || cfg.FailClosedAfterCrash {
		t.Fatalf("config %+v", cfg)
	}
	n, err := Prepare(cfg, Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if ks := n.killSwitchSettings(); !ks.on || !ks.allowLAN || ks.failClosed {
		t.Errorf("before a member set anything: %+v", ks)
	}
	if st := n.Status().KillSwitch; !st.On || !st.AllowLAN {
		t.Errorf("status before a member set anything: %+v", st)
	}
	data, err := n.device.marshal()
	if err != nil || strings.Contains(string(data), "kill_switch") || strings.Contains(string(data), "allow_lan") {
		t.Errorf("unset toggles written: %s, %v", data, err)
	}
	off := false
	n.settingsMu.Lock()
	next := n.device
	next.KillSwitch = &off
	err = n.storeDevice(next)
	n.settingsMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if ks := n.killSwitchSettings(); ks.on || !ks.allowLAN {
		t.Errorf("after the member turned it off: %+v", ks)
	}
	n2, err := Prepare(cfg, Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if ks := n2.killSwitchSettings(); ks.on || !ks.allowLAN {
		t.Errorf("the next start: %+v, want the member's off and the node's allow-LAN", ks)
	}
}

// countingKillSwitch counts its Applies.
type countingKillSwitch struct{ applies int }

func (c *countingKillSwitch) Apply(context.Context, firewall.KillSwitchRules) error {
	c.applies++
	return nil
}

func (c *countingKillSwitch) Close() error { return nil }

// The kill switch in place is applied again at every killSwitchReapply
// tick, the tick handled a little after it fired included: on Linux that
// renews the direct destinations well within firewall.DirectTimeout.
func TestTheKillSwitchIsReappliedAtEveryTick(t *testing.T) {
	ks := &countingKillSwitch{}
	clock := time.Unix(1_000_000, 0)
	k := killSwitchKeeper{newKS: func() KillSwitch { return ks }, log: slog.New(slog.DiscardHandler), now: func() time.Time { return clock }}
	r := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: mustSet(t, "203.0.113.50/32")}
	tick := clock
	for i := range 6 {
		// The node loop handles a tick late, by more or less each time.
		clock = tick.Add(time.Duration(50-49*(i%2)) * time.Millisecond)
		k.keep(context.Background(), true, r)
		if ks.applies != i+1 {
			t.Fatalf("tick %d: %d applies, want %d", i, ks.applies, i+1)
		}
		clock = tick.Add(killSwitchReapply / 4) // another event between ticks
		k.keep(context.Background(), true, r)
		if ks.applies != i+1 {
			t.Fatalf("an event %v after tick %d applied it again", killSwitchReapply/4, i)
		}
		tick = tick.Add(killSwitchReapply)
	}
	if firewall.DirectTimeout < 2*killSwitchReapply {
		t.Errorf("firewall.DirectTimeout %v leaves no stall margin over a %v re-apply", firewall.DirectTimeout, killSwitchReapply)
	}
}

// A start narrows a crashed run's kill switch before it restores the
// host: once the OS's resolvers are back, the crashed run's connected
// shape (on macOS, DNS to the direct upstreams from any socket) is gone.
func TestAStartNarrowsTheKillSwitchBeforeRestoringTheHost(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	host := &memKillSwitches{}
	host.put(&firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: mustSet(t, "0.0.0.0/0"),
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}})
	atRestore := make(chan *firewall.KillSwitchRules, 4)
	b := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything),
		deviceOpt{prepare: func(_ *Config, p *Platform) {
			p.RestoreDNS = func() error { atRestore <- host.rules(); return nil }
		}})
	select {
	case r := <-atRestore:
		if r == nil || r.TUN != "" || r.Upstreams != nil || r.Allow.Contains(netip.MustParseAddr("203.0.113.7")) {
			t.Errorf("the OS's resolvers were restored with the kill switch holding %+v, want the down shape", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the start restored no resolver configuration")
	}
	b.connection(t, Connected)
}

// A slow first start (here a TUN that hangs, then fails) under the crash
// posture holds the kill switch; a disconnect sent while it hangs, and
// waited on until the start fails (ErrNotRunning), is still recorded, so
// the next start comes up disconnected and removes it. Only the slow
// case: a start that fails at once serves the local API for
// milliseconds, so a disconnect almost never reaches it (`sudo thinkpol
// rollback`, TP-134, or the uninstall is the way out then).
func TestADisconnectWaitedOutThroughAFailingStartIsHonouredAtTheNextStart(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	host := &memKillSwitches{}
	rec := &memConnectRecord{}
	_ = rec.Save(true) // the member connected earlier in this boot
	service := func(c *Config, p *Platform) { c.Service, p.ConnectRecord = true, rec }
	inTUN, release := make(chan struct{}), make(chan struct{})
	entered, released := sync.OnceFunc(func() { close(inTUN) }), sync.OnceFunc(func() { close(release) })
	b := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything),
		deviceOpt{prepare: func(c *Config, p *Platform) {
			service(c, p)
			p.NewTUN = func(string, int) (wgtun.Device, error) {
				entered()
				<-release
				return nil, errors.New("no TUN today")
			}
		}})
	t.Cleanup(released) // before the node's cleanup waits for it
	<-inTUN
	inPlace(t, host, "down")
	disconnected := make(chan error, 1)
	go func() { disconnected <- b.node.Disconnect(context.Background()) }()
	eventually(t, func() bool { c, ok, _ := rec.Load(); return ok && !c })
	released()
	select {
	case err := <-b.done:
		if err == nil {
			t.Fatal("the start didn't fail")
		}
		b.done <- nil // for the cleanup
	case <-time.After(10 * time.Second):
		t.Fatal("the start didn't return")
	}
	if err := <-disconnected; !errors.Is(err, ErrNotRunning) {
		t.Errorf("Disconnect: %v, want ErrNotRunning", err)
	}
	inPlace(t, host, "down") // the crash posture holds while the agent is down

	next := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything), deviceOpt{prepare: service})
	next.connection(t, Disconnected)
	inPlace(t, host, "none")
}

// A disconnect whose caller gives up (Ctrl-C) before the busy node took
// it leaves the record as the node's own choice: the node goes on
// connecting, and so would a restart in this boot.
func TestADisconnectTheCallerAbandonsLeavesTheNodesChoiceRecorded(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	host := &memKillSwitches{}
	rec := &memConnectRecord{}
	_ = rec.Save(true) // the member connected earlier in this boot
	inTUN, release := make(chan struct{}), make(chan struct{})
	entered, released := sync.OnceFunc(func() { close(inTUN) }), sync.OnceFunc(func() { close(release) })
	b := startDevice(t, s, reg, true, withKillSwitch(host, nil), withPreset(rules.PresetEverything),
		deviceOpt{prepare: func(c *Config, p *Platform) {
			c.Service, p.ConnectRecord = true, rec
			virtual := p.NewTUN
			p.NewTUN = func(name string, mtu int) (wgtun.Device, error) {
				entered()
				<-release
				return virtual(name, mtu)
			}
		}})
	t.Cleanup(released) // before the node's cleanup waits for it
	<-inTUN
	ctx, cancel := context.WithCancel(context.Background())
	disconnected := make(chan error, 1)
	go func() { disconnected <- b.node.Disconnect(ctx) }()
	eventually(t, func() bool { c, ok, _ := rec.Load(); return ok && !c })
	cancel()
	if err := <-disconnected; !errors.Is(err, context.Canceled) {
		t.Errorf("Disconnect: %v, want context.Canceled", err)
	}
	if c, ok, _ := rec.Load(); !ok || !c {
		t.Error("the record says disconnected while the node goes on connecting")
	}
	released()
	b.connection(t, Connected)
	if c, _, _ := rec.Load(); !c {
		t.Error("the record says disconnected with the node connected")
	}
	inPlace(t, host, "up")
}

// A server starting on a host a device run left its kill switch on
// removes it: it would refuse the server's traffic.
func TestAServerStartRemovesADeviceRunsKillSwitch(t *testing.T) {
	s := newTestSpace(t)
	host := &memKillSwitches{}
	host.put(&firewall.KillSwitchRules{Mark: routetable.Mark, Allow: mustSet(t, "203.0.113.50/32")})
	plat := testPlatform()
	plat.NewKillSwitch = host.new
	n, err := Prepare(serverConfig(s.stateDir(t, s.a, 1)), Logs{}, plat)
	if err != nil {
		t.Fatal(err)
	}
	n.startKillSwitch(context.Background())
	if r := host.rules(); r != nil {
		t.Errorf("the device run's kill switch is still in place: %+v", r)
	}
}

// Before the node runs, the kill switch is reported not applied yet, not
// enforced: nothing has been put as meant; the health leaves that to the
// start.
func TestAKillSwitchNotAppliedYetIsSaidSo(t *testing.T) {
	s := newTestSpace(t)
	plat := testPlatform()
	plat.NewKillSwitch = (&memKillSwitches{}).new
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.KillSwitch = true
	n, err := Prepare(cfg, Logs{}, plat)
	if err != nil {
		t.Fatal(err)
	}
	st := n.Status()
	if k := st.KillSwitch; k.Enforced || k.Error != KillSwitchNotApplied || !k.On {
		t.Errorf("kill switch before the start: %+v, want on, not applied", k)
	}
	if slices.Contains(st.Health().Problems, ProblemKillSwitch) {
		t.Errorf("health %+v counts a kill switch not applied yet as failed", st.Health())
	}
}
