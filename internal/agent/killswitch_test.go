package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	for _, a := range []string{"203.0.113.50", "198.51.100.7", "2001:db8:d0::7", "10.1.2.3", "fe80::1", "ff02::fb"} {
		if !conn.Allow.Contains(netip.MustParseAddr(a)) {
			t.Errorf("the connected shape with allow-LAN doesn't let %s out", a)
		}
	}
	if conn.Allow.Contains(netip.MustParseAddr("203.0.113.7")) || conn.TUN != "thinkpol0" || len(conn.Upstreams) != 1 {
		t.Errorf("connected shape %+v %v", conn, conn.Allow.Prefixes())
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
	if err := b.node.SetKillSwitch(true); err != nil {
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
	if err := b.node.SetAllowLAN(true); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { r := host.rules(); return r != nil && r.Allow.Contains(netip.MustParseAddr("192.168.1.1")) })
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	inPlace(t, host, "down")
	if err := b.node.SetKillSwitch(false); err != nil {
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
	eventually(t, func() bool { st := b.node.Status().KillSwitch; return !st.Enforced && st.Error == "apply_failed" })
	host.failWith(nil)
	if err := b.node.SetAllowLAN(false); err != nil { // any change retries at once
		t.Fatal(err)
	}
	inPlace(t, host, "connected")
	eventually(t, func() bool { return b.node.Status().KillSwitch.Enforced })
}
