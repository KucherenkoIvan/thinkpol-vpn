package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// KillSwitch is the host's kill switch (firewall.KillSwitch: an nftables
// table on Linux, a pf anchor on macOS): Apply puts rules in place,
// replacing what any run left; Close removes it, whichever run put it
// there. What it leaves in place outlives the process.
type KillSwitch interface {
	Apply(ctx context.Context, r firewall.KillSwitchRules) error
	Close() error
}

// KillSwitchStatus is a device's kill switch as Status reports it.
type KillSwitchStatus struct {
	// On and AllowLAN are the toggles in effect: the device file's, else
	// the node's defaults.
	On, AllowLAN bool
	// Active: the rules are meant to be in place now (On, or the crash
	// posture while the connection is meant up).
	Active bool
	// Enforced: the host holds what is meant (in place, or rightly not);
	// Error says why not, a code: "apply_failed", "unsupported".
	Enforced bool
	Error    string
}

// killSwitchReapply is how often the kill switch in place is applied
// again: a re-apply checks it is whole and puts back what someone
// removed (`nft flush ruleset`, `pfctl -F`).
const killSwitchReapply = 10 * time.Second

// crashPresets are the presets whose devices fail closed after a crash
// with the kill switch off (PRD D4, "Crash posture").
var crashPresets = []rules.Preset{rules.PresetEverything, rules.PresetAllButDomestic}

// killSwitchSettings are what decides the kill switch, but for the
// connection.
type killSwitchSettings struct {
	on, allowLAN, failClosed bool
	preset                   rules.Preset
}

// killSwitchView is the connection as the kill switch sees it.
type killSwitchView struct {
	// meantUp: the connection is meant up (connecting, connected,
	// retrying, removed): a crash now must fail closed.
	meantUp bool
	// connected is the route table's exemptions while the data plane is
	// up (the connected shape), nil while it is down; tun is its TUN.
	connected *routetable.Exempt
	tun       string
	// entries are the endpoints of the device's links in its section.
	entries []netip.Addr
}

// active is whether the rules are meant to be in place.
func (s killSwitchSettings) active(meantUp bool) bool {
	return s.on || s.failClosed && meantUp && slices.Contains(crashPresets, s.preset)
}

// rules are the kill switch's rules for v: the down shape (the entries)
// or, connected, the connected one (the TUN, the direct destinations and
// the direct upstreams too), with the LAN when allowed.
func (s killSwitchSettings) rules(v killSwitchView) firewall.KillSwitchRules {
	var b lists.Builder
	for _, a := range v.entries {
		_ = b.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // unmapped, valid
	}
	if s.allowLAN {
		for _, p := range firewall.LAN {
			_ = b.AddPrefix(p)
		}
	}
	r := firewall.KillSwitchRules{Mark: routetable.Mark}
	r.Allow, _ = b.Build()
	if v.connected != nil {
		r.TUN, r.Direct, r.Upstreams = v.tun, v.connected.Direct, slices.Clone(v.connected.Upstreams)
	}
	return r
}

// entries are the endpoint addresses of the links in section.
func entries(section netmap.Section) []netip.Addr {
	var out []netip.Addr
	for _, l := range section.Links {
		for _, e := range l.Endpoints {
			if a := e.Address.Addr().Unmap().WithZone(""); a.IsValid() && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// killSwitchKeeper puts the kill switch in place or removes it as asked,
// on the goroutine that runs the node; what it leaves is left when the
// process ends.
type killSwitchKeeper struct {
	newKS func() KillSwitch
	log   *slog.Logger
	// ks is the kill switch it holds; nil before the first call, after a
	// Close, and on a host without one.
	ks KillSwitch
	// applied is what is in place (nil: nothing, as far as it knows);
	// removed says Close succeeded since.
	applied *firewall.KillSwitchRules
	removed bool
	// failed is the last call's failure; reapplyAt when the rules in
	// place are applied again.
	failed    error
	reapplyAt time.Time
}

// keep puts r in place (want), or removes what any run left (!want).
// Applying what is in place again is due only every killSwitchReapply,
// or after a failure.
func (k *killSwitchKeeper) keep(ctx context.Context, want bool, r firewall.KillSwitchRules) {
	if k.newKS == nil {
		return
	}
	now := time.Now()
	if !want {
		if k.removed && k.failed == nil {
			return
		}
		ks := k.ks
		if ks == nil {
			ks = k.newKS()
		}
		k.ks, k.applied = nil, nil
		if ks == nil {
			k.removed, k.failed = true, nil
			return
		}
		if err := ks.Close(); err != nil {
			k.fail(errors.Join(errKillSwitchRemove, err))
			k.ks = ks // tried again on the next call
			return
		}
		k.removed, k.failed = true, nil
		k.log.Info("kill switch removed")
		return
	}
	if k.applied != nil && k.applied.Equal(r) && k.failed == nil && now.Before(k.reapplyAt) {
		return
	}
	if k.ks == nil {
		if k.ks = k.newKS(); k.ks == nil {
			k.fail(firewall.ErrKillSwitchUnsupported)
			return
		}
	}
	first := k.applied == nil || !k.applied.Equal(r)
	if err := k.ks.Apply(ctx, r); err != nil {
		k.applied = nil
		k.fail(err)
		return
	}
	k.applied, k.removed, k.failed, k.reapplyAt = &r, false, nil, now.Add(killSwitchReapply)
	if first {
		k.log.Info("kill switch in place", "tunnel", onOff(r.TUN != ""), "allowed_ranges", len(r.Allow.Ranges()))
	}
}

// errKillSwitchRemove: removing the kill switch failed.
var errKillSwitchRemove = errors.New("removing the kill switch failed")

func (k *killSwitchKeeper) fail(err error) {
	if k.failed == nil || k.failed.Error() != err.Error() {
		k.log.Warn("kill switch not enforced, retrying", "err", err)
	}
	k.failed = err
}

// status is what Status says of it.
func (k *killSwitchKeeper) status(s killSwitchSettings, active bool) KillSwitchStatus {
	st := KillSwitchStatus{On: s.on, AllowLAN: s.allowLAN, Active: active, Enforced: k.failed == nil}
	switch {
	case k.failed == nil:
	case errors.Is(k.failed, firewall.ErrKillSwitchUnsupported):
		st.Error = "unsupported"
	default:
		st.Error = "apply_failed"
	}
	return st
}

// killSwitchSettings are the device's kill switch settings in effect:
// its device file's toggles, else the node's defaults.
func (n *Node) killSwitchSettings() killSwitchSettings {
	n.settingsMu.Lock()
	defer n.settingsMu.Unlock()
	s := killSwitchSettings{on: n.cfg.KillSwitch, allowLAN: n.cfg.AllowLAN, failClosed: n.cfg.FailClosedAfterCrash, preset: n.device.Rules.Preset}
	if v := n.device.KillSwitch; v != nil {
		s.on = *v
	}
	if v := n.device.AllowLAN; v != nil {
		s.allowLAN = *v
	}
	return s
}

// enforceKillSwitch puts the kill switch in place for v, or removes it,
// as the settings say, and reports it. Only the goroutine that runs a
// device calls it.
func (n *Node) enforceKillSwitch(ctx context.Context, v killSwitchView) {
	s := n.killSwitchSettings()
	active := s.active(v.meantUp)
	n.ks.keep(ctx, active, s.rules(v))
	st := n.ks.status(s, active)
	n.report.set(func(p *report) { p.killSwitch = st })
}

// SetKillSwitch sets a device's kill switch toggle, stored in DeviceFile
// (only the service writes it), and returns once the node acted on it
// (Status shows what it did). ErrServerMode on a server.
func (n *Node) SetKillSwitch(ctx context.Context, on bool) error {
	return n.setToggle(ctx, func(s *DeviceSettings) { s.KillSwitch = &on }, "kill switch set", "kill_switch", on)
}

// SetAllowLAN sets whether a device's kill switch lets the LAN out
// (firewall.LAN), stored in DeviceFile, and returns once the node acted
// on it. ErrServerMode on a server.
func (n *Node) SetAllowLAN(ctx context.Context, on bool) error {
	return n.setToggle(ctx, func(s *DeviceSettings) { s.AllowLAN = &on }, "allow-LAN set", "allow_lan", on)
}

// setToggle stores the toggle set changes, then has the node's goroutine
// act on it and waits for that; a node that stopped takes it at its next
// start.
func (n *Node) setToggle(ctx context.Context, set func(*DeviceSettings), msg, key string, on bool) error {
	if n.Mode() == ModeServer {
		return ErrServerMode
	}
	n.settingsMu.Lock()
	next := n.device
	set(&next)
	err := n.storeDevice(next)
	n.settingsMu.Unlock()
	if err != nil {
		return err
	}
	s := n.killSwitchSettings()
	n.report.set(func(p *report) { p.killSwitch.On, p.killSwitch.AllowLAN = s.on, s.allowLAN })
	n.logs.Info(msg, key, onOff(on))
	done := make(chan struct{})
	select {
	case n.killSwitchRequests <- done:
	case <-n.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
