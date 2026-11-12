package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"runtime"
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
	// Error says why not.
	Enforced bool
	Error    KillSwitchError
}

// KillSwitchError is why a kill switch isn't enforced, a code the local
// API passes on.
type KillSwitchError string

const (
	// KillSwitchApplyFailed: putting it in place failed; retried.
	KillSwitchApplyFailed KillSwitchError = "apply_failed"
	// KillSwitchRemoveFailed: removing it failed; retried.
	KillSwitchRemoveFailed KillSwitchError = "remove_failed"
	// KillSwitchUnsupported: the OS can't hold it.
	KillSwitchUnsupported KillSwitchError = "unsupported"
	// KillSwitchNotApplied: the node hasn't put it as meant yet (it
	// hasn't started, or waits as a server's section in device mode,
	// leaving the host as it is).
	KillSwitchNotApplied KillSwitchError = "not_applied"
)

// killSwitchReapply is how often the kill switch in place is applied
// again: a re-apply checks it is whole and puts back what someone
// removed of its own table or anchor (`nft flush ruleset`, a flush of
// its anchor), and on Linux renews the direct destinations
// (firewall.DirectTimeout). On macOS a flush of the main ruleset
// (`pfctl -F all`, a pf.conf loaded without `anchor "com.apple/*"`)
// removes Apple's hook, under which the anchor is evaluated at all:
// that isn't repaired here (the agent doesn't reload /etc/pf.conf), and
// the kill switch stays not enforced until the hook is back.
const killSwitchReapply = 10 * time.Second

// killSwitchStopTimeout bounds the last apply as the node returns, its
// own context done: a hung pfctl mustn't hold the stop.
const killSwitchStopTimeout = 10 * time.Second

// KillSwitchStopNote is what the agent warns as it stops with the kill
// switch in place (the toggle, or the crash posture while meant up), and
// what the kill-switch command's help says: a stop leaves it, as a crash
// does (docs/design/security.md, "A stop is not a disconnect").
const KillSwitchStopNote = "a stop leaves the kill switch in place, as a crash does: only the entries (and the LAN with allow-LAN) are reachable until the agent runs again; to stop with traffic going direct, run `thinkpol kill-switch off` and `thinkpol disconnect` first, or `thinkpol service uninstall`"

// warnLeftInPlace warns, as the node returns, when it leaves the kill
// switch in place.
func (k *killSwitchKeeper) warnLeftInPlace() {
	if k.applied != nil {
		k.log.Warn("the agent stops; " + KillSwitchStopNote)
	}
}

// crashPresets are the presets whose devices fail closed after a crash
// with the kill switch off (PRD D4, "Crash posture").
var crashPresets = []rules.Preset{rules.PresetEverything, rules.PresetAllButDomestic}

// killSwitchSettings are what decides the kill switch, but for the
// connection.
type killSwitchSettings struct {
	on, allowLAN, failClosed bool
	preset                   rules.Preset
	// marked: the links' sockets pass the kill switch by their mark
	// (Linux), before its DNS refusals; else (macOS) DNS to an entry
	// that serves its transport on a DNS port must be let through.
	marked bool
}

// linksMarked is killSwitchSettings.marked on this OS.
const linksMarked = runtime.GOOS == "linux"

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
	entries []netip.AddrPort
}

// active is whether the rules are meant to be in place.
func (s killSwitchSettings) active(meantUp bool) bool {
	return s.on || s.failClosed && meantUp && slices.Contains(crashPresets, s.preset)
}

// rules are the kill switch's rules for v: the down shape (the entries)
// or, connected, the connected one (the TUN, the direct destinations and
// the direct upstreams too), with the LAN when allowed. Down, DNS to the
// LAN is refused even with allow-LAN (owner, 2026-11-12): the OS is back
// on its own resolvers, a home router that forwards lookups in the
// clear. An entry on the LAN that is also its resolver gets none either:
// on Linux the links' sockets pass by their mark, before the refusals;
// on macOS (no mark) only an entry whose transport is on port 53 or 853
// is spared, or its link couldn't come up.
func (s killSwitchSettings) rules(v killSwitchView) firewall.KillSwitchRules {
	var eb, db, lb, ab lists.Builder
	for _, e := range v.entries {
		a := e.Addr()
		_ = eb.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // unmapped, valid
		if !s.marked && (e.Port() == 53 || e.Port() == 853) {
			_ = db.AddPrefix(netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, p := range firewall.LAN {
		_ = lb.AddPrefix(p)
	}
	ents, _ := eb.Build()
	r := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: ents}
	if s.allowLAN {
		lan, _ := lb.Build()
		ab.AddSet(ents)
		ab.AddSet(lan)
		r.Allow, _ = ab.Build()
		if v.connected == nil {
			onDNSPorts, _ := db.Build()
			r.NoDNS = lan.Minus(onDNSPorts)
		}
	}
	if v.connected != nil {
		r.TUN, r.Direct, r.Upstreams = v.tun, v.connected.Direct, slices.Clone(v.connected.Upstreams)
	}
	return r
}

// entries are the endpoints of the links in section, their addresses
// unmapped and without a zone.
func entries(section netmap.Section) []netip.AddrPort {
	var out []netip.AddrPort
	for _, l := range section.Links {
		for _, e := range l.Endpoints {
			a := e.Address.Addr().Unmap().WithZone("")
			if ap := netip.AddrPortFrom(a, e.Address.Port()); a.IsValid() && !slices.Contains(out, ap) {
				out = append(out, ap)
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
	// now is the clock; nil is time.Now.
	now func() time.Time
}

// keep puts r in place (want), or removes what any run left (!want).
// Applying what is in place again is due at the next killSwitchReapply
// tick, or after a failure.
func (k *killSwitchKeeper) keep(ctx context.Context, want bool, r firewall.KillSwitchRules) {
	if k.newKS == nil {
		return
	}
	now := time.Now()
	if k.now != nil {
		now = k.now()
	}
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
	// Half a period: the ticker's next tick comes a period after the one
	// handled here, which is earlier than a period after now; due at a
	// whole period, every other tick would be skipped (20 s, not 10 s).
	k.applied, k.removed, k.failed, k.reapplyAt = &r, false, nil, now.Add(killSwitchReapply/2)
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
		st.Error = KillSwitchUnsupported
	case errors.Is(k.failed, errKillSwitchRemove):
		st.Error = KillSwitchRemoveFailed
	default:
		st.Error = KillSwitchApplyFailed
	}
	return st
}

// killSwitchSettings are the device's kill switch settings in effect:
// its device file's toggles, else the node's defaults.
func (n *Node) killSwitchSettings() killSwitchSettings {
	n.settingsMu.Lock()
	defer n.settingsMu.Unlock()
	s := killSwitchSettings{on: n.cfg.KillSwitch, allowLAN: n.cfg.AllowLAN, failClosed: n.cfg.FailClosedAfterCrash, preset: n.device.Rules.Preset, marked: linksMarked}
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
