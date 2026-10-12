package dataplane

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// RuleStatus is how the routing rules are enforced. Like the rest of
// Status it quotes nothing from the rules: skipped rules are named by
// origin and position.
type RuleStatus struct {
	// Preset is the base under the device's own rules: its choice, or the
	// space's rules when the map can't build that preset
	// (PresetUnavailable).
	Preset            rules.Preset
	PresetUnavailable bool
	// Direct4 and Direct6 count the prefixes that go around the tunnel,
	// which route-table mode installs as routes.
	Direct4, Direct6 int
	// Skipped are the rules not enforced as written, and why.
	Skipped []rules.Skip
}

// exitDevice names the WireGuard device (and router egress) of a chain's
// exit: one per exit, since each claims the internet as allowed IPs.
func exitDevice(exit netmap.NodeID) string { return "exit-" + exit.String() }

// chainExits are the chains that can carry traffic, by name: those whose
// exit is a usable WireGuard peer.
func chainExits(chains []netmap.Chain, peers []OverlayPeer) map[string]netmap.NodeID {
	usable := make(map[netmap.NodeID]bool, len(peers))
	for _, p := range peers {
		usable[p.ID] = true
	}
	out := make(map[string]netmap.NodeID, len(chains))
	for _, c := range chains {
		if usable[c.Exit] {
			out[c.Name] = c.Exit
		}
	}
	return out
}

// layout puts the exit of each chain the rules use on a device of its
// own, allowed the internet, and every other peer on the overlay device.
func (e *Engine) layout(oc OverlayConfig) map[string][]devicePeer {
	want := overlayOnly(oc)
	exits := e.usedExits
	if len(exits) == 0 {
		return want
	}
	var overlay []devicePeer
	for _, p := range want[OverlayDevice] {
		if !exits[p.ID] {
			overlay = append(overlay, p)
			continue
		}
		p.AllowedIPs = exitAllowedIPs(p.Addresses, oc)
		want[exitDevice(p.ID)] = []devicePeer{p}
	}
	want[OverlayDevice] = overlay
	return want
}

// exitAllowedIPs are what WireGuard sends an exit and accepts from it: the
// internet, and of the overlay only the exit's own addresses, so an exit
// can't pass its packets off as another peer's. IPv6 only while the
// overlay carries it.
func exitAllowedIPs(own []netip.Addr, oc OverlayConfig) []netip.Prefix {
	var b lists.Builder
	b.AddSet(lists.All().Minus(prefixSet(oc.Networks)))
	for _, a := range own {
		_ = b.AddPrefix(netip.PrefixFrom(a, a.BitLen()))
	}
	s, _ := b.Build()
	out := s.Prefixes()
	if oc.IPv6Off != nil {
		out = slices.DeleteFunc(out, func(p netip.Prefix) bool { return p.Addr().Is6() })
	}
	return out
}

func prefixSet(prefixes []netip.Prefix) *lists.Set {
	var b lists.Builder
	for _, p := range prefixes {
		_ = b.AddPrefix(p)
	}
	s, _ := b.Build()
	return s
}

// ruleInput is what a section gives the rules.
type ruleInput struct {
	rules   []netmap.Rule
	presets netmap.RulePresets
	blobs   []netmap.BlobRef
}

func ruleInputOf(s netmap.Section) *ruleInput {
	return &ruleInput{rules: s.Rules, presets: s.Presets, blobs: s.Blobs}
}

// compileRules compiles the device's rules from a section's, with the
// space's overlay networks, against the chains e.chainExit can carry. The
// result routes nothing until the next layout and router table. A preset
// the map can't build, or whose chain can't carry traffic, is compiled
// failing closed and reported as ErrPresetUnavailable.
func (e *Engine) compileRules(s *ruleInput, networks []netip.Prefix) error {
	entries, err := rules.Effective(s.rules, s.presets, e.ownRules)
	if _, ok := e.chainExit[s.presets.Chain]; err == nil && e.ownRules.Preset != rules.PresetSpace && !ok {
		err = fmt.Errorf("%w: chain unavailable", rules.ErrPresetUnavailable)
	}
	standIns := make(map[[32]byte]bool)
	t := rules.Compile(entries, rules.Options{
		Overlay: networks,
		GeoIP:   e.geoip(s.blobs, standIns),
		Chain:   func(name string) bool { _, ok := e.chainExit[name]; return ok },
	})
	inUse := standIns
	for _, b := range s.blobs {
		inUse[b.SHA256] = true
	}
	for sum := range e.geoipSets {
		if !inUse[sum] {
			delete(e.geoipSets, sum)
		}
	}
	e.ruleTable = t
	e.ruleInput = s
	e.ruleNetworks = networks
	e.usedExits = make(map[netmap.NodeID]bool)
	for _, c := range t.Chains() {
		e.usedExits[e.chainExit[c]] = true
	}
	e.ruleStatus = RuleStatus{Preset: e.ownRules.Preset, PresetUnavailable: err != nil, Skipped: slices.Clone(t.Skipped())}
	for _, p := range t.Direct().Prefixes() {
		if p.Addr().Is4() {
			e.ruleStatus.Direct4++
		} else {
			e.ruleStatus.Direct6++
		}
	}
	return err
}

// geoip resolves a list name to the section's geoip blob of that name, as
// cfg.Blobs has it, or while it hasn't, the previous version cfg.StandIn
// has (noted in standIns), checked and decoded once per hash. A name two
// blobs claim, a blob the node doesn't have or one that doesn't check out
// resolves to nothing.
func (e *Engine) geoip(blobs []netmap.BlobRef, standIns map[[32]byte]bool) func(string) (*lists.Set, bool) {
	named := make(map[string][]netmap.BlobRef)
	for _, b := range blobs {
		if b.Kind == netmap.BlobGeoIP && b.Name != "" {
			named[b.Name] = append(named[b.Name], b)
		}
	}
	return func(name string) (*lists.Set, bool) {
		refs := named[name]
		if len(refs) != 1 {
			return nil, false
		}
		ref := refs[0]
		if s, ok := e.geoipSets[ref.SHA256]; ok {
			return s, true
		}
		var b []byte
		ok := false
		if e.cfg.Blobs != nil {
			b, ok = e.cfg.Blobs(ref)
		}
		if !ok && e.cfg.StandIn != nil {
			var prev netmap.BlobRef
			if prev, b, ok = e.cfg.StandIn(ref.Kind, ref.Name); ok && prev.Kind == ref.Kind && prev.Name == ref.Name {
				ref = prev
				standIns[ref.SHA256] = true
				if s, cached := e.geoipSets[ref.SHA256]; cached {
					return s, true
				}
			} else {
				ok = false
			}
		}
		if !ok {
			return nil, false
		}
		if uint64(len(b)) != ref.Size || sha256.Sum256(b) != ref.SHA256 {
			e.debug("geoip blob does not match its reference", "list", name)
			return nil, false
		}
		s, err := lists.Decode(b)
		if err != nil {
			e.debug("geoip blob does not decode", "list", name, "err", err)
			return nil, false
		}
		e.geoipSets[ref.SHA256] = s
		return s, true
	}
}

// ruleRoutes are the router's rule routes for the compiled rules: a
// chain's destinations to its exit's egress, blocked ones (and a chain's
// whose egress isn't there) to none. Direct destinations get Direct
// routes: in route-table mode they never enter the TUN, and one that does
// anyway is dropped and counted rather than sent through an exit.
func (e *Engine) ruleRoutes(egresses map[string]*router.Egress) []router.Route {
	if e.ruleTable == nil {
		return nil
	}
	routes := e.ruleTable.Routes()
	out := make([]router.Route, 0, len(routes))
	for _, r := range routes {
		rt := router.Route{Prefix: r.Prefix, Direct: r.Action.Kind == netmap.ActionDirect}
		if exit, ok := e.chainExit[r.Action.Chain]; ok && r.Action.Kind == netmap.ActionChain {
			rt.Egress = egresses[exitDevice(exit)]
		}
		out = append(out, rt)
	}
	return out
}

// SetRules replaces the device's own rule choice (its local file) and
// enforces the result at once, without waiting for a map. A preset the
// map can't build is enforced failing closed (see rules.PresetRules) and
// reported with rules.ErrPresetUnavailable.
func (e *Engine) SetRules(l rules.Local) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}
	e.ownRules = l
	return e.recompileRules()
}

// ReloadRules compiles the rules again with the blobs cfg.Blobs has now:
// call it when a list the rules use arrives.
func (e *Engine) ReloadRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}
	return e.recompileRules()
}

// recompileRules compiles the rules again and lays the devices out for
// them: a chain the rules start or stop using moves its exit.
func (e *Engine) recompileRules() error {
	if e.ruleInput == nil || e.overlay == nil {
		return nil // the first Apply that can run compiles them
	}
	unavailable := e.compileRules(e.ruleInput, e.ruleNetworks)
	want := e.assign(*e.overlay)
	if err := e.removePeers(want, true, e.paths); err != nil {
		return err
	}
	if err := e.addPeers(want, e.paths, e.mtu); err != nil {
		return err
	}
	if err := e.setTable(); err != nil {
		return err
	}
	return unavailable
}

// setTable gives the router the table for what runs now; Status reports
// the rules that table enforces.
func (e *Engine) setTable() error {
	t := e.table()
	if err := e.router.SetTable(t); err != nil {
		return err
	}
	e.routedRules, e.routedExit = e.ruleStatus, len(t.Forward) > 0
	return nil
}
