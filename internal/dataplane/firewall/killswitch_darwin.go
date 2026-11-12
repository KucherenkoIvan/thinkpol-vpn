package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The kill switch's pf objects: an anchor under Apple's hook that sorts
// after the guard's (the guard counts any anchor before its own as a
// bypass), its table, and the record of its own enable reference.
const (
	KillSwitchAnchor = "com.apple/001.thinkpol-killswitch"
	killSwitchTable  = "thinkpol_killswitch"
	killSwitchNoDNS  = "thinkpol_killswitch_nodns"
	killSwitchRecord = "pf-killswitch.token"
	killSwitchHeader = "# thinkpol firewall: the pf enable reference (pfctl -E) the kill switch holds; released with pfctl -X"
)

// KillSwitch keeps everything but KillSwitchRules from leaving the
// device, both families, with a pf anchor, KillSwitchAnchor, and its two
// tables (what passes, and NoDNS), loaded together by one `pfctl -a <anchor> -f - -o none`
// (killSwitchRules lists the rules), with pf enabled by a reference of
// its own, recorded in netcfg.StateDir as the guard's is. The anchor and
// the reference stay when the process dies; Close removes the anchor's
// rules and table and releases the reference, a fresh kill switch's a
// previous run's (its record, this boot).
//
// Apply checks the main ruleset has Apple's hook (without it nothing is
// enforced: an ordinary failure, retried), loads the anchor unless it
// holds exactly what the last load left (the rules as pfctl listed them,
// the tables entry for entry), enables pf, and kills the states, of
// either family, whose other end isn't in the table: pf passes a state
// without rules. A load pf took is enabled even when its read-back
// fails: its rules are in pf, unchecked, and with pf off (a stock Mac)
// they would be evaluated not at all. Unlike the guard it doesn't look for what passes before
// its anchor (quick passes above the hook, earlier anchors, skipped
// interfaces): the guard's anchor sorts before it on purpose.
type KillSwitch struct {
	mu sync.Mutex
	pfEnabler
	own func() ([]netip.Addr, error)

	// applied is what the last good load put in place, nil until then.
	applied *appliedKillSwitch
	// killStates: pf's states still need checking against applied.
	killStates bool
	closed     bool
}

// appliedKillSwitch is a load: its rules, the table loaded and the
// anchor's rules as pfctl listed them after it.
type appliedKillSwitch struct {
	rules        KillSwitchRules
	table, noDNS []netip.Prefix
	listed       []string
}

// allows reports whether the table lets anything out to addr.
func (a *appliedKillSwitch) allows(addr netip.Addr) bool {
	return slices.ContainsFunc(a.table, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// NewKillSwitch returns the host's kill switch, its record in
// netcfg.StateDir. Nothing changes until Apply or Close.
func NewKillSwitch() *KillSwitch {
	return newKillSwitch(execPfctl{path: pfctlPath, timeout: pfctlTimeout},
		tokenStore{dir: netcfg.StateDir, boot: trusteddir.BootSession, record: killSwitchRecord, header: killSwitchHeader}, hostAddrs)
}

func newKillSwitch(pf pfctl, tokens tokenStore, own func() ([]netip.Addr, error)) *KillSwitch {
	k := &KillSwitch{own: own, pfEnabler: pfEnabler{pf: pf, tokens: tokens}}
	k.stale = func() { k.killStates = true }
	return k
}

// Apply puts r in place: the anchor, then pf enabled by the kill
// switch's reference, then the states the anchor would refuse killed.
// Applying what is in place again reads it back and reloads it if it
// differs. A failed load leaves what was there (one pf transaction).
func (k *KillSwitch) Apply(ctx context.Context, r KillSwitchRules) (err error) {
	if r.TUN != "" && !validInterface.MatchString(r.TUN) {
		return fmt.Errorf("firewall: TUN %q isn't an interface name", r.TUN)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return errKillSwitchClosed
	}
	defer func() { err = killSwitchUnsupported(err) }()
	if _, err := checkHook(ctx, k.pf); err != nil {
		k.killStates = true // pf may evaluate no anchor meanwhile
		return err
	}
	if a := k.applied; a == nil || !a.rules.Equal(r) || !k.intact(ctx, a) {
		k.applied = nil
		a, loaded, err := k.load(ctx, r)
		if err != nil && loaded {
			// pf took the text: kill the states its table refuses, as
			// after a good load, or a read-back that keeps failing leaves
			// them passing. Not recorded as applied: the next Apply
			// loads it again, and kills again.
			k.killStates = true
			after, eerr := k.enable(ctx)
			var kerr error
			if eerr == nil {
				kerr = killStates(ctx, k.pf, k.own, a.allows, true, "the kill switch refuses")
			}
			return errors.Join(err, eerr, kerr, after)
		}
		if err != nil {
			return err
		}
		k.applied, k.killStates = a, true
	}
	after, err := k.enable(ctx)
	if err == nil && k.killStates {
		if err = killStates(ctx, k.pf, k.own, k.applied.allows, true, "the kill switch refuses"); err == nil {
			k.killStates = false
		}
	}
	return errors.Join(err, after)
}

// load loads r's anchor and reads it back: the rules checked for their
// words (checkListed), the tables entry for entry. loaded says pf took
// the load, whatever the read-back found; when it did and the read-back
// failed, a holds what was loaded, unchecked (no listing).
func (k *KillSwitch) load(ctx context.Context, r KillSwitchRules) (a *appliedKillSwitch, loaded bool, err error) {
	var b lists.Builder
	b.AddSet(r.Allow)
	b.AddSet(r.Direct)
	all, _ := b.Build()
	table, upstreams := all.Prefixes(), killSwitchUpstreams(r.Upstreams)
	var noDNS []netip.Prefix
	if r.NoDNS != nil {
		noDNS = r.NoDNS.Prefixes()
	}
	rules := killSwitchRules(r.TUN, upstreams)
	text := tableDef(killSwitchNoDNS, noDNS) + tableText(killSwitchTable, table, rules)
	if _, err := k.pf.run(ctx, []byte(text), "-a", KillSwitchAnchor, "-f", "-", "-o", "none"); err != nil {
		return nil, false, fmt.Errorf("firewall: load the kill switch: %w", err)
	}
	unchecked := &appliedKillSwitch{rules: r, table: table, noDNS: noDNS}
	listed, err := k.listRules(ctx)
	if err != nil {
		return unchecked, true, err
	}
	if err := checkListed(listed, rules, "kill switch"); err != nil {
		return unchecked, true, err
	}
	got := map[string][]netip.Prefix{}
	for name, want := range map[string][]netip.Prefix{killSwitchTable: table, killSwitchNoDNS: noDNS} {
		if got[name], err = listTable(ctx, k.pf, KillSwitchAnchor, name, true, "kill switch"); err != nil {
			return unchecked, true, err
		}
		if !slices.Equal(got[name], sortedPrefixes(slices.Clone(want))) {
			return unchecked, true, fmt.Errorf("firewall: pf's table %s holds %d entries unlike the %d loaded", name, len(got[name]), len(want))
		}
	}
	return &appliedKillSwitch{rules: r, table: got[killSwitchTable], noDNS: got[killSwitchNoDNS], listed: listed}, true, nil
}

func (k *KillSwitch) listRules(ctx context.Context) ([]string, error) {
	b, _, err := rulesOf(ctx, k.pf, KillSwitchAnchor, false)
	if err != nil {
		return nil, err
	}
	return readLines(b)
}

// intact reports whether the anchor still holds exactly a.
func (k *KillSwitch) intact(ctx context.Context, a *appliedKillSwitch) bool {
	listed, err := k.listRules(ctx)
	if err != nil || !slices.Equal(listed, a.listed) {
		return false
	}
	table, err := listTable(ctx, k.pf, KillSwitchAnchor, killSwitchTable, true, "kill switch")
	if err != nil || !slices.Equal(table, a.table) {
		return false
	}
	noDNS, err := listTable(ctx, k.pf, KillSwitchAnchor, killSwitchNoDNS, true, "kill switch")
	return err == nil && slices.Equal(noDNS, a.noDNS)
}

// Close flushes the anchor's rules and tables, then releases the
// references the kill switch holds or owes, or the one its record holds
// from this boot (a previous run's). A failure leaves the rest in place
// for another Close; the anchor goes first, so pf is never left off with
// it meant to be in place. With no pfctl at all there is nothing to
// remove.
func (k *KillSwitch) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	ctx := context.Background()
	k.applied = nil
	err := flushAnchor(ctx, k.pf, KillSwitchAnchor, true, "kill switch", killSwitchTable, killSwitchNoDNS)
	if errors.Is(err, errNoPfctl) {
		err = k.forget()
	} else if err == nil {
		err = k.releaseAll(ctx)
	}
	if err != nil {
		return killSwitchUnsupported(err)
	}
	k.closed = true
	return nil
}

// killSwitchUnsupported is err, wrapping ErrKillSwitchUnsupported too
// when there is no pfctl (errNoPfctl).
func killSwitchUnsupported(err error) error {
	if errors.Is(err, errNoPfctl) {
		return fmt.Errorf("%w: %w", ErrKillSwitchUnsupported, err)
	}
	return err
}

// killSwitchUpstreams are the direct DNS upstreams the kill switch passes
// DNS to, on their ports: link-local ones aside (pf can't name them
// without their interface; allow-LAN lets them out).
func killSwitchUpstreams(ups []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for _, ap := range ups {
		a := ap.Addr().Unmap().WithZone("")
		if !a.IsLinkLocalUnicast() && !a.IsUnspecified() && ap.Port() != 0 {
			out = append(out, netip.AddrPortFrom(a, ap.Port()))
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(out)
}

// killSwitchRules are the anchor's rules, in order:
//
//	pass out quick on lo0 all no state
//	pass out quick on <utun> all no state                                             (connected only)
//	block return out quick proto { tcp, udp } from any to <thinkpol_killswitch_nodns> port 53
//	block return out quick proto { tcp, udp } from any to <thinkpol_killswitch_nodns> port 853
//	pass out quick from any to <thinkpol_killswitch> no state
//	pass out quick proto { tcp, udp } from any to <upstream> port <its port> no state (each upstream)
//	pass out quick inet proto udp from any port 68 to any port 67 no state            (DHCPv4)
//	pass out quick inet6 proto udp from any port 546 to { ff02::1:2, fe80::/10 } port 547 no state (DHCPv6, two rules)
//	pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state
//	pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state
//	block return out quick all
//
// Outgoing only and stateless, as the guard's. The two blocks refuse DNS
// (plain, DNS over TLS and DNS over QUIC) to NoDNS (the LAN while down
// with allow-LAN), which the table passes otherwise; they are there,
// over an empty table, in every shape. pf
// can't match a hop
// limit: neighbour discovery passes to any destination by its ICMPv6
// type (nothing else; a router could forward it), MLD only to
// multicast.
func killSwitchRules(tun string, upstreams []netip.AddrPort) []guardRule {
	pass := func(w ...string) []string { return append([]string{"pass", "out", "quick"}, w...) }
	rules := []guardRule{{"pass out quick on lo0 all no state", 1, pass("on", "lo0")}}
	if tun != "" {
		rules = append(rules, guardRule{"pass out quick on " + tun + " all no state", 1, pass("on", tun)})
	}
	noDNS := "<" + killSwitchNoDNS + ">"
	block := []string{"block", "return", "out", "quick", noDNS}
	rules = append(rules,
		guardRule{"block return out quick proto { tcp, udp } from any to " + noDNS + " port 53", 2, slices.Concat(block, []string{"53"})},
		guardRule{"block return out quick proto { tcp, udp } from any to " + noDNS + " port 853", 2, slices.Concat(block, []string{"853"})},
		guardRule{"pass out quick from any to <" + killSwitchTable + "> no state", 1, pass("<" + killSwitchTable + ">")})
	for _, u := range upstreams {
		a, p := u.Addr().String(), strconv.Itoa(int(u.Port()))
		rules = append(rules, guardRule{"pass out quick proto { tcp, udp } from any to " + a + " port " + p + " no state", 2, pass(a, "port", p)})
	}
	return append(rules,
		guardRule{"pass out quick inet proto udp from any port 68 to any port 67 no state", 1, pass("inet", "udp", "67")},
		guardRule{"pass out quick inet6 proto udp from any port 546 to { ff02::1:2, fe80::/10 } port 547 no state", 2, pass("inet6", "udp", "547")},
		guardRule{"pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state", 5, pass("inet6", "icmp6-type")},
		guardRule{"pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state", 4, pass("inet6", "ff00::/8", "icmp6-type")},
		guardRule{"block return out quick all", 1, []string{"block", "return", "out", "quick"}},
	)
}
