package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

func (r *rig) ksStore() tokenStore {
	s := r.store()
	s.record, s.header = killSwitchRecord, killSwitchHeader
	return s
}

func (r *rig) killSwitch() *KillSwitch { return newKillSwitch(r.pf, r.ksStore(), ownAddrs) }

func (r *rig) ksRecord(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, killSwitchRecord))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// downRules are the kill switch's rules while the tunnel is down: an
// entry of each family.
func downRules(t *testing.T) KillSwitchRules {
	return KillSwitchRules{Mark: routetable.Mark, Allow: set(t, "203.0.113.50/32", "2001:db8:e::50/128")}
}

// upRules are the connected shape: the utun, a direct range of each
// family and the upstreams.
func upRules(t *testing.T) KillSwitchRules {
	return KillSwitchRules{
		TUN: "utun7", Mark: routetable.Mark,
		Allow:     set(t, "203.0.113.50/32", "2001:db8:e::50/128"),
		Direct:    set(t, "198.51.100.0/24", "2001:db8:d0::/48"),
		Upstreams: aps("[2001:db8:53::1]:53", "192.0.2.53:53", "[fe80::1%en0]:53"),
	}
}

// The kill switch loads its anchor (after the guard's, both families,
// stateless), holds pf on by a reference of its own, recorded apart from
// the guard's, and kills the states, of either family, its table
// doesn't allow.
func TestKillSwitchLoadsItsAnchorAndHoldsPfOn(t *testing.T) {
	r := newRig(t)
	entry4 := netip.MustParseAddrPort("203.0.113.50:443")
	r.pf.states = []fakeState{
		{"tcp", netip.AddrPortFrom(ownV4, 50000), netip.MustParseAddrPort("203.0.113.7:443"), true},
		{"tcp", netip.AddrPortFrom(ownV4, 50001), entry4, true},
		{"udp", netip.AddrPortFrom(ownV6, 50002), netip.MustParseAddrPort("[2001:db8:ab::7]:443"), true},
		{"tcp", netip.MustParseAddrPort("[::1]:50003"), netip.MustParseAddrPort("[::1]:8080"), true},
	}
	k := r.killSwitch()
	if err := k.Apply(context.Background(), downRules(t)); err != nil {
		t.Fatal(err)
	}
	a := r.pf.anchors[KillSwitchAnchor]
	if a == nil {
		t.Fatal("no anchor loaded")
	}
	if KillSwitchAnchor <= GuardAnchor {
		t.Errorf("the kill switch's anchor %s sorts before the guard's %s: the guard would count it as a bypass", KillSwitchAnchor, GuardAnchor)
	}
	want := []string{
		"pass out quick on lo0 all no state",
		"pass out quick from any to <thinkpol_killswitch> no state",
		"pass out quick inet proto udp from any port = 68 to any port = 67 no state",
		"pass out quick inet6 proto udp from any port = 546 to ff02::1:2 port = 547 no state",
		"pass out quick inet6 proto udp from any port = 546 to fe80::/10 port = 547 no state",
	}
	if !slices.Equal(a.rules[:5], want) || a.rules[len(a.rules)-1] != "block return out quick all" || len(a.rules) != 5+5+4+1 {
		t.Errorf("the anchor lists:\n%s", strings.Join(a.rules, "\n"))
	}
	if got := strings.Join(a.tables[killSwitchTable], " "); got != "203.0.113.50/32 2001:db8:e::50/128" {
		t.Errorf("the table holds %s", got)
	}
	if !r.pf.isOn() || len(r.pf.references()) != 1 {
		t.Errorf("pf on %v with references %v, want on by one", r.pf.isOn(), r.pf.references())
	}
	if !strings.Contains(r.ksRecord(t), "token ") || r.record(t) != "" {
		t.Errorf("records: kill switch %q, guard %q; want the kill switch's alone", r.ksRecord(t), r.record(t))
	}
	var left []netip.AddrPort
	for _, s := range r.pf.stateList() {
		left = append(left, s.remote)
	}
	if !slices.Equal(left, []netip.AddrPort{entry4, netip.MustParseAddrPort("[::1]:8080")}) {
		t.Errorf("states left %v, want the entry's and loopback's", left)
	}

	// The same again reads it back and loads nothing; changed from
	// outside, it is loaded again.
	loads := r.pf.ran("-f -")
	if err := k.Apply(context.Background(), downRules(t)); err != nil {
		t.Fatal(err)
	}
	if r.pf.ran("-f -") != loads {
		t.Error("the same rules were loaded again")
	}
	r.pf.set(func(f *fakePF) {
		a := f.anchors[KillSwitchAnchor]
		a.tables[killSwitchTable] = append(a.tables[killSwitchTable], "192.0.2.0/24")
	})
	if err := k.Apply(context.Background(), downRules(t)); err != nil {
		t.Fatal(err)
	}
	if r.pf.ran("-f -") != loads+1 || slices.Contains(r.pf.anchors[KillSwitchAnchor].tables[killSwitchTable], "192.0.2.0/24") {
		t.Error("an entry added from outside wasn't undone")
	}
}

// Connected, the utun and DNS to the direct upstreams pass too (a
// link-local upstream is the LAN's: pf can't name it without its
// interface).
func TestKillSwitchConnectedShape(t *testing.T) {
	r := newRig(t)
	k := r.killSwitch()
	if err := k.Apply(context.Background(), upRules(t)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.pf.anchors[KillSwitchAnchor].tables[killSwitchTable], " "); got != "198.51.100.0/24 203.0.113.50/32 2001:db8:e::50/128 2001:db8:d0::/48" {
		t.Errorf("the table holds %s, want the entries and the direct destinations", got)
	}
	rules := strings.Join(r.pf.anchors[KillSwitchAnchor].rules, "\n")
	for _, w := range []string{
		"pass out quick on utun7 all no state",
		"pass out quick proto tcp from any to 192.0.2.53 port = 53 no state",
		"pass out quick proto udp from any to 2001:db8:53::1 port = 53 no state",
	} {
		if !strings.Contains(rules, w) {
			t.Errorf("no %q in:\n%s", w, rules)
		}
	}
	if strings.Contains(rules, "fe80::1") {
		t.Errorf("a link-local upstream has a rule:\n%s", rules)
	}
	// Down again: the utun's pass goes.
	if err := k.Apply(context.Background(), downRules(t)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.pf.anchors[KillSwitchAnchor].rules, "\n"), "utun7") {
		t.Error("the down shape still passes the utun")
	}
}

// The kill switch's reference is its own: the guard closing (a
// disconnect) leaves pf on, and the kill switch closing leaves the
// guard's.
func TestKillSwitchAndGuardHoldTheirOwnReferences(t *testing.T) {
	r := newRig(t)
	g, k := r.guard(), r.killSwitch()
	ctx := context.Background()
	if err := g.Apply(ctx, exempt(t)); err != nil {
		t.Fatal(err)
	}
	if err := k.Apply(ctx, upRules(t)); err != nil {
		t.Fatal(err)
	}
	if n := len(r.pf.references()); n != 2 {
		t.Fatalf("%d references, want the guard's and the kill switch's", n)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if !r.pf.isOn() || r.pf.anchors[KillSwitchAnchor] == nil || r.ksRecord(t) == "" {
		t.Error("closing the guard turned pf off or took the kill switch with it")
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if r.pf.isOn() || r.pf.anchors[KillSwitchAnchor] != nil || r.ksRecord(t) != "" {
		t.Errorf("after Close: pf on %v, anchor %v, record %q", r.pf.isOn(), r.pf.anchors[KillSwitchAnchor], r.ksRecord(t))
	}
}

// What a run left (a crash, a stop) stays until a fresh kill switch's
// Close, which removes the anchor and releases the recorded reference; or
// a fresh one's Apply, which takes the reference over.
func TestKillSwitchOutlivesItsRun(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.killSwitch().Apply(ctx, downRules(t)); err != nil {
		t.Fatal(err)
	}
	// The process died: nothing closed it.
	next := r.killSwitch()
	if err := next.Apply(ctx, downRules(t)); err != nil {
		t.Fatal(err)
	}
	if n := len(r.pf.references()); n != 1 {
		t.Errorf("%d references after the next run's Apply, want the one taken over", n)
	}
	if err := r.killSwitch().Close(); err != nil {
		t.Fatal(err)
	}
	if r.pf.isOn() || r.pf.anchors[KillSwitchAnchor] != nil || r.ksRecord(t) != "" {
		t.Errorf("a fresh Close left: pf on %v, anchor %v, record %q", r.pf.isOn(), r.pf.anchors[KillSwitchAnchor], r.ksRecord(t))
	}
}

// Without Apple's hook nothing evaluates the anchor: Apply fails (retried
// by the agent) and loads nothing; with no pfctl the kill switch is
// unsupported, and Close has nothing to remove.
func TestKillSwitchNeedsTheHookAndPfctl(t *testing.T) {
	r := newRig(t)
	r.pf.main = []string{`scrub-anchor "com.apple/*" all fragment reassemble`}
	k := r.killSwitch()
	if err := k.Apply(context.Background(), downRules(t)); err == nil || r.pf.anchors[KillSwitchAnchor] != nil {
		t.Errorf("Apply without the hook: %v, anchor %v", err, r.pf.anchors[KillSwitchAnchor])
	}
	none := newKillSwitch(execPfctl{path: "/nonexistent-tp048/pfctl", timeout: time.Second}, r.ksStore(), ownAddrs)
	if err := none.Apply(context.Background(), downRules(t)); !errors.Is(err, ErrKillSwitchUnsupported) || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("Apply with no pfctl: %v, want ErrKillSwitchUnsupported alone", err)
	}
	if err := none.Close(); err != nil {
		t.Errorf("Close with no pfctl: %v", err)
	}
}

// A load pfctl lists otherwise than written (a pass with state) is
// refused, and Apply fails.
func TestKillSwitchRefusesAListingWithState(t *testing.T) {
	r := newRig(t)
	r.pf.loadHook = func(a *fakeAnchor) {
		a.rules[1] = strings.Replace(a.rules[1], "no state", "keep state", 1)
	}
	err := r.killSwitch().Apply(context.Background(), downRules(t))
	if err == nil || !strings.Contains(err.Error(), "kill switch's rule 2") {
		t.Errorf("Apply: %v, want the listing refused", err)
	}
}

// IPv4 ends read "addr:port" in `pfctl -s states` (built, not recorded:
// TP-048's device checks), IPv6 ends "addr[port]"; a table lists either
// family, an IPv4 host without /32.
func TestKillSwitchReadsBothFamilies(t *testing.T) {
	states, err := parseStatesOf([]byte(altq+"ALL tcp 192.0.2.10:50000 -> 203.0.113.7:443       ESTABLISHED:ESTABLISHED\nALL udp 2001:db8:1::10[5353] -> 2001:db8:ab::7[53]       MULTIPLE:SINGLE\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0][1] != netip.MustParseAddr("203.0.113.7") || states[1][1] != netip.MustParseAddr("2001:db8:ab::7") {
		t.Errorf("states %v", states)
	}
	if v6, _ := parseStatesOf([]byte("ALL tcp 192.0.2.10:50000 -> 203.0.113.7:443 X\n"), false); len(v6) != 0 {
		t.Errorf("the guard's reading took IPv4: %v", v6)
	}
	table, err := parseTableOf([]byte("   198.51.100.0/24\n   203.0.113.50\n   2001:db8:e::50\n"), true)
	if err != nil || len(table) != 3 || table[1] != netip.MustParsePrefix("203.0.113.50/32") {
		t.Errorf("table %v, %v", table, err)
	}
	if _, err := parseTable([]byte("   203.0.113.50\n")); err == nil {
		t.Error("the guard's table reading took IPv4")
	}
}
