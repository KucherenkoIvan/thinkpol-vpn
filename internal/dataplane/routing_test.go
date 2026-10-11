package dataplane_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// How the router took a packet: through an egress (its name), or not.
const (
	sentDirect  = "direct"
	sentBlocked = "blocked"
)

// routeOf sends a datagram from nd to dst and reports how nd's router took
// it.
func routeOf(t *testing.T, nd *node, dst netip.Addr) string {
	t.Helper()
	before := nd.engine.Status()
	src := nd.v4
	if dst.Is6() {
		src = nd.v6
	}
	nd.stack.send(packettest.UDPDatagram(netip.AddrPortFrom(src, 4000), netip.AddrPortFrom(dst, 53), []byte("probe")))
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		after := nd.engine.Status()
		switch {
		case after.Router.Direct > before.Router.Direct:
			return sentDirect
		case after.Router.NoRoute > before.Router.NoRoute:
			return "no route"
		case after.Router.Blocked > before.Router.Blocked:
			return sentBlocked
		}
		for _, e := range after.Egresses {
			i := slices.IndexFunc(before.Egresses, func(b router.EgressStatus) bool { return b.Name == e.Name })
			if i < 0 && e.Routed > 0 || i >= 0 && e.Routed > before.Egresses[i].Routed {
				return e.Name
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the router never took the packet to %s", nd.name, dst)
	return ""
}

func exitOf(nd *node) string { return "exit-" + nd.id.String() }

func mustRule(t *testing.T, text string) netmap.Rule {
	t.Helper()
	r, err := netmap.ParseRule(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// withChain makes s the exit of device a's chain nl, with rules.
func withChain(t *testing.T, a, s *node, ruleText ...string) {
	a.section.Chains = []netmap.Chain{{Name: "nl", Exit: s.id}}
	a.section.Rules = nil
	for _, text := range ruleText {
		a.section.Rules = append(a.section.Rules, mustRule(t, text))
	}
}

// Internet traffic goes by the rules: a chain's destinations through its
// exit (on a WireGuard device of its own, so the exit's session carries
// them), direct ones nowhere in the tunnel, blocked ones nowhere at all;
// the overlay keeps working, and goes first.
func TestRulesRouteThroughTheChainsExit(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	withChain(t, a, s,
		"local -> direct",
		"cidr:198.51.100.0/24 -> direct",
		"cidr:203.0.113.0/24 -> block",
		"cidr:2001:db8:bad::/48 -> block",
		"cidr:100.64.0.0/10 -> block", // the overlay is decided before any rule
		"default -> chain:nl")
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	st := a.engine.Status()
	devices := map[netmap.NodeID]string{}
	for _, p := range st.Peers {
		devices[p.ID] = p.Device
	}
	if devices[s.id] != exitOf(s) || devices[b.id] != dataplane.OverlayDevice || len(st.Egresses) != 2 {
		t.Fatalf("status %+v: the exit belongs on a device of its own", st)
	}
	if st.Rules.Preset != rules.PresetSpace || st.Rules.Direct4 == 0 || st.Rules.Direct6 == 0 || len(st.Rules.Skipped) != 0 {
		t.Fatalf("rule status %+v", st.Rules)
	}

	ping(t, a, s.v4)
	ping(t, a, s.v6)
	ping(t, a, b.v4)
	for dst, want := range map[string]string{
		"192.0.2.80":     exitOf(s),
		"2001:db8::80":   exitOf(s),
		"198.51.100.7":   sentDirect,
		"192.168.1.1":    sentDirect,
		"fe80::1":        sentDirect,
		"203.0.113.9":    sentBlocked,
		"2001:db8:bad::": sentBlocked,
		b.v4.String():    dataplane.OverlayDevice,
		s.v4.String():    exitOf(s),
	} {
		if got := routeOf(t, a, netip.MustParseAddr(dst)); got != want {
			t.Errorf("%s: %s, want %s", dst, got, want)
		}
	}

	// The exit decrypts what a sent it for the internet (and, until
	// egress is on, drops it as not its own).
	deadline := time.Now().Add(wait)
	for s.engine.Status().Router.NotLocal < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("server-1 never decrypted a's internet traffic: %+v", s.engine.Status().Router)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The exit's device accepts internet sources from it, but no overlay
// address other than the exit's own: an exit can't pass its packets off
// as another peer's.
func TestAnExitCannotSpeakForOtherPeers(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	withChain(t, a, s, "default -> chain:nl")
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, a, s.v4) // sessions up
	for _, tc := range []struct {
		src     netip.Addr
		arrives bool
	}{
		{b.v4, false},
		{netip.MustParseAddr("100.64.0.99"), false}, // no peer's, still the overlay
		{netip.MustParseAddr("192.0.2.80"), true},
		{s.v4, true},
	} {
		src := netip.AddrPortFrom(tc.src, 53)
		dst := netip.AddrPortFrom(a.v4, 4000)
		payload := []byte("from " + tc.src.String())
		got := false
		for range 3 {
			s.stack.send(packettest.UDPDatagram(src, dst, payload))
			if receive(a, src, payload, 300*time.Millisecond) {
				got = true
				break
			}
		}
		if got != tc.arrives {
			t.Errorf("from %s via the exit: arrived %v, want %v", tc.src, got, tc.arrives)
		}
	}
}

func receive(nd *node, src netip.AddrPort, payload []byte, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case p := <-nd.stack.got:
			if s, _, data, ok := packettest.UDPData(p); ok && s == src && string(data) == string(payload) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// blobStore is a stand-in for TP-017's store.
type blobStore struct {
	mu    sync.Mutex
	blobs map[[32]byte][]byte
}

func (b *blobStore) get(ref netmap.BlobRef) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.blobs[ref.SHA256]
	return data, ok
}

func (b *blobStore) put(sum [32]byte, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blobs[sum] = data
}

// A GeoIP list arriving after the map, the device switching presets and
// adding its own rules: each takes effect at once, without a new map; the
// list is used only once it checks out.
func TestRulesFollowListsAndLocalChoices(t *testing.T) {
	var b lists.Builder
	for _, p := range []string{"77.88.0.0/18", "2a02:6b8::/32"} {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	ru, _ := b.Build()
	blob := ru.Blob()
	ref := netmap.BlobRef{Kind: netmap.BlobGeoIP, SHA256: sha256Of(blob), Size: uint64(len(blob)), Name: "ru"}
	store := &blobStore{blobs: map[[32]byte][]byte{}}

	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	withChain(t, a, s, "local -> direct", "geoip:ru -> direct", "default -> chain:nl")
	a.section.Blobs = []netmap.BlobRef{ref}
	a.section.Presets = netmap.RulePresets{Domestic: "ru", Chain: "nl"}
	a.blobs = store.get
	for _, nd := range []*node{s, a} {
		nd.start(t, net)
	}
	yandex, google := netip.MustParseAddr("77.88.8.8"), netip.MustParseAddr("8.8.8.8")
	yandex6 := netip.MustParseAddr("2a02:6b8::feed:ff")
	check := func(when string, want map[netip.Addr]string, wantSkips []rules.Skip) {
		t.Helper()
		for dst, w := range want {
			if got := routeOf(t, a, dst); got != w {
				t.Errorf("%s: %s: %s, want %s", when, dst, got, w)
			}
		}
		if got := a.engine.Status().Rules.Skipped; !slices.Equal(got, wantSkips) {
			t.Errorf("%s: skipped %v, want %v", when, got, wantSkips)
		}
	}
	noList := []rules.Skip{{Origin: rules.OriginSpace, Index: 1, Reason: rules.ReasonNoList}}

	check("before the list", map[netip.Addr]string{yandex: exitOf(s), google: exitOf(s)}, noList)

	corrupt := slices.Clone(blob)
	corrupt[len(corrupt)-1] ^= 1
	store.put(ref.SHA256, corrupt)
	if err := a.engine.ReloadRules(); err != nil {
		t.Fatal(err)
	}
	check("with a corrupt list", map[netip.Addr]string{yandex: exitOf(s)}, noList)

	store.put(ref.SHA256, blob)
	if err := a.engine.ReloadRules(); err != nil {
		t.Fatal(err)
	}
	check("with the list", map[netip.Addr]string{yandex: sentDirect, yandex6: sentDirect, google: exitOf(s)}, nil)

	if err := a.engine.SetRules(rules.Local{Preset: rules.PresetEverything}); err != nil {
		t.Fatal(err)
	}
	if st := a.engine.Status().Rules; st.Preset != rules.PresetEverything || st.PresetUnavailable {
		t.Fatalf("rule status %+v", st)
	}
	check("everything", map[netip.Addr]string{yandex: exitOf(s), netip.MustParseAddr("192.168.0.1"): sentDirect}, nil)

	if err := a.engine.SetRules(rules.Local{
		Preset: rules.PresetAllButDomestic,
		Rules: []netmap.Rule{
			mustRule(t, "cidr:77.88.8.0/24 -> chain:nl"),
			mustRule(t, "cidr:8.8.8.0/24 -> block"),
			mustRule(t, "domain-suffix:example.com -> direct"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	check("all but domestic with local rules", map[netip.Addr]string{
		yandex: exitOf(s), netip.MustParseAddr("77.88.0.1"): sentDirect, google: sentBlocked,
	}, []rules.Skip{{Origin: rules.OriginLocal, Index: 2, Reason: rules.ReasonByName}})

	// The map drops the presets: the device's choice fails closed, never
	// falling back to the space's rules (which send RU direct).
	a.section.Presets = netmap.RulePresets{}
	a.apply(t)
	if st := a.engine.Status().Rules; st.Preset != rules.PresetAllButDomestic || !st.PresetUnavailable {
		t.Fatalf("rule status %+v: the preset is gone from the map", st)
	}
	check("a preset the map can't build", map[netip.Addr]string{
		yandex: exitOf(s), netip.MustParseAddr("77.88.0.1"): sentBlocked, netip.MustParseAddr("1.1.1.1"): sentBlocked,
		netip.MustParseAddr("192.168.0.1"): sentDirect,
	}, []rules.Skip{{Origin: rules.OriginLocal, Index: 2, Reason: rules.ReasonByName}})
	if err := a.engine.SetRules(rules.Local{Preset: rules.PresetEverything}); !errors.Is(err, rules.ErrPresetUnavailable) {
		t.Fatalf("SetRules of an unavailable preset: %v", err)
	}
	check("everything, unavailable", map[netip.Addr]string{yandex: sentBlocked, netip.MustParseAddr("10.1.1.1"): sentDirect}, nil)

	text := fmt.Sprintf("%v %+v %#v", a.engine.Status(), a.engine.Status(), a.engine.Status())
	for _, quoted := range []string{"example.com", "77.88.", "\"ru\"", "\"nl\""} {
		if strings.Contains(text, quoted) {
			t.Fatalf("status quotes %q from the rules:\n%s", quoted, text)
		}
	}
}

// A chain whose exit isn't a usable peer can't carry traffic: its
// destinations are blocked, never sent direct, and the exit stays where
// it was.
func TestAChainWithoutItsExitBlocks(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	withChain(t, a, s, "cidr:198.51.100.0/24 -> direct", "default -> chain:nl")
	a.section.Chains = []netmap.Chain{{Name: "nl", Exit: netmap.NodeID{9, 9, 9}}}
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	st := a.engine.Status()
	if len(st.Egresses) != 1 || !slices.Contains(st.Rules.Skipped, rules.Skip{Origin: rules.OriginSpace, Index: 1, Reason: rules.ReasonNoChain}) {
		t.Fatalf("status %+v", st)
	}
	if got := routeOf(t, a, netip.MustParseAddr("192.0.2.80")); got != sentBlocked {
		t.Fatalf("internet traffic %s, want blocked", got)
	}
	if got := routeOf(t, a, netip.MustParseAddr("198.51.100.1")); got != sentDirect {
		t.Fatalf("direct traffic %s", got)
	}

	// The map fixes the chain: the exit moves to its device and carries.
	a.section.Chains[0].Exit = s.id
	a.apply(t)
	if got := routeOf(t, a, netip.MustParseAddr("192.0.2.80")); got != exitOf(s) {
		t.Fatalf("internet traffic %s, want %s", got, exitOf(s))
	}
	ping(t, a, s.v4)
	ping(t, a, b.v4)
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }

// Only a chain some rule uses gets a device for its exit: one no rule uses
// leaves its exit on the overlay device, without the internet in its
// allowed IPs. Switching rules moves the exit at once.
func TestExitDevicesFollowTheRules(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	withChain(t, a, s, "local -> direct", "default -> block")
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	device := func() string {
		for _, p := range a.engine.Status().Peers {
			if p.ID == s.id {
				return p.Device
			}
		}
		return ""
	}
	if d := device(); d != dataplane.OverlayDevice || len(a.engine.Status().Egresses) != 1 {
		t.Fatalf("an unused chain's exit is on %q, egresses %+v", d, a.engine.Status().Egresses)
	}
	if got := routeOf(t, a, netip.MustParseAddr("192.0.2.80")); got != sentBlocked {
		t.Fatalf("internet traffic %s", got)
	}

	if err := a.engine.SetRules(rules.Local{Rules: []netmap.Rule{mustRule(t, "cidr:192.0.2.0/24 -> chain:nl")}}); err != nil {
		t.Fatal(err)
	}
	if d := device(); d != exitOf(s) {
		t.Fatalf("the exit is on %q once a rule uses its chain", d)
	}
	if got := routeOf(t, a, netip.MustParseAddr("192.0.2.80")); got != exitOf(s) {
		t.Fatalf("internet traffic %s", got)
	}
	ping(t, a, s.v4)

	if err := a.engine.SetRules(rules.Local{}); err != nil {
		t.Fatal(err)
	}
	if d := device(); d != dataplane.OverlayDevice || len(a.engine.Status().Egresses) != 1 {
		t.Fatalf("the exit is on %q after its chain went out of use", d)
	}
	ping(t, a, s.v4)
	ping(t, a, b.v4)
}
