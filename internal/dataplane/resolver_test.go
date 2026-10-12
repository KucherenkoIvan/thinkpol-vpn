package dataplane_test

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// dnsRecorder keeps the last configuration an engine gave its resolver.
type dnsRecorder struct {
	mu   sync.Mutex
	last dns.Config
	n    int
}

func (r *dnsRecorder) Update(c dns.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.n = c, r.n+1
}

func (r *dnsRecorder) config() dns.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func routeKind(c dns.Config, name string) (dns.RouteKind, []netip.Addr) {
	if c.Route == nil {
		return dns.RouteDirect, nil
	}
	r := c.Route(name)
	return r.Kind, r.Via
}

// A device's resolver serves its own and its peers' names, and resolves
// other names by its rules: direct ones by the domestic upstream, the
// rest through the tunnel at its chain's exit. An exit's serves the
// space's overlay; other servers have none.
func TestTheResolverFollowsTheMapAndTheRules(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	a.section.Node.Kind, b.section.Node.Kind, s.section.Node.Kind = netmap.NodeDevice, netmap.NodeDevice, netmap.NodeServer
	s.section.Node.AllowEgress = true
	a.section.SpaceName, a.section.Node.Name = "home", "device-a"
	for i, name := range map[netmap.NodeID]string{s.id: "server-1", b.id: "device-b"} {
		j := slices.IndexFunc(a.section.Peers, func(p netmap.Peer) bool { return p.ID == i })
		a.section.Peers[j].Name = name
	}
	withChain(t, a, s, "domain-suffix:example.ru -> direct", "local -> direct", "default -> chain:nl")
	recs := map[*node]*dnsRecorder{}
	for _, nd := range []*node{s, a, b} {
		recs[nd] = &dnsRecorder{}
		nd.dns = recs[nd]
		nd.start(t, net)
	}

	c := recs[a].config()
	if !slices.Equal(c.Listen, []netip.Addr{a.v4, a.v6}) {
		t.Errorf("device listens on %v", c.Listen)
	}
	if !slices.Contains(c.Clients, netip.PrefixFrom(a.v4, 32)) || slices.Contains(c.Clients, space4) {
		t.Errorf("device's clients %v: itself only", c.Clients)
	}
	if c.Zone != "home.internal" {
		t.Errorf("zone %q", c.Zone)
	}
	wantNames := map[string][]netip.Addr{"device-a": {a.v4, a.v6}, "server-1": {s.v4, s.v6}, "device-b": {b.v4, b.v6}}
	if !maps.EqualFunc(c.Names, wantNames, slices.Equal) {
		t.Errorf("names %v", c.Names)
	}
	if k, _ := routeKind(c, "www.example.ru"); k != dns.RouteDirect {
		t.Errorf("a direct name goes %v", k)
	}
	if k, via := routeKind(c, "example.com"); k != dns.RouteTunnel || !slices.Equal(via, []netip.Addr{s.v4, s.v6}) {
		t.Errorf("a tunnel name goes %v via %v", k, via)
	}

	if c.RouteAddr == nil {
		t.Fatal("no routes for reverse names")
	}
	if r := c.RouteAddr(netip.MustParseAddr("192.168.1.1")); r.Kind != dns.RouteDirect {
		t.Errorf("a local address's reverse name goes %v", r.Kind)
	}
	if r := c.RouteAddr(netip.MustParseAddr("192.0.2.1")); r.Kind != dns.RouteTunnel || !slices.Equal(r.Via, []netip.Addr{s.v4, s.v6}) {
		t.Errorf("an internet address's reverse name goes %v via %v", r.Kind, r.Via)
	}

	if c := recs[s].config(); !slices.Equal(c.Listen, []netip.Addr{s.v4, s.v6}) || !slices.Contains(c.Clients, space4) || c.Zone != "" || c.Route != nil {
		t.Errorf("exit's resolver: %+v", c)
	}
	if c := recs[b].config(); c.Zone != "" || len(c.Names) != 0 {
		t.Errorf("a device without a space name has names: %+v", c)
	} else if k, _ := routeKind(c, "example.com"); k != dns.RouteDirect {
		t.Errorf("without rules a name goes %v, as every address goes direct", k)
	}

	// A device's own rules decide names at once.
	if err := a.engine.SetRules(rules.Local{Rules: []netmap.Rule{mustRule(t, "domain:example.com -> direct")}}); err != nil {
		t.Fatal(err)
	}
	if k, _ := routeKind(recs[a].config(), "example.com"); k != dns.RouteDirect {
		t.Errorf("after SetRules: %v", k)
	}
	if k, _ := routeKind(recs[a].config(), "example.org"); k != dns.RouteTunnel {
		t.Errorf("after SetRules, another name: %v", k)
	}

	// A peer the map takes away leaves DNS with it; a chain whose exit
	// can't carry traffic blocks rather than going direct.
	a.section.Peers = slices.DeleteFunc(a.section.Peers, func(p netmap.Peer) bool { return p.ID == b.id })
	a.section.Chains = []netmap.Chain{{Name: "nl", Exit: netmap.NodeID{9}}}
	a.apply(t)
	c = recs[a].config()
	if _, ok := c.Names["device-b"]; ok {
		t.Errorf("a removed peer's name stays: %v", c.Names)
	}
	if k, _ := routeKind(c, "example.org"); k != dns.RouteBlock {
		t.Errorf("a chain without its exit: %v", k)
	}

	// A server that doesn't allow egress serves no one.
	s.section.Node.AllowEgress = false
	s.apply(t)
	if c := recs[s].config(); len(c.Listen) != 0 {
		t.Errorf("a server without egress listens on %v", c.Listen)
	}
}
