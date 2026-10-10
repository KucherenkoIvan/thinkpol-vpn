package devmap

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// transports are the transports a spec can use, each with the length of the
// link secret Plan makes for it. Their settings are all empty for now; a
// transport with settings needs them in the spec first.
var transports = map[string]struct {
	t          transport.Transport
	secretSize int
}{
	udp.Name: {udp.New(udp.Options{}), udp.MinSecretSize},
}

func transportNames() []string { return slices.Sorted(maps.Keys(transports)) }

// Plan derives every node's section from a spec (see the package doc for
// the rules) and returns the map's contents, recipients in the spec's node
// order, and the nodes' names by id. Link secrets come from random
// (crypto/rand when nil), fresh on every call.
func Plan(s *Spec, k Keys, version uint64, random io.Reader) (netmap.Contents, Names, error) {
	random = orCryptoRand(random)
	fail := func(n Node, format string, args ...any) error {
		return &Error{File: s.File, Pos: n.Pos, Msg: n.Name + ": " + fmt.Sprintf(format, args...)}
	}

	ids := make([]netmap.NodeID, len(s.Nodes))
	names := Names{}
	for i, n := range s.Nodes {
		pub, ok := k.Nodes[n.Name]
		if !ok {
			return netmap.Contents{}, nil, fail(n, "no public keys")
		}
		ids[i] = NodeID(k.Space, pub.Map)
		if other, taken := names[ids[i]]; taken {
			return netmap.Contents{}, nil, fail(n, "has the same keys as %s", other)
		}
		names[ids[i]] = n.Name
	}

	v4, v6 := s.IPv4Network, s.IPv6Network
	if !v6.IsValid() {
		v6 = DefaultIPv6Network(k.Space)
	}
	ipv4, err := assign(s, v4, func(n Node) netip.Addr { return n.IPv4 })
	if err != nil {
		return netmap.Contents{}, nil, err
	}
	ipv6, err := assign(s, v6, func(n Node) netip.Addr { return n.IPv6 })
	if err != nil {
		return netmap.Contents{}, nil, err
	}

	sections := make([]netmap.Section, len(s.Nodes))
	for i, n := range s.Nodes {
		node := netmap.NodeSettings{ID: ids[i], Kind: n.Kind, IPv4: ipv4[i], IPv6: ipv6[i], IPv4Network: v4, IPv6Network: v6}
		for _, l := range n.Listeners {
			node.Listeners = append(node.Listeners, netmap.Listener{Transport: l.Transport, Address: l.AddrPort})
		}
		sections[i].Node = node
	}

	// Peers and routes come from the paths: the ends are peers, each with
	// its neighbour on the path as a first hop; every node in between routes
	// to both ends through its neighbours.
	addPeer := func(at, peer, firstHop int) {
		sec := &sections[at]
		j := slices.IndexFunc(sec.Peers, func(p netmap.Peer) bool { return p.ID == ids[peer] })
		if j < 0 {
			sec.Peers = append(sec.Peers, netmap.Peer{
				ID:           ids[peer],
				WireGuardKey: k.Nodes[s.Nodes[peer].Name].WireGuard,
				Addresses:    []netip.Addr{ipv4[peer], ipv6[peer]},
			})
			j = len(sec.Peers) - 1
		}
		if hop := (netmap.Path{FirstHop: ids[firstHop]}); !slices.Contains(sec.Peers[j].Paths, hop) {
			sec.Peers[j].Paths = append(sec.Peers[j].Paths, hop)
		}
	}
	addRoute := func(at, dest, next int) {
		sec := &sections[at]
		j := slices.IndexFunc(sec.Routes, func(r netmap.Route) bool { return r.Destination == ids[dest] })
		if j < 0 {
			sec.Routes = append(sec.Routes, netmap.Route{Destination: ids[dest]})
			j = len(sec.Routes) - 1
		}
		if !slices.Contains(sec.Routes[j].NextHops, ids[next]) {
			sec.Routes[j].NextHops = append(sec.Routes[j].NextHops, ids[next])
		}
	}
	for _, p := range s.Paths {
		a, b := p.Nodes[0], p.Nodes[len(p.Nodes)-1]
		addPeer(a, b, p.Nodes[1])
		addPeer(b, a, p.Nodes[len(p.Nodes)-2])
		for h := 1; h < len(p.Nodes)-1; h++ {
			addRoute(p.Nodes[h], b, p.Nodes[h+1])
			addRoute(p.Nodes[h], a, p.Nodes[h-1])
		}
	}

	// Each link gets one secret per transport the dialed node has endpoints
	// for: the dialer's credential, and the listener's verifier (udp is
	// symmetric, so they are the same bytes).
	for _, l := range s.Links {
		from, to := s.Nodes[l.From], s.Nodes[l.To]
		secrets := map[string][]byte{}
		link := netmap.Link{Peer: ids[l.To]}
		for _, e := range to.Endpoints {
			secret, ok := secrets[e.Transport]
			if !ok {
				secret = make([]byte, transports[e.Transport].secretSize)
				if _, err := io.ReadFull(random, secret); err != nil {
					return netmap.Contents{}, nil, err
				}
				secrets[e.Transport] = secret
				sections[l.To].Inbound = append(sections[l.To].Inbound, netmap.InboundLink{
					Peer: ids[l.From], PeerKind: from.Kind, Transport: e.Transport, Credential: secret,
				})
			}
			link.Endpoints = append(link.Endpoints, netmap.Endpoint{Transport: e.Transport, Address: e.AddrPort, Credential: secret})
		}
		sections[l.From].Links = append(sections[l.From].Links, link)
	}

	c := netmap.Contents{SpaceID: k.Space, Version: version, RecoveryKey: k.RecoveryKey}
	for i, n := range s.Nodes {
		if err := checkWithTransports(sections[i]); err != nil {
			return netmap.Contents{}, nil, fail(n, "%v", err)
		}
		c.Recipients = append(c.Recipients, netmap.Recipient{Key: k.Nodes[n.Name].Map, Section: sections[i]})
	}
	return c, names, nil
}

// assign gives every node without a fixed address the lowest free host
// address of network, in spec order.
func assign(s *Spec, network netip.Prefix, fixed func(Node) netip.Addr) ([]netip.Addr, error) {
	taken := map[netip.Addr]bool{network.Addr(): true}
	for _, n := range s.Nodes {
		if a := fixed(n); a.IsValid() {
			taken[a] = true
		}
	}
	out := make([]netip.Addr, len(s.Nodes))
	next := network.Addr()
	for i, n := range s.Nodes {
		if a := fixed(n); a.IsValid() {
			out[i] = a
			continue
		}
		for taken[next] {
			next = next.Next()
		}
		if !network.Contains(next) {
			return nil, &Error{File: s.File, Pos: n.Pos, Msg: fmt.Sprintf("%s: no address left in %v", n.Name, network)}
		}
		out[i] = next
		taken[next] = true
	}
	return out, nil
}

// checkWithTransports has each transport check what Plan made for it, the
// way a node's engine will before using it.
func checkWithTransports(sec netmap.Section) error {
	for _, l := range sec.Links {
		for _, e := range l.Endpoints {
			cfg := transport.DialConfig{Credential: e.Credential, Settings: e.Settings}
			if err := transports[e.Transport].t.CheckEndpoint(e.Address.String(), cfg); err != nil {
				return err
			}
		}
	}
	for _, in := range sec.Inbound {
		if err := transports[in.Transport].t.CheckInbound(transport.PeerLink{Verifier: in.Credential, Settings: in.Settings}); err != nil {
			return err
		}
	}
	return nil
}

// Build plans a spec and seals and signs the map.
func Build(s *Spec, k Keys, version uint64, random io.Reader) ([]byte, error) {
	c, _, err := Plan(s, k, version, random)
	if err != nil {
		return nil, err
	}
	env, err := netmap.Build(k.Signing, c)
	if errors.Is(err, netmap.ErrInvalidContents) {
		// Plan checks what a spec can get wrong; this is the builder's
		// policy catching something it missed.
		return nil, fmt.Errorf("%s: %w (recipients are the nodes in spec order)", s.File, err)
	}
	return env, err
}
