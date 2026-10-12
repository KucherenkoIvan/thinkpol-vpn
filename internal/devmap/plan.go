package devmap

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
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

// Link is a pair of neighbours on paths: From dials To.
type Link struct{ From, To int }

// Links derives who dials whom from a spec's paths: every pair of
// neighbours once, in order of first use. The node without endpoints (a
// device) dials the one with; when both have endpoints, the one declared
// first dials.
func Links(s *Spec) ([]Link, error) {
	var links []Link
	var errs []error
	linked := map[[2]int]bool{}
	for _, p := range s.Paths {
		for k := 1; k < len(p.Nodes); k++ {
			x, y := p.Nodes[k-1], p.Nodes[k]
			if linked[[2]int{x, y}] || linked[[2]int{y, x}] {
				continue
			}
			linked[[2]int{x, y}] = true
			xe, ye := len(s.Nodes[x].Endpoints) > 0, len(s.Nodes[y].Endpoints) > 0
			switch {
			case ye && (!xe || x < y):
				links = append(links, Link{From: x, To: y})
			case xe:
				links = append(links, Link{From: y, To: x})
			default:
				errs = append(errs, &Error{File: s.File, Pos: p.Hops[k], Msg: fmt.Sprintf(
					"neither %s nor %s has endpoints, so neither can dial the other", s.Nodes[x].Name, s.Nodes[y].Name)})
			}
		}
	}
	return links, errors.Join(errs...)
}

// Plan derives every node's section from a spec (see the package doc for
// the rules) and returns the map's contents, recipients in the spec's node
// order, and the nodes' names by id. Link secrets come from secrets
// (RandomSecrets(nil) when nil: fresh on every call).
func Plan(s *Spec, k Keys, version uint64, secrets Secrets) (netmap.Contents, Names, error) {
	if secrets == nil {
		secrets = RandomSecrets(nil)
	}
	fail := func(n Node, format string, args ...any) error {
		return &Error{File: s.File, Pos: n.Pos, Msg: n.Name + ": " + fmt.Sprintf(format, args...)}
	}
	if version == 0 || version > netmap.MaxVersion {
		return netmap.Contents{}, nil, fmt.Errorf("map version %d: must be from 1 to %d", version, uint64(netmap.MaxVersion))
	}

	ids := make([]netmap.NodeID, len(s.Nodes))
	names := Names{}
	keys := map[netmap.NodePublicKey]string{}
	for i, n := range s.Nodes {
		pub, ok := k.Nodes[n.Name]
		if !ok {
			return netmap.Contents{}, nil, fail(n, "no public keys")
		}
		if other, taken := keys[pub.Map]; taken {
			return netmap.Contents{}, nil, fail(n, "has the same keys as %s", other)
		}
		if other, taken := names[pub.ID]; taken {
			return netmap.Contents{}, nil, fail(n, "has the same node id as %s", other)
		}
		ids[i] = pub.ID
		names[pub.ID], keys[pub.Map] = n.Name, n.Name
	}

	links, err := Links(s)
	if err != nil {
		return netmap.Contents{}, nil, err
	}

	v4, v6 := s.IPv4Network, s.IPv6Network
	if !v6.IsValid() {
		v6 = k.IPv6Network
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
		node := netmap.NodeSettings{
			ID: ids[i], Kind: n.Kind, IPv4: ipv4[i], IPv6: ipv6[i], IPv4Network: v4, IPv6Network: v6,
			AllowIngress: n.Ingress, AllowEgress: n.Egress,
		}
		for _, l := range n.Listeners {
			node.Listeners = append(node.Listeners, netmap.Listener{Transport: l.Transport, Address: l.AddrPort})
		}
		sections[i].Node = node
		sections[i].Rules = slices.Clone(n.Rules)
		for _, ch := range n.Chains {
			sections[i].Chains = append(sections[i].Chains, netmap.Chain{Name: ch.Name, Exit: ids[ch.Exit]})
		}
		for _, l := range n.Lists {
			sections[i].Blobs = append(sections[i].Blobs, s.Lists[l].Ref)
		}
	}
	var header []netmap.BlobRef
	var total uint64
	for _, l := range s.Lists {
		if l.Ref.Size == 0 {
			return netmap.Contents{}, nil, &Error{File: s.File, Pos: l.Pos, Msg: "list " + l.Name + ": not read (ReadLists)"}
		}
		if total += l.Ref.Size; total > blobs.ServerMaxHeldSize {
			return netmap.Contents{}, nil, &Error{File: s.File, Pos: l.Pos, Msg: fmt.Sprintf("list %s: the lists together pass %d bytes, what a server holds", l.Name, blobs.ServerMaxHeldSize)}
		}
		ref := l.Ref
		ref.Name = "" // the header lists blobs unnamed
		header = append(header, ref)
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
	routes := forwarding{}
	for _, p := range s.Paths {
		a, b := p.Nodes[0], p.Nodes[len(p.Nodes)-1]
		addPeer(a, b, p.Nodes[1])
		addPeer(b, a, p.Nodes[len(p.Nodes)-2])
		for h := 1; h < len(p.Nodes)-1; h++ {
			routes.add(p.Nodes[h], b, p.Nodes[h+1], p.Pos)
			routes.add(p.Nodes[h], a, p.Nodes[h-1], p.Pos)
		}
	}
	if err := routes.checkLoops(s); err != nil {
		return netmap.Contents{}, nil, err
	}
	for _, r := range routes {
		route := netmap.Route{Destination: ids[r.dest]}
		for _, h := range r.next {
			route.NextHops = append(route.NextHops, ids[h])
		}
		sections[r.at].Routes = append(sections[r.at].Routes, route)
	}

	// Each link gets one secret per transport the dialed node has endpoints
	// for: the dialer's credential, and the listener's verifier (udp is
	// symmetric, so they are the same bytes).
	for _, l := range links {
		from, to := s.Nodes[l.From], s.Nodes[l.To]
		made := map[string][]byte{}
		link := netmap.Link{Peer: ids[l.To]}
		for _, e := range to.Endpoints {
			secret, ok := made[e.Transport]
			if !ok {
				var err error
				if secret, err = secrets(from.Name, to.Name, e.Transport, transports[e.Transport].secretSize); err != nil {
					return netmap.Contents{}, nil, err
				}
				made[e.Transport] = secret
				sections[l.To].Inbound = append(sections[l.To].Inbound, netmap.InboundLink{
					Peer: ids[l.From], PeerKind: from.Kind, Transport: e.Transport, Credential: secret,
				})
			}
			link.Endpoints = append(link.Endpoints, netmap.Endpoint{Transport: e.Transport, Address: e.AddrPort, Credential: secret})
		}
		sections[l.From].Links = append(sections[l.From].Links, link)
	}

	c := netmap.Contents{SpaceID: k.Space, Version: version, RecoveryKey: k.RecoveryKey, Blobs: header}
	for i, n := range s.Nodes {
		if err := checkWithTransports(sections[i]); err != nil {
			return netmap.Contents{}, nil, fail(n, "%v", err)
		}
		c.Recipients = append(c.Recipients, netmap.Recipient{Key: k.Nodes[n.Name].Map, Section: sections[i]})
	}
	return c, names, nil
}

// forwarding is the relays' routes in order of first use: at node at, to
// dest, through next (in priority order), each next hop from the path that
// introduced it.
type forwarding []route

type route struct {
	at, dest int
	next     []int
	from     []Pos
}

func (f *forwarding) add(at, dest, next int, from Pos) {
	j := slices.IndexFunc(*f, func(r route) bool { return r.at == at && r.dest == dest })
	if j < 0 {
		*f = append(*f, route{at: at, dest: dest})
		j = len(*f) - 1
	}
	if r := &(*f)[j]; !slices.Contains(r.next, next) {
		r.next = append(r.next, next)
		r.from = append(r.from, from)
	}
}

// checkLoops refuses routes that can send a packet in a circle: with
// failover a relay may use any of its next hops, so the next-hop graph
// toward each destination must have no cycle. Two paths that cross the
// same relays in opposite directions make one.
func (f forwarding) checkLoops(s *Spec) error {
	type edge struct{ at, dest int }
	hops := map[edge]int{}
	for i, r := range f {
		hops[edge{r.at, r.dest}] = i
	}
	var errs []error
	for _, dest := range uniqueDests(f) {
		state := map[int]int{} // 0 unvisited, 1 on the stack, 2 done
		var stack []int
		var visit func(at int) []int
		visit = func(at int) []int {
			state[at] = 1
			stack = append(stack, at)
			r := f[hops[edge{at, dest}]]
			for _, n := range r.next {
				if n == dest {
					continue
				}
				switch state[n] {
				case 1:
					return append(slices.Clone(stack[slices.Index(stack, n):]), n)
				case 0:
					if cycle := visit(n); cycle != nil {
						return cycle
					}
				}
			}
			stack = stack[:len(stack)-1]
			state[at] = 2
			return nil
		}
		for _, r := range f {
			if r.dest != dest || state[r.at] != 0 {
				continue
			}
			stack = stack[:0]
			cycle := visit(r.at)
			if cycle == nil {
				continue
			}
			var names, lines []string
			last := Pos{}
			for i, at := range cycle {
				names = append(names, s.Nodes[at].Name)
				if i == len(cycle)-1 {
					break
				}
				hop := f[hops[edge{at, dest}]]
				p := hop.from[slices.Index(hop.next, cycle[i+1])]
				if line := strconv.Itoa(p.Line); !slices.Contains(lines, line) {
					lines = append(lines, line)
				}
				if p.Line > last.Line {
					last = p
				}
			}
			errs = append(errs, &Error{File: s.File, Pos: last, Msg: fmt.Sprintf(
				"the paths on lines %s make a forwarding loop toward %s: %s",
				strings.Join(lines, " and "), s.Nodes[dest].Name, strings.Join(names, " → "))})
			break
		}
	}
	return errors.Join(errs...)
}

func uniqueDests(f forwarding) []int {
	var dests []int
	for _, r := range f {
		if !slices.Contains(dests, r.dest) {
			dests = append(dests, r.dest)
		}
	}
	return dests
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

// NextVersion is the version for a new build: the current Unix time, or
// one past previous (the map being replaced) when that is a map of the same
// space with a version at least as high, so nodes always take the new map.
func NextVersion(now time.Time, previous []byte, trust netmap.Trust) uint64 {
	v := uint64(max(now.Unix(), 1))
	if m, err := netmap.Verify(previous, trust); err == nil && m.Header().Version >= v {
		v = m.Header().Version + 1
	}
	return v
}

// Secrets makes the secret of the link from one node to another (by name)
// over a transport, size bytes long.
type Secrets func(from, to, transport string, size int) ([]byte, error)

// RandomSecrets draws every secret from r (crypto/rand when nil).
func RandomSecrets(r io.Reader) Secrets {
	r = orCryptoRand(r)
	return func(_, _, _ string, size int) ([]byte, error) {
		b := make([]byte, size)
		_, err := io.ReadFull(r, b)
		return b, err
	}
}

// InsecureSeededSecrets derives each link's secret from seed and the link
// (HMAC-SHA256 of its ends and transport), so builds of one space give a
// link the same secret whatever else changed, and a lab test can hand some
// nodes a newer map and keep others on an older one. Never for a real
// space: the seed gives away every link.
func InsecureSeededSecrets(seed string) Secrets {
	return func(from, to, transport string, size int) ([]byte, error) {
		var out []byte
		for block := byte(0); len(out) < size; block++ {
			m := hmac.New(sha256.New, []byte(seed))
			m.Write([]byte("thinkpol dev map link secret\x00" + from + "\x00" + to + "\x00" + transport + "\x00"))
			m.Write([]byte{block})
			out = m.Sum(out)
		}
		return out[:size], nil
	}
}

// Build plans a spec and seals and signs the map.
func Build(s *Spec, k Keys, version uint64, secrets Secrets) ([]byte, error) {
	c, _, err := Plan(s, k, version, secrets)
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

// ReadLists reads each of the spec's list files with read (a path relative
// to the spec's directory unless absolute), checks it is a GeoIP list blob
// a node would hold, and sets its reference.
func ReadLists(s *Spec, read func(path string) ([]byte, error)) error {
	var errs []error
	fail := func(l List, format string, args ...any) {
		errs = append(errs, &Error{File: s.File, Pos: l.Pos, Msg: "list " + l.Name + ": " + fmt.Sprintf(format, args...)})
	}
	bySum := map[[32]byte]string{}
	var total int
	for i, l := range s.Lists {
		path := l.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(s.File), path)
		}
		data, err := read(path)
		if err != nil {
			fail(l, "%v", err)
			continue
		}
		if len(data) > blobs.MaxBlobSize {
			fail(l, "%s is %d bytes, more than a node holds (%d)", path, len(data), blobs.MaxBlobSize)
			continue
		}
		// The header lists every list, and servers hold all of them.
		if total += len(data); total > blobs.ServerMaxHeldSize {
			fail(l, "the lists together pass %d bytes, what a server holds", blobs.ServerMaxHeldSize)
			continue
		}
		if _, err := lists.Decode(data); err != nil {
			fail(l, "%s is not a GeoIP list blob (`thinkpol dev lists build` writes them): %v", path, err)
			continue
		}
		ref := netmap.BlobRef{Kind: netmap.BlobGeoIP, SHA256: sha256.Sum256(data), Size: uint64(len(data)), Name: l.Name}
		if other, dup := bySum[ref.SHA256]; dup {
			fail(l, "same content as list %s", other)
			continue
		}
		bySum[ref.SHA256] = l.Name
		s.Lists[i].Ref = ref
	}
	return errors.Join(errs...)
}
