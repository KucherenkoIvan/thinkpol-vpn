package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// OverlayDevice is the name of the WireGuard device (and router egress)
// for device-to-device peers. Chains get a device each (TP-030).
const OverlayDevice = "overlay"

// ErrEngineClosed is returned by a closed engine.
var ErrEngineClosed = errors.New("dataplane: engine closed")

// EngineConfig is what an engine runs on.
type EngineConfig struct {
	// ID is the node's id in the space: every section applied must be its.
	ID netmap.NodeID
	// Space is the space the engine serves; links accepted from another
	// space are refused.
	Space        transport.SpaceID
	WireGuardKey netmap.WireGuardPrivateKey
	Registry     *transport.Registry
	// TUN is the overlay interface: a real TUN (package tun), or a virtual
	// one in tests. The engine owns it.
	TUN tun.Device
	// Interface sets the TUN's addresses, MTU and link state; the engine
	// owns it and closes it. Nil leaves the TUN alone (tests with a
	// virtual TUN).
	Interface netcfg.Configurator
	// LinkMTU is the MTU of the network under every link; 0 means
	// DefaultLinkMTU.
	LinkMTU int
	// Path tunes the path layer; its Space is set from Space.
	Path path.Options
	// Log gets WireGuard's errors; nil discards them.
	Log *slog.Logger
}

// Engine is one space's data plane on a node (DESIGN.md "Data plane"): the
// TUN, the router, one WireGuard device per egress, and the path layer
// under them, configured from the node's section of the map.
//
//	TUN ──► router ──► WireGuard (per egress) ──► path.Bind ──► path.Node ──► links
//
// Every WireGuard device reads a router egress as its TUN and has a Bind of
// the engine's node as its only network: no socket, no listen port. The
// composition root opens the listeners and serves them with Serve, each
// with the peer table Inbound keeps for its transport.
type Engine struct {
	cfg    EngineConfig
	tunDev string
	node   *path.Node
	router *router.Router

	mu      sync.Mutex
	closed  bool
	devices map[string]*egressDevice
	inbound map[string]*transport.PeerTable
	links   map[string][]transport.PeerLink // last applied, by transport
	applied *applied
}

type egressDevice struct {
	egress *router.Egress
	wg     *wg.Device
	peers  []OverlayPeer
}

// applied is what the last Apply put in place, for Status.
type applied struct {
	overlay OverlayConfig
	skipped []error
}

// NewEngine starts an engine. It carries nothing until the first Apply.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	switch {
	case cfg.ID.IsZero():
		return nil, errors.New("dataplane: engine needs the node's id")
	case cfg.WireGuardKey == (netmap.WireGuardPrivateKey{}):
		return nil, errors.New("dataplane: engine needs the node's WireGuard key")
	case cfg.Registry == nil || cfg.TUN == nil:
		return nil, errors.New("dataplane: engine needs a transport registry and a TUN")
	}
	name, err := cfg.TUN.Name()
	if err != nil {
		return nil, fmt.Errorf("dataplane: TUN name: %w", err)
	}
	opts := cfg.Path
	opts.Space = cfg.Space
	node, err := path.NewNode(path.NodeID(cfg.ID), opts)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:     cfg,
		tunDev:  name,
		node:    node,
		router:  router.New(cfg.TUN),
		devices: make(map[string]*egressDevice),
		inbound: make(map[string]*transport.PeerTable),
		links:   make(map[string][]transport.PeerLink),
	}, nil
}

// Apply makes the engine carry the node's section s: the path layer's
// links and routes, the listeners' peer tables, the WireGuard peers (only
// what changed, so sessions survive), the router's table, and the TUN's
// addresses and MTU. A section the engine can't run with (another node's,
// an MTU below MinOverlayMTU, no IPv4 overlay address) or an interface
// netcfg refuses changes nothing; what the section holds that can't be
// used safely is skipped, and Status says what and why.
func (e *Engine) Apply(ctx context.Context, s netmap.Section) error {
	if s.Node.ID != e.cfg.ID {
		return fmt.Errorf("dataplane: section of node %s, not %s", s.Node.ID, e.cfg.ID)
	}
	pc := PathConfigFrom(s, e.cfg.Registry)
	in := InboundFrom(s, e.cfg.Registry, e.cfg.Space)
	oc, err := OverlayConfigFrom(s, e.cfg.WireGuardKey.Public(), OverlayMTU(pc, in, e.cfg.Registry, e.cfg.LinkMTU))
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}
	if e.cfg.Interface != nil {
		err := e.cfg.Interface.Apply(ctx, netcfg.Config{Interfaces: []netcfg.Interface{{
			Name: e.tunDev, Addrs: oc.Addrs, MTU: oc.MTU, Up: true,
		}}})
		if err != nil {
			return fmt.Errorf("dataplane: overlay interface: %w", err)
		}
	}

	e.node.Update(pc.Table)
	e.links = in.Links
	for name, table := range e.inbound {
		table.Set(in.Links[name])
	}

	// One device per egress; M0 has the overlay's only. A chain's exit
	// will be a peer of its chain's device alone (TP-030).
	want := map[string][]OverlayPeer{OverlayDevice: oc.Peers}
	if err := e.setDevices(want, pc.Peers, oc.MTU); err != nil {
		return err
	}

	table := router.Table{Overlay: oc.Networks}
	for name, d := range e.devices {
		for _, p := range want[name] {
			for _, a := range p.Addresses {
				table.Peers = append(table.Peers, router.Route{Prefix: netip.PrefixFrom(a, a.BitLen()), Egress: d.egress})
			}
		}
	}
	if err := e.router.SetTable(table); err != nil {
		return err
	}
	e.applied = &applied{overlay: oc, skipped: slices.Concat(pc.Skipped, in.Skipped, oc.Skipped)}
	return nil
}

// setDevices gives each egress device its peers. A peer key lives in one
// device at a time, so peers leaving a device go first, then every Bind's
// peers change in one step (a peer can move between devices), then each
// device gets its whole set.
func (e *Engine) setDevices(want map[string][]OverlayPeer, paths []path.Peer, mtu int) error {
	key := e.cfg.WireGuardKey
	for name, d := range e.devices {
		if _, ok := want[name]; !ok {
			d.wg.Close()
			delete(e.devices, name)
		}
	}
	for name, d := range e.devices {
		staying := make(map[netmap.NodeID]bool)
		for _, p := range want[name] {
			staying[p.ID] = true
		}
		kept := slices.DeleteFunc(slices.Clone(d.peers), func(p OverlayPeer) bool { return !staying[p.ID] })
		if len(kept) != len(d.peers) {
			if err := d.wg.Configure(key, wgPeers(kept)); err != nil {
				return err
			}
			d.peers = kept
		}
	}
	for name := range want {
		if e.devices[name] != nil {
			continue
		}
		egress, err := e.router.NewEgress(name, mtu)
		if err != nil {
			return err
		}
		e.devices[name] = &egressDevice{egress: egress, wg: wg.New(name, egress, e.node.NewBind(), e.cfg.Log)}
	}

	firstHops := make(map[path.NodeID][]path.NodeID, len(paths))
	for _, p := range paths {
		firstHops[p.ID] = p.FirstHops
	}
	binds := make(map[*path.Bind][]path.Peer, len(e.devices))
	for name, d := range e.devices {
		var peers []path.Peer
		for _, p := range want[name] {
			id := path.NodeID(p.ID)
			peers = append(peers, path.Peer{ID: id, FirstHops: firstHops[id]})
		}
		binds[d.wg.Bind()] = peers
	}
	if err := e.node.SetPeers(binds); err != nil {
		return err
	}
	for name, d := range e.devices {
		if err := d.egress.SetMTU(mtu); err != nil {
			return err
		}
		if err := d.wg.Configure(key, wgPeers(want[name])); err != nil {
			return err
		}
		d.peers = want[name]
	}
	return nil
}

func wgPeers(peers []OverlayPeer) []wg.Peer {
	out := make([]wg.Peer, 0, len(peers))
	for _, p := range peers {
		ips := make([]netip.Prefix, 0, len(p.Addresses))
		for _, a := range p.Addresses {
			ips = append(ips, netip.PrefixFrom(a, a.BitLen()))
		}
		out = append(out, wg.Peer{Key: p.Key, Node: path.NodeID(p.ID), AllowedIPs: ips})
	}
	return out
}

// Serve runs the path layer on a listener of the named transport until the
// listener or the engine closes; see path.Node.Serve. Open the listener
// with Inbound(transportName) as its peers.
func (e *Engine) Serve(transportName string, l transport.Listener) error {
	return e.node.Serve(transportName, l)
}

// Inbound is the peer table for the engine's listeners of a transport:
// the links the node's section says to accept over it, kept current by
// Apply.
func (e *Engine) Inbound(transportName string) transport.Peers {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.inbound[transportName]
	if t == nil {
		t = transport.NewPeerTable(e.links[transportName]...)
		e.inbound[transportName] = t
	}
	return t
}

// Status is what the engine reports. It holds no network addresses but the
// overlay's: it may go into telemetry.
type Status struct {
	// MTU is the overlay's MTU; 0 before the first Apply.
	MTU int
	// IPv6 says whether the overlay carries IPv6, and IPv6Off why not.
	IPv6    bool
	IPv6Off string
	Peers   []PeerStatus
	// Skipped is what the last applied section held that the engine left
	// out, and why.
	Skipped []string
	Router  router.Counters
	Path    path.Counters
}

// PeerStatus is one WireGuard peer.
type PeerStatus struct {
	ID        netmap.NodeID
	Device    string
	Addresses []netip.Addr
	// FirstHop is the hop the peer's packets leave through now; zero
	// before the first packet or without a path.
	FirstHop      netmap.NodeID
	LastHandshake time.Time
}

// Status reports the engine's state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{Router: e.router.Counters(), Path: e.node.Counters()}
	if e.applied == nil || e.closed {
		return s
	}
	oc := e.applied.overlay
	s.MTU, s.IPv6 = oc.MTU, oc.IPv6Off == nil
	if oc.IPv6Off != nil {
		s.IPv6Off = oc.IPv6Off.Error()
	}
	for _, err := range e.applied.skipped {
		s.Skipped = append(s.Skipped, err.Error())
	}
	for name, d := range e.devices {
		handshakes := make(map[netmap.WireGuardKey]time.Time)
		if peers, err := d.wg.Peers(); err == nil {
			for _, p := range peers {
				handshakes[p.Key] = p.LastHandshake
			}
		}
		for _, p := range d.peers {
			ps := PeerStatus{ID: p.ID, Device: name, Addresses: p.Addresses, LastHandshake: handshakes[p.Key]}
			if hop, _, ok := d.wg.Bind().Current(path.NodeID(p.ID)); ok {
				ps.FirstHop = netmap.NodeID(hop)
			}
			s.Peers = append(s.Peers, ps)
		}
	}
	slices.SortFunc(s.Peers, func(a, b PeerStatus) int { return slices.Compare(a.ID[:], b.ID[:]) })
	return s
}

// Close stops the engine: the WireGuard devices, the router and the TUN,
// the path layer, and the TUN's configuration.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	devices := e.devices
	e.devices = nil
	e.mu.Unlock()

	for _, d := range devices {
		d.wg.Close()
	}
	errs := []error{e.router.Close(), e.node.Close()}
	if e.cfg.Interface != nil {
		errs = append(errs, e.cfg.Interface.Close())
	}
	return errors.Join(errs...)
}
