package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// OverlayDevice is the name of the WireGuard device (and router egress)
// for device-to-device peers. Chains get a device each (TP-030).
const OverlayDevice = "overlay"

// ErrEngineClosed is returned by a closed engine.
var ErrEngineClosed = errors.New("dataplane: engine closed")

// The steps of Apply, as Status.LastApplyError names a failed one.
const (
	StepSection   = "section"   // the section can't run here: another node's (nothing changed), no IPv4 address, MTU
	StepRemovals  = "removals"  // taking away peers the section no longer allows
	StepInterface = "interface" // the TUN's addresses and MTU (netcfg)
	StepDevices   = "devices"   // WireGuard devices and their Binds' peers
	StepRouter    = "router"    // the router's table
	// StepRouteTable is the OS routing table (route-table mode).
	StepRouteTable = "route table"
)

// EngineConfig is what an engine runs on.
type EngineConfig struct {
	// ID is the node's id in the space: every section applied must be its.
	ID netmap.NodeID
	// Space is the space the engine serves (never zero); links accepted
	// from another space are refused.
	Space        transport.SpaceID
	WireGuardKey netmap.WireGuardPrivateKey
	Registry     *transport.Registry
	// TUN is the overlay interface: a real TUN (package tun), or a virtual
	// one in tests. The engine owns it once NewEngine succeeds.
	TUN tun.Device
	// Interface sets the TUN's addresses, MTU and link state; the engine
	// owns it once NewEngine succeeds. Nil leaves the TUN alone: in-process
	// tests, and platforms where the OS configures the TUN it hands over
	// (Android's VpnService, Apple's NetworkExtension).
	Interface netcfg.Configurator
	// LinkMTU is the MTU of the network under every link; 0 means
	// DefaultLinkMTU.
	LinkMTU int
	// Path tunes the path layer; its Space is set from Space.
	Path path.Options
	// Log gets WireGuard's errors and handshake timeouts, the links' lives
	// (path.Options.Log, unless Path has its own) and, at debug level, the
	// details of what Apply skipped or failed at, which may quote the map:
	// keep it local. Nil discards them.
	Log *slog.Logger
	// Blobs returns a blob the map references, false while the node
	// doesn't have it (TP-017's store); the engine checks its size and
	// SHA-256 itself. Called with the engine locked: it must not call back
	// into the engine. Nil: no blobs, so geoip rules match nothing.
	Blobs func(netmap.BlobRef) ([]byte, bool)
	// StandIn, if set, returns the blob of a kind and name the node held
	// before (TP-017's Service.Latest), for a reference Blobs doesn't have
	// yet: rules keep using the previous list until its successor is
	// verified. What it returns is checked against the reference it
	// returns, which must have the kind and name asked for. Called with
	// the engine locked, like Blobs.
	StandIn func(kind netmap.BlobKind, name string) (netmap.BlobRef, []byte, bool)
	// Rules is the device's own rule choice (its local file), until
	// SetRules replaces it.
	Rules rules.Local
	// Forward lets the node be its space's exit when its section allows
	// egress: what the overlay device decrypts for destinations outside
	// the overlay goes to the TUN, for the network stack to forward and
	// NAT. Only where that stack does it safely: a server's worker, whose
	// namespace the supervisor's tables confine (TP-014). Off, the engine
	// writes only the node's own addresses to the TUN, whatever the
	// section says, as on a device.
	Forward bool
	// RouteTable, if set, enforces the rules in the OS routing table (a
	// device's route-table mode); the engine owns it once NewEngine
	// succeeds. Nil leaves the OS routing alone: servers' workers, tests,
	// and platforms where the OS takes the routes with the TUN.
	RouteTable RouteTable
	// DNS, if set, is the node's resolver (a *dns.Server): the engine
	// tells it what to serve after every Apply and rule change (see
	// dnsConfig). Called with the engine locked: it must not call back
	// into the engine.
	DNS interface{ Update(dns.Config) }
	// Events, if set, hears what happens to the engine (Event), on the
	// goroutine whose call caused it, once that call let the engine go.
	Events func(Event)
}

// Engine is one space's data plane on a node (DESIGN.md "Data plane"): the
// TUN, the router, one WireGuard device per egress, and the path layer
// under them, configured from the node's section of the map.
//
//	TUN ──► router ──► WireGuard (per egress) ──► path.Bind ──► path.Node ──► links
//
// Every WireGuard device reads a router egress as its TUN and has a Bind of
// the engine's node as its only network: no socket, no listen port.
//
// The engine is in-process wiring only. Creating the TUN and the
// configurator, building the transport registry (with the socket Control),
// watching for new maps and calling Apply with each, and opening, serving
// and closing the listeners are the agent's (TP-011's agent.RunDataPlane).
type Engine struct {
	cfg     EngineConfig
	tunName string
	node    *path.Node
	router  *router.Router
	// assign lays peers out on devices (layout: chain exits on their own,
	// the rest on the overlay device); rules gives the router its rule
	// routes (ruleRoutes). Tests swap them.
	assign func(OverlayConfig) map[string][]devicePeer
	rules  func(egresses map[string]*router.Egress) []router.Route

	// serial orders Apply, SetRules, ReloadRules and Close; mu guards the
	// state, and is let go while the OS routing table changes (seconds,
	// at a country's size) so Status and Inbound don't wait for it.
	serial sync.Mutex
	// ctx ends with Close: what SetRules and ReloadRules do runs under it.
	ctx    context.Context
	cancel context.CancelFunc
	// interfaceWatched is closed when the interface's watcher has stopped
	// (nil without an Interface).
	interfaceWatched chan struct{}

	mu      sync.Mutex
	closed  bool
	pending []Event // noted for cfg.Events (flushEvents)
	devices map[string]*egressDevice
	inbound map[string]*transport.PeerTable
	links   map[string][]transport.PeerLink // last applied, by transport

	// What runs now, for the router table and Status.
	mtu      int
	ipv6Off  error
	local    []netip.Addr
	networks []netip.Prefix
	exit     bool // the section allows egress and cfg.Forward is set
	skipped  []Skip
	lastErr  string
	// routedExit is whether the router's table forwards (Status.Exit).
	routedExit bool
	// ifc is the overlay interface's configuration in place (nil before
	// the first Apply that set it), which a link event re-applies;
	// ifcReapplies counts those that succeeded, ifcTiming paces them.
	ifc          *netcfg.Interface
	ifcReapplies uint64
	ifcTiming    interfaceTiming

	// Routing rules: the device's own choice, what the last section gave
	// them, the chains that can carry traffic, and the result.
	ownRules     rules.Local
	ruleInput    *ruleInput
	ruleNetworks []netip.Prefix
	chainExit    map[string]netmap.NodeID // chains whose exit is a usable peer
	usedExits    map[netmap.NodeID]bool   // their exits the rules send traffic to
	overlay      *OverlayConfig           // the last section's, and its paths, for recompiling
	paths        []path.Peer
	routedRules  RuleStatus // what the router's table enforces
	ruleTable    *rules.Table
	ruleStatus   RuleStatus
	geoipSets    map[[32]byte]*lists.Set // decoded, by hash

	// Route-table mode: the links' endpoints, and what the OS routing
	// table holds (nil before the first enforcement).
	endpoints  []netip.Addr
	upstreams  []netip.AddrPort // the resolver's direct upstreams (SetDirectUpstreams)
	routesWant *routetable.Want
	nameRules  *rules.Names // the rules compiled for DNS names

	// What the resolver needs of the last section: the node's kind and
	// egress setting, and the overlay names.
	kind      netmap.NodeKind
	egress    bool
	spaceName string
	ownName   string
	peerNames map[netmap.NodeID]string
}

// devicePeer is a peer of one device: the router sends it the peer's
// overlay addresses, and WireGuard accepts AllowedIPs from it (a chain's
// exit also has the default routes there).
type devicePeer struct {
	OverlayPeer
	AllowedIPs []netip.Prefix
}

type egressDevice struct {
	egress *router.Egress
	wg     *wg.Device
	peers  []devicePeer // what WireGuard has
}

// NewEngine starts an engine. It carries nothing until the first Apply.
// On error the caller keeps the TUN, the Interface and the RouteTable and
// closes them.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	switch {
	case cfg.ID.IsZero():
		return nil, errors.New("dataplane: engine needs the node's id")
	case cfg.Space == transport.SpaceID{}:
		return nil, errors.New("dataplane: engine needs the space's id")
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
	if opts.Log == nil {
		opts.Log = cfg.Log
	}
	node, err := path.NewNode(path.NodeID(cfg.ID), opts)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:       cfg,
		tunName:   name,
		node:      node,
		router:    router.New(cfg.TUN),
		devices:   make(map[string]*egressDevice),
		inbound:   make(map[string]*transport.PeerTable),
		links:     make(map[string][]transport.PeerLink),
		ownRules:  cfg.Rules,
		geoipSets: make(map[[32]byte]*lists.Set),
		ifcTiming: defaultInterfaceTiming,
	}
	e.assign, e.rules = e.layout, e.ruleRoutes
	e.ctx, e.cancel = context.WithCancel(context.Background())
	if cfg.Interface != nil {
		e.interfaceWatched = make(chan struct{})
		go e.watchInterface()
	}
	return e, nil
}

// overlayOnly puts every peer on the overlay device, allowed its own
// addresses.
func overlayOnly(oc OverlayConfig) map[string][]devicePeer {
	peers := make([]devicePeer, 0, len(oc.Peers))
	for _, p := range oc.Peers {
		peers = append(peers, devicePeer{OverlayPeer: p, AllowedIPs: hostPrefixes(p.Addresses)})
	}
	return map[string][]devicePeer{OverlayDevice: peers}
}

func hostPrefixes(addrs []netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// Apply makes the engine carry the node's section s: the path layer's
// links and routes, the listeners' peer tables, the WireGuard peers (only
// what changed, so sessions survive; each chain's exit on a device of its
// own), the routing rules and the router's table, and the TUN's
// addresses and MTU. What the section holds that can't be used safely is
// skipped, entry by entry (Status.Skipped), never the whole section.
//
// A section of another node changes nothing. Otherwise revocation never
// waits: the path table, the listeners' tables and the removal of every
// peer (or peer address) the section no longer allows go first, even when
// the section can't run here (no usable IPv4 address, MTU) or a later
// step fails. After a failed step (named by
// Status.LastApplyError) the engine runs the earlier steps of the new
// section and the rest of the previous one; peers it added are those both
// allow. Applying the same section again, or a newer one, converges.
func (e *Engine) Apply(ctx context.Context, s netmap.Section) error {
	defer e.flushEvents()
	e.serial.Lock()
	defer e.serial.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}
	step, err := e.apply(ctx, s)
	e.lastErr = ""
	if err != nil {
		e.lastErr = step
		e.debug("apply failed", "step", step, "err", err)
	}
	e.updateDNS()
	return err
}

func (e *Engine) apply(ctx context.Context, s netmap.Section) (string, error) {
	if s.Node.ID != e.cfg.ID {
		return StepSection, fmt.Errorf("dataplane: section of node %s, not %s", s.Node.ID, e.cfg.ID)
	}
	e.kind, e.egress, e.spaceName, e.ownName = s.Node.Kind, s.Node.AllowEgress, s.SpaceName, s.Node.Name
	e.peerNames = make(map[netmap.NodeID]string, len(s.Peers))
	for _, p := range s.Peers {
		e.peerNames[p.ID] = p.Name
	}
	pc := PathConfigFrom(s, e.cfg.Registry)
	in := AcceptedInbound(s, e.cfg.Registry, e.cfg.Space, e.cfg.LinkMTU)
	mtu := OverlayMTU(&pc, &in, e.cfg.Registry, e.cfg.LinkMTU)
	oc, ocErr := OverlayConfigFrom(s, e.cfg.WireGuardKey.Public(), mtu)
	details := slices.Concat(pc.Skipped, in.Skipped, oc.Skipped)
	for _, d := range details {
		e.debug("skipped", "entry", d.Error())
	}
	e.skipped = skips(details)

	e.links = in.Links
	for name, table := range e.inbound {
		table.Set(in.Links[name])
	}
	e.node.Update(pc.Table)
	var want map[string][]devicePeer
	var shrinkErr error
	if ocErr == nil {
		e.chainExit = chainExits(s.Chains, oc.Peers)
		_ = e.compileRules(ruleInputOf(s), oc.Networks) // an unavailable preset is in Status
		shrinkErr = e.shrinkRoutes(ctx)
		e.overlay, e.paths = &oc, pc.Peers
		e.endpoints = endpointsOf(pc)
		want = e.assign(oc)
	} else {
		want = sectionPeers(s, e.devices)
	}
	if err := e.removePeers(want, ocErr == nil, pc.Peers); err != nil {
		return StepRemovals, err
	}
	if ocErr != nil {
		return StepSection, ocErr
	}

	if e.cfg.Interface != nil {
		ifc := netcfg.Interface{Name: e.tunName, Addrs: slices.Clone(oc.Addrs), MTU: oc.MTU, Up: true}
		if err := e.cfg.Interface.Apply(ctx, netcfg.Config{Interfaces: []netcfg.Interface{ifc}}); err != nil {
			return StepInterface, fmt.Errorf("dataplane: overlay interface: %w", err)
		}
		e.ifc = &ifc
	}
	e.mtu, e.ipv6Off, e.local, e.networks = oc.MTU, oc.IPv6Off, oc.Local, oc.Networks
	e.exit = e.cfg.Forward && s.Node.Kind == netmap.NodeServer && s.Node.AllowEgress

	if err := e.addPeers(want, pc.Peers, oc.MTU); err != nil {
		return StepDevices, err
	}
	if err := e.setTable(); err != nil {
		return StepRouter, err
	}
	if err := e.growRoutes(ctx, shrinkErr); err != nil {
		return StepRouteTable, err
	}
	return "", nil
}

// sectionPeers is what a section that can't run allows the running
// devices: their peers whose id, key and addresses it still lists.
func sectionPeers(s netmap.Section, devices map[string]*egressDevice) map[string][]devicePeer {
	listed := make(map[netmap.NodeID]netmap.Peer, len(s.Peers))
	for _, p := range s.Peers {
		listed[p.ID] = p
	}
	want := make(map[string][]devicePeer, len(devices))
	for name, d := range devices {
		want[name] = nil
		for _, p := range d.peers {
			if q, ok := listed[p.ID]; ok && q.WireGuardKey == p.Key {
				p.Addresses = slices.DeleteFunc(slices.Clone(p.Addresses), func(a netip.Addr) bool { return !slices.Contains(q.Addresses, a) })
				p.AllowedIPs = slices.DeleteFunc(slices.Clone(p.AllowedIPs), func(a netip.Prefix) bool {
					return a.IsSingleIP() && !slices.Contains(p.Addresses, a.Addr())
				})
				want[name] = append(want[name], p)
			}
		}
	}
	return want
}

// removePeers takes from every device the peers, and the addresses of
// peers, that want no longer gives it, and closes the devices want has
// none for (when known). Nothing is added.
func (e *Engine) removePeers(want map[string][]devicePeer, known bool, paths []path.Peer) error {
	departing := make(map[string]*egressDevice)
	changed := false
	for name, d := range e.devices {
		next, stays := want[name]
		if !stays && known {
			departing[name] = d
			continue
		}
		byID := make(map[netmap.NodeID]devicePeer, len(next))
		for _, p := range next {
			byID[p.ID] = p
		}
		var kept []devicePeer
		for _, p := range d.peers {
			q, ok := byID[p.ID]
			if !ok || q.Key != p.Key {
				continue
			}
			p.Addresses = slices.DeleteFunc(slices.Clone(p.Addresses), func(a netip.Addr) bool { return !slices.Contains(q.Addresses, a) })
			p.AllowedIPs = slices.DeleteFunc(slices.Clone(p.AllowedIPs), func(a netip.Prefix) bool { return !slices.Contains(q.AllowedIPs, a) })
			if len(p.AllowedIPs) > 0 {
				kept = append(kept, p)
			}
		}
		if samePeers(kept, d.peers) {
			continue
		}
		if err := d.wg.Configure(e.cfg.WireGuardKey, wgPeers(kept)); err != nil {
			return err
		}
		d.peers = kept
		changed = true
	}
	if !changed && len(departing) == 0 {
		return nil
	}
	binds := make(map[*path.Bind][]path.Peer, len(e.devices))
	for name, d := range e.devices {
		if departing[name] == nil {
			binds[d.wg.Bind()] = pathPeers(d.peers, paths)
		}
	}
	if err := e.node.SetPeers(binds); err != nil {
		return err
	}
	// The router stops using departing egresses before their devices close.
	for name := range departing {
		delete(e.devices, name)
	}
	if err := e.setTable(); err != nil {
		return err
	}
	var errs []error
	for _, d := range departing {
		errs = append(errs, d.wg.Close())
	}
	return errors.Join(errs...)
}

// addPeers gives each device all of want, creating the devices it lacks.
// A peer key lives in one device at a time, and removePeers took peers off
// the devices they leave, so every Bind's peers change in one step.
func (e *Engine) addPeers(want map[string][]devicePeer, paths []path.Peer, mtu int) error {
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
	binds := make(map[*path.Bind][]path.Peer, len(e.devices))
	for name, d := range e.devices {
		binds[d.wg.Bind()] = pathPeers(want[name], paths)
	}
	if err := e.node.SetPeers(binds); err != nil {
		return err
	}
	for name, d := range e.devices {
		if err := d.egress.SetMTU(mtu); err != nil {
			return err
		}
		if err := d.wg.Configure(e.cfg.WireGuardKey, wgPeers(want[name])); err != nil {
			return err
		}
		d.peers = want[name]
	}
	return nil
}

// reflectLocal: macOS routes the utun's own address into the utun (see
// router.Table.ReflectLocal).
const reflectLocal = runtime.GOOS == "darwin"

// table is the router table for what runs now.
func (e *Engine) table() router.Table {
	// A device never forwards the OS's traffic: only its own addresses
	// may speak through it.
	t := router.Table{Overlay: e.networks, Local: e.local, ReflectLocal: reflectLocal, LocalSourcesOnly: e.kind == netmap.NodeDevice}
	egresses := make(map[string]*router.Egress, len(e.devices))
	for name, d := range e.devices {
		egresses[name] = d.egress
		for _, p := range d.peers {
			for _, a := range p.Addresses {
				t.Peers = append(t.Peers, router.Route{Prefix: netip.PrefixFrom(a, a.BitLen()), Egress: d.egress})
			}
		}
	}
	if e.rules != nil {
		t.Rules = e.rules(egresses)
	}
	// The space's devices and servers are the overlay device's peers;
	// a chain's exit device carries replies from its exit, never
	// traffic for this node to forward.
	if d := e.devices[OverlayDevice]; e.exit && d != nil {
		t.Forward = []*router.Egress{d.egress}
	}
	return t
}

func pathPeers(peers []devicePeer, paths []path.Peer) []path.Peer {
	firstHops := make(map[path.NodeID][]path.NodeID, len(paths))
	for _, p := range paths {
		firstHops[p.ID] = p.FirstHops
	}
	out := make([]path.Peer, 0, len(peers))
	for _, p := range peers {
		id := path.NodeID(p.ID)
		out = append(out, path.Peer{ID: id, FirstHops: firstHops[id]})
	}
	return out
}

func wgPeers(peers []devicePeer) []wg.Peer {
	out := make([]wg.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, wg.Peer{Key: p.Key, Node: path.NodeID(p.ID), AllowedIPs: p.AllowedIPs})
	}
	return out
}

func samePeers(a, b []devicePeer) bool {
	return slices.EqualFunc(a, b, func(p, q devicePeer) bool {
		return p.ID == q.ID && p.Key == q.Key && slices.Equal(p.Addresses, q.Addresses) && slices.Equal(p.AllowedIPs, q.AllowedIPs)
	})
}

func (e *Engine) debug(msg string, args ...any) {
	if e.cfg.Log != nil {
		e.cfg.Log.Debug(msg, args...)
	}
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

// Status is what the engine reports, for the local API and telemetry. It
// holds no network addresses but the overlay's, and nothing quoted from
// the map: what was skipped and what failed come from fixed vocabularies.
type Status struct {
	// MTU is the overlay's MTU; 0 before the first Apply that got that far.
	MTU int
	// IPv6 says whether the overlay carries IPv6, and IPv6Off why not.
	IPv6    bool
	IPv6Off string
	Peers   []PeerStatus
	// Neighbors are the path layer's adjacent nodes and their links.
	Neighbors []path.NeighborStatus
	// Egresses are the router's egresses, one per WireGuard device.
	Egresses []router.EgressStatus
	// Skipped is what the last applied section held that the engine left
	// out, and why.
	Skipped []Skip
	// LastApplyError is the step the last Apply failed at (Step*), empty
	// if it succeeded.
	LastApplyError string
	Router         router.Counters
	Path           path.Counters
	// Rules is how the routing rules are enforced.
	Rules RuleStatus
	// Exit says the node forwards its peers' internet traffic: its
	// section allows egress and EngineConfig.Forward is set.
	Exit bool
	// RouteTable is how the OS routing table enforces them.
	RouteTable RouteTableStatus
	// InterfaceReapplies counts successful re-applies of the overlay
	// interface's addresses and MTU after its link came up (most change
	// nothing).
	InterfaceReapplies uint64
}

// PeerStatus is one WireGuard peer.
type PeerStatus struct {
	ID        netmap.NodeID
	Device    string
	Addresses []netip.Addr
	// FirstHop is the hop the peer's packets leave through now; zero
	// before the first packet or without a path.
	FirstHop         netmap.NodeID
	LastHandshake    time.Time
	RxBytes, TxBytes uint64
}

// Status reports the engine's state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{
		MTU:            e.mtu,
		IPv6:           e.mtu > 0 && e.ipv6Off == nil,
		Neighbors:      e.node.Neighbors(),
		Egresses:       e.router.Egresses(),
		Skipped:        slices.Clone(e.skipped),
		LastApplyError: e.lastErr,
		Router:         e.router.Counters(),
		Path:           e.node.Counters(),
		Rules:          e.routedRules,
		Exit:           e.routedExit,
		RouteTable:     e.routeTableStatus(),

		InterfaceReapplies: e.ifcReapplies,
	}
	s.Rules.Skipped = slices.Clone(s.Rules.Skipped)
	if e.ipv6Off != nil {
		s.IPv6Off = e.ipv6Off.Error()
	}
	for name, d := range e.devices {
		reported := make(map[netmap.WireGuardKey]wg.PeerStatus)
		if peers, err := d.wg.Peers(); err == nil {
			for _, p := range peers {
				reported[p.Key] = p
			}
		}
		for _, p := range d.peers {
			r := reported[p.Key]
			ps := PeerStatus{
				ID: p.ID, Device: name, Addresses: slices.Clone(p.Addresses),
				LastHandshake: r.LastHandshake, RxBytes: r.RxBytes, TxBytes: r.TxBytes,
			}
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
	e.cancel()
	if e.interfaceWatched != nil {
		<-e.interfaceWatched
	}
	e.serial.Lock()
	defer e.serial.Unlock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	devices := e.devices
	e.devices = map[string]*egressDevice{}
	e.mu.Unlock()

	var errs []error
	// Routing goes back to the OS first: nothing goes on into a TUN
	// that is closing.
	if e.cfg.RouteTable != nil {
		errs = append(errs, e.cfg.RouteTable.Close())
	}
	for _, d := range devices {
		errs = append(errs, d.wg.Close())
	}
	errs = append(errs, e.router.Close(), e.node.Close())
	if e.cfg.Interface != nil {
		errs = append(errs, e.cfg.Interface.Close())
	}
	return errors.Join(errs...)
}
