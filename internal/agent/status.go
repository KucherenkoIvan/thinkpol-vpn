package agent

import (
	"errors"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Status is a node's state as the local API reports it (TP-022). It holds
// no public address, key or secret and nothing quoted from the map (PRD
// S1, S4): nodes are the space's opaque ids, addresses are the overlay's,
// and whatever failed is named from fixed vocabularies.
type Status struct {
	// Mode is the node's mode; ModeAuto while it is removed from its space
	// and its kind unknown.
	Mode  Mode
	Space netmap.SpaceID
	// MapVersion is the version of the map the node follows.
	MapVersion uint64
	// Removed is set while the map has no section for the node.
	Removed    bool
	Connection Connection
	// Retrying is set while a start, an Apply or (on a server) serving the
	// map failed and waits to be retried.
	Retrying bool
	// DataPlane is a device's engine report, nil while its data plane is
	// down.
	DataPlane *dataplane.Status
	// Listeners counts the listeners a device's data plane serves.
	Listeners int
	// Workers and PublicListeners are a server's.
	Workers         []WorkerStatus
	PublicListeners []PublicListenerStatus
	// Egress is a server's (nil on a device).
	Egress *supervisor.EgressInfo
	// RulePreset is a device's rule preset (LocalRulesFile; "space" when it
	// chose none); RulesEnforced is set while its data plane runs them, and
	// PresetUnavailable when the map can't build the preset, which is then
	// enforced failing closed.
	RulePreset        string
	RulesEnforced     bool
	PresetUnavailable bool
	// DNSUnprotected is set while a connected device's OS may resolve
	// names outside the node's resolver (pointing it failed, or another
	// link's domains in systemd-resolved): names may leave outside the
	// tunnel.
	DNSUnprotected bool
	// DNSUpstreamsStale is set while the last read of a connected
	// device's OS's own resolvers failed: the direct upstreams are the
	// ones read before, so `direct` names may not resolve. The OS still
	// resolves through the node, so on its own it is not DNSUnprotected.
	DNSUpstreamsStale bool
	// DNSUpstreamsRefused is a server's: how many of the resolver
	// upstreams the worker's egress refuses, so the resolver doesn't use
	// them (each is logged with its address).
	DNSUpstreamsRefused int
}

// Connection is whether a node carries traffic.
type Connection uint8

const (
	// Disconnected: a device whose data plane is down on purpose.
	Disconnected Connection = iota
	// Connecting: a device meant to be connected whose data plane isn't up
	// (removed from its space, or its start failed and is retried).
	Connecting
	// Connected: a device's data plane is up.
	Connected
	// Serving: a server, which serves its spaces whenever it runs.
	Serving
)

func (c Connection) String() string {
	switch c {
	case Disconnected:
		return "disconnected"
	case Connecting:
		return "connecting"
	case Connected:
		return "connected"
	case Serving:
		return "serving"
	}
	return "unknown"
}

// WorkerStatus is one space's worker on a server.
type WorkerStatus struct {
	Space netmap.SpaceID
	Ready bool
	// Starts counts the worker's processes so far; more than one means it
	// was restarted.
	Starts int
	// ReadySince is when the running process became ready; RestartAt when
	// a restart after a crash is due (zero when not applicable).
	ReadySince, RestartAt time.Time
	// LastExit is why the previous process ended (spawn or exit); the local
	// API sanitizes it before the wire.
	LastExit string
}

// PublicListenerStatus is one of a server's public listeners: what it
// routed, without its address.
type PublicListenerStatus struct {
	Transport                        string
	Routed, Unauthenticated, NoSpace uint64
	StreamsOverloaded                uint64
	// Rejected counts the peer links the transport refused to route.
	Rejected int
}

// ErrServerMode is Connect or Disconnect on a server, which serves its
// spaces whenever it runs.
var ErrServerMode = errors.New("agent: a server node always serves its spaces")

// ErrDNSUnprotected is Connect bringing a device up whose OS may still
// resolve names outside the node's resolver: the tunnel is up, but names
// may leave outside it (Status.DNSUnprotected).
var ErrDNSUnprotected = errors.New("agent: connected, but the system may resolve names outside the tunnel")

// ErrNotRunning is Connect or Disconnect on a node that isn't running.
var ErrNotRunning = errors.New("agent: the node is not running")

// StartError is a data plane that failed to start on Connect. Step names
// what failed from a fixed vocabulary (dataplane.Step*, or StepTUN), safe
// to show anyone; Err is the detail, for the node's own log.
type StartError struct {
	Step string
	Err  error
}

// The steps of a start before the engine's own (dataplane.Step*).
const (
	StepTUN    = "tun"    // creating the TUN or taking the overlay's network configuration
	StepEngine = "engine" // starting the engine
)

func (e *StartError) Error() string { return e.Err.Error() }
func (e *StartError) Unwrap() error { return e.Err }

// report keeps a node's status for the local API: written by the
// goroutines that run the node, read from any.
type report struct {
	mu      sync.Mutex
	mode    Mode
	space   netmap.SpaceID
	version uint64
	removed bool
	// want: a device meant to be connected.
	want     bool
	retrying bool
	// engine is a device's running engine; it is cleared before the engine
	// closes, and Status calls it under mu, so it is never used closed.
	engine    *dataplane.Engine
	listeners int
	// workers is a server's supervisor, while it runs.
	workers workerReporter
	// preset is a device's rule preset (Status.RulePreset).
	preset string
	// dns says why a device's OS may resolve outside its resolver.
	dns func() error
	// dnsUpstreamsRefused is a server's count of resolver upstreams the
	// worker's egress refuses (Status.DNSUpstreamsRefused).
	dnsUpstreamsRefused int
}

// workerReporter is what a server's status comes from: the supervisor.
type workerReporter interface {
	Workers() []supervisor.WorkerInfo
	Listeners() []supervisor.ListenerInfo
	Egress() supervisor.EgressInfo
}

func (p *report) set(f func(p *report)) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *report) status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Status{Mode: p.mode, Space: p.space, MapVersion: p.version, Removed: p.removed, Retrying: p.retrying, Listeners: p.listeners, DNSUpstreamsRefused: p.dnsUpstreamsRefused}
	if p.mode != ModeServer {
		s.RulePreset = p.preset
	}
	switch {
	case p.mode == ModeServer:
		s.Connection = Serving
	case p.engine != nil:
		s.Connection = Connected
	case p.want:
		s.Connection = Connecting
	}
	if p.engine != nil {
		st := p.engine.Status()
		s.DataPlane = &st
		s.RulesEnforced, s.PresetUnavailable = true, st.Rules.PresetUnavailable
		var problem error
		if p.dns != nil {
			problem = p.dns()
		}
		// Read once: both flags come from the same Problem.
		s.DNSUnprotected = dns.Unprotected(problem)
		s.DNSUpstreamsStale = errors.Is(problem, dns.ErrUpstreamsStale)
	}
	if p.workers != nil {
		for _, w := range p.workers.Workers() {
			s.Workers = append(s.Workers, WorkerStatus{
				Space: w.Space, Ready: w.Ready, Starts: w.Starts, ReadySince: w.ReadyAt, RestartAt: w.NextStart,
				LastExit: w.LastExit,
			})
		}
		e := p.workers.Egress()
		s.Egress = &e
		for _, l := range p.workers.Listeners() {
			s.PublicListeners = append(s.PublicListeners, PublicListenerStatus{
				Transport: l.Transport, Routed: l.Routed, Unauthenticated: l.Unauthenticated, NoSpace: l.NoSpace,
				StreamsOverloaded: l.StreamsOverloaded, Rejected: len(l.Rejected),
			})
		}
	}
	return s
}

// HealthLevel grades a node's health.
type HealthLevel uint8

const (
	HealthOK HealthLevel = iota
	// HealthDegraded: it carries traffic, but something is wrong.
	HealthDegraded
	// HealthDown: it carries no traffic.
	HealthDown
)

func (l HealthLevel) String() string {
	switch l {
	case HealthOK:
		return "ok"
	case HealthDegraded:
		return "degraded"
	case HealthDown:
		return "down"
	}
	return "unknown"
}

// Health is a node's health and what is wrong, worst first.
type Health struct {
	Level    HealthLevel
	Problems []string
}

// The problems Health names.
const (
	ProblemDisconnected   = "disconnected"
	ProblemRemoved        = "removed_from_space"
	ProblemStarting       = "starting"
	ProblemRetrying       = "retrying"
	ProblemApplyFailed    = "apply_failed"    // the last Apply failed; DataPlane.LastApplyError says where
	ProblemNoLinkUp       = "no_link_up"      // no adjacent node answers
	ProblemNeighborDown   = "neighbor_down"   // some adjacent node doesn't answer
	ProblemSkipped        = "entries_skipped" // the map holds entries the node can't use
	ProblemWorkerDown     = "worker_down"     // a space's worker isn't ready
	ProblemWorkerRestarts = "worker_restarted"
	ProblemLinksRejected  = "links_rejected" // a public listener refused peer links
	// ProblemPresetUnavailable: the map can't build the device's rule
	// preset, so it is enforced failing closed (no internet but the local
	// ranges' direct routes).
	ProblemPresetUnavailable = "rule_preset_unavailable"
	// ProblemRouteTable: the OS routing table doesn't hold the rules now
	// (putting it back failed): traffic may go around the tunnel.
	ProblemRouteTable = "route_table_not_enforced"
	// ProblemRulesAhead: other software's policy rules come before the
	// route table's and may route traffic around the tunnel.
	ProblemRulesAhead = "policy_rules_ahead"
	// ProblemOverlayRoutesAhead: other routes the route table can't
	// outrank take overlay addresses (a hostile network's host routes,
	// macOS): those peers' traffic leaves around the tunnel.
	ProblemOverlayRoutesAhead = "overlay_routes_ahead"
	// ProblemGuard: the leak guard isn't in place now (applying it
	// failed; retried): IPv6 from interface-bound sockets may go around
	// the tunnel.
	ProblemGuard = "ipv6_guard_not_enforced"
	// ProblemGuardUnsupported: the OS can't hold the leak guard (Linux:
	// no nf_tables; macOS: no `anchor "com.apple/*"` in pf's main
	// ruleset): the device connects, but IPv6 from interface-bound
	// sockets isn't confined.
	ProblemGuardUnsupported = "ipv6_guard_unsupported"
	// ProblemDNSUnprotected: the OS may resolve names outside the node's
	// resolver, so names may leave outside the tunnel.
	ProblemDNSUnprotected = "dns_not_protected"
	// ProblemDNSUpstreamsStale: the device's direct upstreams may be stale
	// (the last read of the OS's own resolvers failed), so `direct` names
	// may not resolve; the OS still resolves through the node.
	ProblemDNSUpstreamsStale = "dns_upstreams_stale"
	// ProblemDNSUpstreamRefused: resolver upstreams the worker's egress
	// refuses (Status.DNSUpstreamsRefused counts them) aren't configured:
	// the resolver asks the rest, and with none left tunnel-bound names
	// fail.
	ProblemDNSUpstreamRefused = "dns_upstream_refused"
)

// Health grades the status.
func (s Status) Health() Health {
	var h Health
	add := func(level HealthLevel, problem string) {
		h.Level = max(h.Level, level)
		h.Problems = append(h.Problems, problem)
	}
	if s.Removed {
		add(HealthDown, ProblemRemoved)
	}
	switch s.Connection {
	case Disconnected:
		add(HealthDown, ProblemDisconnected)
	case Connecting:
		if s.Retrying {
			add(HealthDown, ProblemRetrying)
		} else if !s.Removed {
			add(HealthDown, ProblemStarting)
		}
	case Serving:
		if s.Retrying {
			add(HealthDegraded, ProblemRetrying)
		}
		down, restarted := false, false
		for _, w := range s.Workers {
			down = down || !w.Ready
			restarted = restarted || w.Starts > 1
		}
		if down {
			add(HealthDown, ProblemWorkerDown)
		}
		if restarted {
			add(HealthDegraded, ProblemWorkerRestarts)
		}
		for _, l := range s.PublicListeners {
			if l.Rejected > 0 {
				add(HealthDegraded, ProblemLinksRejected)
				break
			}
		}
		if s.DNSUpstreamsRefused > 0 {
			add(HealthDegraded, ProblemDNSUpstreamRefused)
		}
	}
	if dp := s.DataPlane; dp != nil {
		if dp.LastApplyError != "" {
			add(HealthDegraded, ProblemApplyFailed)
		}
		up := 0
		for _, n := range dp.Neighbors {
			if n.Up {
				up++
			}
		}
		switch {
		case len(dp.Neighbors) > 0 && up == 0:
			add(HealthDown, ProblemNoLinkUp)
		case up < len(dp.Neighbors):
			add(HealthDegraded, ProblemNeighborDown)
		}
		if len(dp.Skipped) > 0 {
			add(HealthDegraded, ProblemSkipped)
		}
		if s.PresetUnavailable {
			add(HealthDegraded, ProblemPresetUnavailable)
		}
		if rt := dp.RouteTable; rt.Error != "" {
			add(HealthDown, ProblemRouteTable)
		} else if rt.Enforced && rt.RulesAhead > 0 {
			add(HealthDegraded, ProblemRulesAhead)
		}
		if rt := dp.RouteTable; rt.Error == "" && rt.OverlayAhead > 0 {
			add(HealthDown, ProblemOverlayRoutesAhead)
		}
		switch dp.RouteTable.GuardError {
		case "":
		case routetable.ErrorGuardUnsupported:
			add(HealthDegraded, ProblemGuardUnsupported)
		default:
			add(HealthDegraded, ProblemGuard)
		}
		if s.DNSUnprotected {
			add(HealthDegraded, ProblemDNSUnprotected)
		}
		if s.DNSUpstreamsStale {
			add(HealthDegraded, ProblemDNSUpstreamsStale)
		}
	}
	return h
}
