package agent

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Status is a node's state as the local API reports it (TP-022). It holds
// no public address, key or secret and nothing quoted from the map (PRD
// S1, S4): nodes are the space's opaque ids, addresses are the overlay's,
// and whatever failed is named from fixed vocabularies.
type Status struct {
	// Mode is the node's mode (Config.Mode), removed from its space or not.
	Mode  Mode
	Space netmap.SpaceID
	// MapVersion is the version of the map the node follows.
	MapVersion uint64
	// MapsRefused counts the maps the node was given and refused since
	// it started: invalid, or not its space's. One merely not newer than
	// the map it follows (the same file read again) isn't counted.
	MapsRefused uint64
	// Removed is set while the map has no section for the node.
	Removed bool
	// ModeMismatch is set while the map makes a node run in device mode a
	// server: it runs nothing of the map, as while removed.
	ModeMismatch bool
	Connection   Connection
	// Retrying is set while a start, an Apply or (on a server) serving the
	// map failed and waits to be retried.
	Retrying bool
	// DataPlane is a device's engine report, nil while its data plane is
	// down.
	DataPlane *dataplane.Status
	// Listeners counts the listeners a device's data plane serves.
	Listeners int
	// Interface is the name of a device's TUN while its data plane runs.
	Interface string
	// Workers and PublicListeners are a server's.
	Workers         []WorkerStatus
	PublicListeners []PublicListenerStatus
	// Egress is a server's (nil on a device).
	Egress *supervisor.EgressInfo
	// RulePreset is a device's rule preset (DeviceFile; "space" when it
	// chose none); RulesEnforced is set while its data plane runs them, and
	// PresetUnavailable when the map can't build the preset, which is then
	// enforced failing closed.
	RulePreset        string
	RulesEnforced     bool
	PresetUnavailable bool
	// ConnectOnBoot is a device's connect-on-boot (DeviceFile): whether
	// the service connects it at a boot's first start.
	ConnectOnBoot bool
	// KillSwitch is a device's kill switch: its toggles and whether it is
	// in place as meant.
	KillSwitch KillSwitchStatus
	// LastRunCrashed: the previous run under a device's service left a
	// trace on its stderr (LastRun.Crashed); Diagnostics has it.
	LastRunCrashed bool
	// LastRunUnreadable: the service's crash trace file was there but
	// wasn't read (LastRun.Unreadable); Diagnostics says why.
	LastRunUnreadable bool
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
	// DNSNoUpstream is set while a connected device's resolver has no
	// direct upstream to ask (none configured, none read from the OS), or
	// the OS names none now (its previous ones are still asked,
	// dns.ErrNoSystemUpstream): `direct` names may not resolve. Not while
	// DNSUpstreamsStale: those upstreams are unknown, not absent.
	DNSNoUpstream bool
	// DNSUpstreamsRefused is an exit's: how many of the resolver
	// upstreams the worker's egress refuses, so the resolver doesn't use
	// them (each is logged with its address).
	DNSUpstreamsRefused int
	// ExitsUnanswered counts a connected device's exits (DataPlane.Peers
	// with Exit set) that have left a WireGuard handshake initiation
	// unanswered for dataplane.ExitHandshakeDeadline while their first hop
	// was up (exitHandshakes): directly or behind a relay, the traffic
	// sent through them is lost. DefaultExitUnanswered says one of them
	// carries an address family's background route (Rules.DefaultExits):
	// the destinations of that family no other route names are lost.
	ExitsUnanswered       int
	DefaultExitUnanswered bool
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
	// LastExit is why the previous process ended, a code; the
	// supervisor's log has the detail.
	LastExit supervisor.ExitReason
}

// PublicListenerStatus is one of a server's public listeners: what it
// routed, without its address.
type PublicListenerStatus struct {
	Transport                        string
	Routed, Unauthenticated, NoSpace uint64
	StreamsOverloaded                uint64
	// StreamsBoundClosed counts connections the transport closed past its
	// own bounds.
	StreamsBoundClosed uint64
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
// what failed (StepTUN, StepEngine, or one of the engine's Apply steps,
// dataplane.Step*), safe to show anyone; Err is the detail, for the
// node's own log.
type StartError struct {
	Step dataplane.Step
	Err  error
}

// The steps of a start before the engine's own.
const (
	StepTUN    dataplane.Step = "tun"    // creating the TUN or taking the overlay's network configuration
	StepEngine dataplane.Step = "engine" // starting the engine
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
	// mapsRefused counts the maps the node's followers refused.
	mapsRefused uint64
	removed     bool
	// mismatch: the map makes a device-mode node a server.
	mismatch bool
	// conn is a device's connection.
	conn connState
	// retrying: a start, an Apply (a connected device's too) or a
	// server's map waits to be retried.
	retrying bool
	// engine is a device's running engine; it is cleared before the engine
	// closes, and Status calls it under mu, so it is never used closed.
	engine    *dataplane.Engine
	listeners int
	// workers is a server's supervisor, while it runs.
	workers workerReporter
	// preset is a device's rule preset (Status.RulePreset), and
	// connectOnBoot its connect-on-boot.
	preset        string
	connectOnBoot bool
	// killSwitch is a device's kill switch (Status.KillSwitch).
	killSwitch KillSwitchStatus
	// lastRun is what the previous run left in the crash trace file
	// (Node.KeepLastRun).
	lastRun LastRun
	// dns says why a device's OS may resolve outside its resolver.
	dns func() error
	// dnsNoUpstream says a device's resolver has no direct upstream (nil
	// while none runs).
	dnsNoUpstream func() bool
	// dnsUpstreamsRefused is an exit's count of resolver upstreams the
	// worker's egress refuses (Status.DNSUpstreamsRefused).
	dnsUpstreamsRefused int
	// exitDeadline is dataplane.ExitHandshakeDeadline, or the tests'
	// (tuning).
	exitDeadline time.Duration
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
	return p.statusLocked()
}

// forDiagnostics is the status and its running data plane's TUN ("" while
// it is down) and last Apply (nil before one), taken together.
func (p *report) forDiagnostics() (Status, string, *dataplane.ApplyTrace) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.engine == nil {
		return p.statusLocked(), "", nil
	}
	st, tr, ok := p.engine.StatusAndLastApply()
	var last *dataplane.ApplyTrace
	if ok {
		last = &tr
	}
	return p.statusWith(&st), p.engine.TUNName(), last
}

// lastRunTrace is what the previous run left (report.lastRun).
func (p *report) lastRunTrace() LastRun {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastRun
}

func (p *report) statusLocked() Status { return p.statusWith(nil) }

// statusWith is the status, with dp as the engine's if it was read
// already (nil: read it now).
func (p *report) statusWith(dp *dataplane.Status) Status {
	s := Status{Mode: p.mode, Space: p.space, MapVersion: p.version, MapsRefused: p.mapsRefused, Removed: p.removed, ModeMismatch: p.mismatch, Retrying: p.retrying, Listeners: p.listeners, DNSUpstreamsRefused: p.dnsUpstreamsRefused,
		LastRunCrashed: p.lastRun.Crashed(), LastRunUnreadable: p.lastRun.Unreadable != ""}
	if p.mode != ModeServer {
		s.RulePreset, s.ConnectOnBoot = p.preset, p.connectOnBoot
		s.KillSwitch = p.killSwitch
	}
	switch {
	case p.mode == ModeServer:
		s.Connection = Serving
	case p.conn == connConnected:
		s.Connection = Connected
	case p.conn != connDisconnected:
		// Meant to be up: starting, retrying, or out of its space.
		s.Connection = Connecting
	}
	if p.engine != nil {
		if dp == nil {
			st := p.engine.Status()
			dp = &st
		}
		st := *dp
		s.DataPlane, s.Interface = &st, p.engine.TUNName()
		s.RulesEnforced, s.PresetUnavailable = true, st.Rules.PresetUnavailable
		var problem error
		if p.dns != nil {
			problem = p.dns()
		}
		// Read once: both flags come from the same Problem.
		s.DNSUnprotected = dns.Unprotected(problem)
		s.DNSUpstreamsStale = errors.Is(problem, dns.ErrUpstreamsStale)
		// Unknown upstreams (stale) aren't absent ones: one cause, one code.
		s.DNSNoUpstream = !s.DNSUpstreamsStale &&
			(errors.Is(problem, dns.ErrNoSystemUpstream) || p.dnsNoUpstream != nil && p.dnsNoUpstream())
		s.ExitsUnanswered, s.DefaultExitUnanswered = exitHandshakes(&st, p.exitDeadline)
	}
	if p.workers != nil {
		for _, w := range p.workers.Workers() {
			s.Workers = append(s.Workers, WorkerStatus{
				Space: w.Space, Ready: w.Ready, Starts: w.Starts, ReadySince: w.ReadyAt, RestartAt: w.NextStart,
				LastExit: w.LastExitReason,
			})
		}
		e := p.workers.Egress()
		s.Egress = &e
		for _, l := range p.workers.Listeners() {
			s.PublicListeners = append(s.PublicListeners, PublicListenerStatus{
				Transport: l.Transport, Routed: l.Routed, Unauthenticated: l.Unauthenticated, NoSpace: l.NoSpace,
				StreamsOverloaded: l.StreamsOverloaded, StreamsBoundClosed: l.StreamsBoundClosed, Rejected: len(l.Rejected),
			})
		}
	}
	return s
}

// exitHandshakes grades the exits among st.Peers as of st.ReadAt: how
// many are unanswered, and whether the default rule's exit is one of them.
// Ages are measured to the read, never to a later clock reading: a stall
// before grading would age the snapshot's initiations past answers it
// can't show. An exit
// is unanswered once the first initiation sent to it since its first hop
// came up has gone deadline without an answer: while the first hop is
// down that is the neighbor's problem (one cause, one code), and
// WireGuard's initiations can't get through; one sent before the first
// hop came back tells nothing of the exit, however long pending. So an
// exit nothing was sent to isn't counted, nor one sent nothing since its
// first hop came up (WireGuard gives up retrying after 90 s without
// traffic): nothing has tested the link since it returned. One flagged
// while its first hop stayed up stays so until a handshake completes,
// even if traffic to it stops. A chain has one exit, so a default exit
// unanswered (RuleStatus.DefaultExits: what carries either family's
// background route) is the internet lost, whatever the other exits do.
func exitHandshakes(st *dataplane.Status, deadline time.Duration) (unanswered int, defaultUnanswered bool) {
	up := make(map[netmap.NodeID]bool, len(st.Neighbors))
	for _, n := range st.Neighbors {
		up[netmap.NodeID(n.Node)] = n.Up
	}
	for _, p := range st.Peers {
		sent := p.FirstInitiationSinceLinkUp
		if !p.Exit || !up[p.FirstHop] || sent.IsZero() || st.ReadAt.Sub(sent) < deadline {
			continue
		}
		unanswered++
		defaultUnanswered = defaultUnanswered || slices.Contains(st.Rules.DefaultExits[:], p.ID)
	}
	return unanswered, defaultUnanswered
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
	Problems []Problem
}

// Problem is what Health says is wrong: a code.
type Problem string

// The problems Health names.
const (
	ProblemDisconnected Problem = "disconnected"
	ProblemRemoved      Problem = "removed_from_space"
	// ProblemModeMismatch: the map makes a node run in device mode a
	// server; it carries nothing until its operator sets server mode.
	ProblemModeMismatch   Problem = "mode_mismatch"
	ProblemStarting       Problem = "starting"
	ProblemRetrying       Problem = "retrying"
	ProblemApplyFailed    Problem = "apply_failed"    // the last Apply failed; DataPlane.LastApplyError says where
	ProblemNoLinkUp       Problem = "no_link_up"      // no adjacent node answers
	ProblemNeighborDown   Problem = "neighbor_down"   // some adjacent node doesn't answer
	ProblemSkipped        Problem = "entries_skipped" // the map holds entries the node can't use
	ProblemWorkerDown     Problem = "worker_down"     // a space's worker isn't ready
	ProblemWorkerRestarts Problem = "worker_restarted"
	ProblemLinksRejected  Problem = "links_rejected" // a public listener refused peer links
	// ProblemPresetUnavailable: the map can't build the device's rule
	// preset, so it is enforced failing closed (no internet but the local
	// ranges' direct routes).
	ProblemPresetUnavailable Problem = "rule_preset_unavailable"
	// ProblemRouteTable: the OS routing table doesn't hold the rules now
	// (putting it back failed): traffic may go around the tunnel.
	ProblemRouteTable Problem = "route_table_not_enforced"
	// ProblemRulesAhead: other software's policy rules come before the
	// route table's and may route traffic around the tunnel.
	ProblemRulesAhead Problem = "policy_rules_ahead"
	// ProblemOverlayRoutesAhead: other routes the route table can't
	// outrank take overlay addresses (a hostile network's host routes,
	// macOS): those peers' traffic leaves around the tunnel.
	ProblemOverlayRoutesAhead Problem = "overlay_routes_ahead"
	// ProblemGuard: the leak guard isn't in place now (applying it
	// failed; retried): IPv6 from interface-bound sockets may go around
	// the tunnel.
	ProblemGuard Problem = "ipv6_guard_not_enforced"
	// ProblemGuardUnsupported: the OS can't hold the leak guard (Linux:
	// no nf_tables; macOS: no `anchor "com.apple/*"` in pf's main
	// ruleset): the device connects, but IPv6 from interface-bound
	// sockets isn't confined.
	ProblemGuardUnsupported Problem = "ipv6_guard_unsupported"
	// ProblemKillSwitch: a device's kill switch isn't as meant (putting
	// it in place or removing it failed; retried every 10 s): while it
	// should be in, traffic may leave around the tunnel when it is down.
	ProblemKillSwitch Problem = "kill_switch_not_enforced"
	// ProblemKillSwitchUnsupported: the OS can't hold the kill switch
	// (Linux: no nf_tables; macOS: no pfctl) while it should be in.
	ProblemKillSwitchUnsupported Problem = "kill_switch_unsupported"
	// ProblemRouteRecordsCorrupt: a route record of thinkpol's was found
	// corrupt this boot (macOS; the log names it and says why) while
	// routes with thinkpol's route flag that no record names are in
	// place. Those are left alone as foreign ones: an owner already
	// running when its record went bad still removes its own and rewrites
	// its record at its next change, and the problem goes; the rest (a
	// dead owner's, or a set-aside record's) stay until reboot unless they
	// went with their owner's interface (a leftover host route sends its
	// address around the tunnel, policy_rules_ahead; leftover reject
	// routes keep blocking). Removing a set-aside file acknowledges the
	// problem; it does not remove the routes.
	ProblemRouteRecordsCorrupt Problem = "route_records_corrupt"
	// ProblemDNSUnprotected: the OS may resolve names outside the node's
	// resolver, so names may leave outside the tunnel.
	ProblemDNSUnprotected Problem = "dns_not_protected"
	// ProblemDNSUpstreamsStale: the device's direct upstreams may be stale
	// (the last read of the OS's own resolvers failed), so `direct` names
	// may not resolve; the OS still resolves through the node.
	ProblemDNSUpstreamsStale Problem = "dns_upstreams_stale"
	// ProblemDNSUpstreamRefused: resolver upstreams the worker's egress
	// refuses (Status.DNSUpstreamsRefused counts them) aren't configured:
	// the resolver asks the rest, and with none left tunnel-bound names
	// fail.
	ProblemDNSUpstreamRefused Problem = "dns_upstream_refused"
	// ProblemDNSNoUpstream: a device's resolver has no direct upstream to
	// ask, so `direct` names don't resolve (Status.DNSNoUpstream).
	ProblemDNSNoUpstream Problem = "dns_no_upstream"
	// ProblemExitNoHandshake: an exit the device routes through,
	// directly or behind a relay, has left WireGuard's handshake
	// unanswered past the deadline while its first hop was up
	// (Status.ExitsUnanswered). Down when the exit of the chain carrying
	// either family's background (/0) route is unanswered (a chain has one
	// exit, so none of its exits answers): that family's destinations no
	// other route names are lost. The background route is the action with
	// the most addresses, which may not be the default rule's (rules
	// before it can take every address). Degraded for any other exit
	// unanswered. Only a completed handshake clears it, even if the device
	// goes idle. The deadline runs from the first initiation sent since the
	// first hop came up: one pending from before doesn't count, and an exit
	// sent none since isn't graded.
	ProblemExitNoHandshake Problem = "exit_no_handshake"
)

// Health grades the status.
func (s Status) Health() Health {
	var h Health
	add := func(level HealthLevel, problem Problem) {
		h.Level = max(h.Level, level)
		h.Problems = append(h.Problems, problem)
	}
	if s.Removed {
		add(HealthDown, ProblemRemoved)
	}
	if s.ModeMismatch {
		add(HealthDown, ProblemModeMismatch)
	}
	switch s.Connection {
	case Disconnected:
		add(HealthDown, ProblemDisconnected)
	case Connecting:
		if s.Retrying {
			add(HealthDown, ProblemRetrying)
		} else if !s.Removed && !s.ModeMismatch {
			add(HealthDown, ProblemStarting)
		}
	case Serving:
		s.serverProblems(add)
	}
	if s.DataPlane != nil {
		s.dataPlaneProblems(add)
	}
	switch s.KillSwitch.Error {
	case "", KillSwitchNotApplied:
	case KillSwitchUnsupported:
		add(HealthDegraded, ProblemKillSwitchUnsupported)
	default:
		add(HealthDegraded, ProblemKillSwitch)
	}
	return h
}

// serverProblems adds a server's problems: its map, workers, listeners
// and resolver upstreams.
func (s Status) serverProblems(add func(HealthLevel, Problem)) {
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

// dataPlaneProblems adds a running data plane's problems: its map, links,
// exits, rules, route table and DNS.
func (s Status) dataPlaneProblems(add func(HealthLevel, Problem)) {
	dp := s.DataPlane
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
	switch {
	case s.DefaultExitUnanswered:
		add(HealthDown, ProblemExitNoHandshake)
	case s.ExitsUnanswered > 0:
		add(HealthDegraded, ProblemExitNoHandshake)
	}
	if len(dp.Skipped) > 0 {
		add(HealthDegraded, ProblemSkipped)
	}
	if s.PresetUnavailable {
		add(HealthDegraded, ProblemPresetUnavailable)
	}
	routeTableProblems(dp.RouteTable, add)
	if s.DNSUnprotected {
		add(HealthDegraded, ProblemDNSUnprotected)
	}
	if s.DNSUpstreamsStale {
		add(HealthDegraded, ProblemDNSUpstreamsStale)
	}
	if s.DNSNoUpstream {
		add(HealthDegraded, ProblemDNSNoUpstream)
	}
}

// routeTableProblems adds the OS routing table's problems and its leak
// guard's.
func routeTableProblems(rt dataplane.RouteTableStatus, add func(HealthLevel, Problem)) {
	if rt.Error != "" {
		add(HealthDown, ProblemRouteTable)
	} else if rt.Enforced && rt.RulesAhead > 0 {
		add(HealthDegraded, ProblemRulesAhead)
	}
	if rt.Error == "" && rt.OverlayAhead > 0 {
		add(HealthDown, ProblemOverlayRoutesAhead)
	}
	if rt.CorruptRecords > 0 && rt.UnownedRoutes > 0 {
		add(HealthDegraded, ProblemRouteRecordsCorrupt)
	}
	switch rt.GuardError {
	case "":
	case dataplane.RouteTableGuardUnsupported:
		add(HealthDegraded, ProblemGuardUnsupported)
	default:
		add(HealthDegraded, ProblemGuard)
	}
}
