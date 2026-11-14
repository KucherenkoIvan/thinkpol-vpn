package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// Diagnostics is a snapshot of what the node changed on the host and what
// the host shows of it (`thinkpol diag`, TP-091): the evidence a device
// run records. Taking it changes nothing. A part the agent couldn't read
// says why in its Unreadable, so "nothing there" and "couldn't look" stay
// apart.
type Diagnostics struct {
	// Agent is who took it: AgentRunning, the agent itself; AgentNotRunning
	// or AgentNotAnswering, root's diag reading the host without it
	// (DiagnoseHost).
	Agent  AgentPresence
	Status Status
	// StatusUnreadable says why there is no Status: no agent answered.
	StatusUnreadable string
	// TUN is a device's overlay interface as the host reports it.
	TUN netcfg.InterfaceReport
	// LastApply is a device's running data plane's last Apply, its steps
	// with their timings.
	LastApply ApplyReport
	// HostParts says Routes, Guard, KillSwitch and DNS were read: they
	// name public addresses (the entries', the direct destinations', the
	// gateway's, the upstreams'), so they are taken only for root.
	HostParts bool
	// Routes are the routes and rules the agent's owners hold, Guard the
	// leak guard and KillSwitch the kill switch, as the host holds them,
	// whatever the data plane's and the kill switch's state (what a
	// crashed or stopped run left shows too).
	Routes     netcfg.Inspection
	Guard      routetable.GuardReport
	KillSwitch firewall.KillSwitchReport
	// DNS is the resolvers the host uses, for the overlay's names and the
	// rest.
	DNS dns.HostReport
	// DropIns are the service's systemd drop-ins: unsupported, reported.
	DropIns DropInReport
	// LastRun is what the previous run under a device's service left on
	// its stderr (KeepLastRun), none otherwise. Taken only for root, like
	// the host parts: a panic's message or the error a run exited with
	// may name a public address.
	LastRun LastRun
}

// DropInReport lists drop-ins for the service's systemd unit
// (thinkpol.service.d/*.conf and service.d/*.conf), which are unsupported: one can set
// THINKPOL_* variables behind the node file's back
// (docs/design/configuration.md "File formats"). Unreadable says why they
// couldn't be listed.
type DropInReport struct {
	Unreadable string
	Paths      []string
}

// Why a part of Diagnostics is unreadable, when the agent says so itself
// rather than quoting what failed.
const (
	// UnreadableNoTUN: the data plane is down, so there is no TUN to read.
	UnreadableNoTUN = "no TUN: the data plane is down"
	// UnreadableNoApply: the data plane is down, or hasn't applied a map
	// yet.
	UnreadableNoApply = "no Apply: the data plane is down or hasn't applied a map yet"
	// UnreadableServer: a server's data planes run in its workers, one per
	// space, with no TUN of the host's (the status has the workers).
	UnreadableServer = "a server: its data planes run in its workers"
	// UnreadableRootOnly: a part that names public addresses, taken for a
	// caller who isn't root.
	UnreadableRootOnly = "root only: it names public addresses"
)

// AgentPresence is whether an agent took a snapshot, its JSON value
// (snake_case: docs/design/api-overview.md, "Naming").
type AgentPresence string

const (
	// AgentRunning: the agent answered and took the snapshot.
	AgentRunning AgentPresence = "running"
	// AgentNotRunning: nothing accepted the local API's connection (no
	// socket, or one nothing listens on): root's diag read the host
	// itself.
	AgentNotRunning AgentPresence = "not_running"
	// AgentNotAnswering: something accepted the connection but no snapshot
	// came in time: root's diag read the host itself, beside an agent that
	// may still be changing it.
	AgentNotAnswering AgentPresence = "not_answering"
)

// Why a part only the agent knows (the status, the TUN, the last Apply)
// is unreadable in a snapshot taken without it.
const (
	UnreadableAgentNotRunning   = "the agent is not running: only it knows this"
	UnreadableAgentNotAnswering = "the agent didn't answer: only it knows this"
)

// ErrDiagNeedsRoot: diag found no agent to answer, and its caller isn't
// root, who alone may read the host's parts itself.
var ErrDiagNeedsRoot = &NeedsRootError{Why: "no agent answered, and reading the host without it is root's: its parts name public addresses"}

// DiagnoseHost is the snapshot root's `thinkpol diag` takes itself when
// no agent answers (TP-133), whatever a dead run left: the host parts
// through insp, the agent's own readers, the drop-ins, and the crash
// trace file at tracePath, read as it is. The parts only the agent knows
// are unreadable, saying which of not running and not answering it was.
// Like the agent's readers it only reads: no lock, no directory made,
// nothing written. A caller who isn't root gets ErrDiagNeedsRoot and no
// snapshot.
func DiagnoseHost(ctx context.Context, insp Inspector, presence AgentPresence, tracePath string) (Diagnostics, error) {
	if os.Geteuid() != 0 {
		return Diagnostics{}, ErrDiagNeedsRoot
	}
	return diagnoseHost(ctx, insp, presence, tracePath), nil
}

// diagnoseHost is DiagnoseHost past its root check.
func diagnoseHost(ctx context.Context, insp Inspector, presence AgentPresence, tracePath string) Diagnostics {
	why := UnreadableAgentNotRunning
	if presence == AgentNotAnswering {
		why = UnreadableAgentNotAnswering
	}
	return Diagnostics{
		Agent:            presence,
		StatusUnreadable: why,
		TUN:              netcfg.InterfaceReport{Unreadable: why},
		LastApply:        ApplyReport{Unreadable: why},
		HostParts:        true,
		Routes:           insp.Routes(),
		Guard:            insp.Guard(ctx),
		KillSwitch:       insp.KillSwitch(ctx),
		DNS:              insp.DNS(ctx),
		DropIns:          insp.DropIns(),
		LastRun:          readLastRun(tracePath),
	}
}

// readLastRun reads the crash trace file at path as a start would
// (readCrashTrace), without a start's fixing, cutting or emptying it: a
// panic's or a fatal error's trace a dead run left. No file is none. A
// file that isn't a regular one with a single link isn't read.
func readLastRun(path string) LastRun {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return LastRun{}
	case err != nil:
		return LastRun{Unreadable: err.Error()}
	case !fi.Mode().IsRegular():
		return LastRun{Unreadable: "not a regular file, not read"}
	case linkCount(fi) != 1:
		return LastRun{Unreadable: "the trace file has more than one link, not read"}
	}
	return readCrashTrace(path, fi)
}

// ApplyReport is a data plane's last Apply; Unreadable says why there is
// none.
type ApplyReport struct {
	Unreadable string
	Trace      dataplane.ApplyTrace
}

// Inspector reads what the host shows of the node's changes, for
// Diagnose. Its readers only read; each says in its report why it
// couldn't. Every field is set.
type Inspector struct {
	// Interface reads an interface by name (netcfg.InspectInterface).
	Interface func(name string) netcfg.InterfaceReport
	// Routes reads the routes and rules the owners hold (netcfg.Inspect).
	Routes func() netcfg.Inspection
	// Guard reads the leak guard (firewall.InspectIPv6Guard).
	Guard func(ctx context.Context) routetable.GuardReport
	// KillSwitch reads the kill switch (firewall.InspectKillSwitch).
	KillSwitch func(ctx context.Context) firewall.KillSwitchReport
	// DNS reads the host's resolvers (dns.Inspect).
	DNS func(ctx context.Context) dns.HostReport
	// DropIns lists the service's systemd drop-ins (service.HostDropIns).
	DropIns func() DropInReport
}

// Diagnose takes the node's diagnostics, with the host parts only when
// withHostParts (otherwise each says it is root's, unread). The status,
// the data plane's TUN name and its last Apply are one read; the TUN
// itself is read from the host after it, so a data plane stopping in
// between shows as a TUN that can't be read.
func (n *Node) Diagnose(ctx context.Context, withHostParts bool) Diagnostics {
	st, tun, last := n.report.forDiagnostics()
	d := Diagnostics{Status: st, TUN: netcfg.InterfaceReport{Unreadable: UnreadableNoTUN}, LastApply: ApplyReport{Unreadable: UnreadableNoApply},
		DropIns: n.plat.Inspect.DropIns()}
	switch {
	case st.Mode == ModeServer:
		d.TUN.Unreadable, d.LastApply.Unreadable = UnreadableServer, UnreadableServer
	case tun != "":
		d.TUN = n.plat.Inspect.Interface(tun)
	}
	if last != nil {
		d.LastApply = ApplyReport{Trace: *last}
	}
	if !withHostParts {
		d.Routes = netcfg.Inspection{RoutesUnreadable: UnreadableRootOnly, RulesUnreadable: UnreadableRootOnly}
		d.Guard = routetable.GuardReport{Unreadable: UnreadableRootOnly}
		d.KillSwitch = firewall.KillSwitchReport{Unreadable: UnreadableRootOnly}
		d.DNS = dns.HostReport{Unreadable: UnreadableRootOnly}
		if d.Status.LastRunCrashed || d.Status.LastRunUnreadable {
			d.LastRun = LastRun{Unreadable: UnreadableRootOnly}
		}
		return d
	}
	d.LastRun = n.report.lastRunTrace()
	d.HostParts = true
	d.Routes = n.plat.Inspect.Routes()
	d.Guard = n.plat.Inspect.Guard(ctx)
	d.KillSwitch = n.plat.Inspect.KillSwitch(ctx)
	d.DNS = n.plat.Inspect.DNS(ctx)
	return d
}
