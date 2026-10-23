package agent

import (
	"context"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// Diagnostics is a snapshot of what the node changed on the host and what
// the host shows of it (`thinkpol diag`, TP-091): the evidence a device
// run records. Taking it changes nothing. A part the agent couldn't read
// says why in its Unreadable, so "nothing there" and "couldn't look" stay
// apart.
type Diagnostics struct {
	Status Status
	// TUN is a device's overlay interface as the host reports it.
	TUN netcfg.InterfaceReport
	// LastApply is a device's running data plane's last Apply, its steps
	// with their timings.
	LastApply ApplyReport
	// HostParts says Routes, Guard and DNS were read: they name public
	// addresses (the entries', the direct destinations', the gateway's,
	// the upstreams'), so they are taken only for root.
	HostParts bool
	// Routes are the routes and rules the agent's owners hold, and Guard
	// the leak guard, as the host holds them, whatever the data plane's
	// state (a crashed run's show too).
	Routes netcfg.Inspection
	Guard  routetable.GuardReport
	// DNS is the resolvers the host uses, for the overlay's names and the
	// rest.
	DNS dns.HostReport
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
	// DNS reads the host's resolvers (dns.Inspect).
	DNS func(ctx context.Context) dns.HostReport
}

// Diagnose takes the node's diagnostics, with the host parts only when
// withHostParts (otherwise each says it is root's, unread). The status,
// the data plane's TUN name and its last Apply are one read; the TUN
// itself is read from the host after it, so a data plane stopping in
// between shows as a TUN that can't be read.
func (n *Node) Diagnose(ctx context.Context, withHostParts bool) Diagnostics {
	st, tun, last := n.report.forDiagnostics()
	d := Diagnostics{Status: st, TUN: netcfg.InterfaceReport{Unreadable: UnreadableNoTUN}, LastApply: ApplyReport{Unreadable: UnreadableNoApply}}
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
		d.DNS = dns.HostReport{Unreadable: UnreadableRootOnly}
		return d
	}
	d.HostParts = true
	d.Routes = n.plat.Inspect.Routes()
	d.Guard = n.plat.Inspect.Guard(ctx)
	d.DNS = n.plat.Inspect.DNS(ctx)
	return d
}
