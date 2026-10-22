package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"

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
	// TUN is the overlay's interface as the host reports it.
	TUN InterfaceReport
	// Routes are the routes and rules the agent's owners hold, and Guard
	// the leak guard, as the host holds them, whatever the data plane's
	// state (a crashed run's show too). They name public addresses (the
	// entries', the direct destinations', the gateway's): root's only.
	Routes netcfg.Inspection
	Guard  routetable.GuardReport
	// DNS is the resolvers the host uses, for the overlay's names and the
	// rest (the direct upstream's address among them): root's only too.
	DNS dns.HostReport
}

// Why a part of Diagnostics is unreadable, when the agent says so itself
// rather than quoting what failed.
const (
	// UnreadableNoTUN: the data plane is down, so there is no TUN to read.
	UnreadableNoTUN = "no TUN: the data plane is down"
	// UnreadableRootOnly: a part that names public addresses, taken for a
	// caller who isn't root.
	UnreadableRootOnly = "root only: it names public addresses"
)

// InterfaceReport is an interface as the host reports it.
type InterfaceReport struct {
	// Unreadable says why the interface couldn't be read; the rest is
	// then empty.
	Unreadable string
	Name       string
	Index      int
	MTU        int
	// Up and Running are the OS's IFF_UP and IFF_RUNNING.
	Up, Running bool
	// Addrs are its addresses with their prefix lengths, sorted.
	Addrs []netip.Prefix
}

// Inspector reads what the host shows of the node's changes, for
// Diagnose. Its readers only read; each says in its report why it
// couldn't. Every field is set.
type Inspector struct {
	// Interface reads an interface by name (InspectInterface).
	Interface func(name string) InterfaceReport
	// Routes reads the routes and rules the owners hold (netcfg.Inspect).
	Routes func() netcfg.Inspection
	// Guard reads the leak guard (firewall.InspectIPv6Guard).
	Guard func(ctx context.Context) routetable.GuardReport
	// DNS reads the host's resolvers (dns.Inspect).
	DNS func(ctx context.Context) dns.HostReport
}

// InspectInterface reads the interface name from the OS.
func InspectInterface(name string) InterfaceReport {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceReport{Unreadable: err.Error()}
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return InterfaceReport{Unreadable: err.Error()}
	}
	r := InterfaceReport{
		Name: ifc.Name, Index: ifc.Index, MTU: ifc.MTU,
		Up: ifc.Flags&net.FlagUp != 0, Running: ifc.Flags&net.FlagRunning != 0,
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(n.IP)
			ones, _ := n.Mask.Size()
			if ok {
				r.Addrs = append(r.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
			}
		}
	}
	slices.SortFunc(r.Addrs, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return r
}

// Diagnose takes the node's diagnostics; host leaves out the parts that
// name public addresses (each then says it is root's). Its status and TUN
// are taken together, so the TUN read is the one the status's data plane
// runs on (unless it stopped meanwhile: the read then says so).
func (n *Node) Diagnose(ctx context.Context, host bool) Diagnostics {
	st, tun := n.report.statusAndTUN()
	d := Diagnostics{Status: st, TUN: InterfaceReport{Unreadable: UnreadableNoTUN}}
	if tun != "" {
		d.TUN = n.plat.Inspect.Interface(tun)
	}
	if !host {
		d.Routes = netcfg.Inspection{RoutesUnreadable: UnreadableRootOnly, RulesUnreadable: UnreadableRootOnly}
		d.Guard = routetable.GuardReport{Unreadable: UnreadableRootOnly}
		d.DNS = dns.HostReport{Unreadable: UnreadableRootOnly}
		return d
	}
	d.Routes = n.plat.Inspect.Routes()
	d.Guard = n.plat.Inspect.Guard(ctx)
	d.DNS = n.plat.Inspect.DNS(ctx)
	return d
}
