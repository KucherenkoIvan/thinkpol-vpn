package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
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
}

// Why a part of Diagnostics is unreadable, when the agent says so itself
// rather than quoting what failed.
const (
	// UnreadableNoTUN: the data plane is down, so there is no TUN to read.
	UnreadableNoTUN = "no TUN: the data plane is down"
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

// Diagnose takes the node's diagnostics. Its status and TUN are taken
// together, so the TUN read is the one the status's data plane runs on
// (unless it stopped meanwhile: the read then says so).
func (n *Node) Diagnose(_ context.Context) Diagnostics {
	st, tun := n.report.statusAndTUN()
	d := Diagnostics{Status: st, TUN: InterfaceReport{Unreadable: UnreadableNoTUN}}
	if tun != "" {
		d.TUN = n.plat.Inspect.Interface(tun)
	}
	return d
}
