package netcfg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
)

var (
	// ErrConflict means applying the config would change or remove an
	// address or route this configurator doesn't own. Nothing foreign is
	// ever touched; resolve it outside (or pick routes that don't collide,
	// e.g. 0.0.0.0/1 + 128.0.0.0/1 next to an existing default route).
	ErrConflict = errors.New("netcfg: conflicts with configuration not owned by thinkpol")
	// ErrNoDefaultRoute is returned by DefaultRoute when the family has none.
	ErrNoDefaultRoute = errors.New("netcfg: no default route")
	// ErrClosed is returned by a configurator after Close.
	ErrClosed = errors.New("netcfg: configurator closed")
	// ErrBusy is returned by a constructor when a configurator of the same
	// owner is alive in the same network namespace.
	ErrBusy = errors.New("netcfg: a configurator of this owner is already alive in the namespace")
)

// Owner is who a configurator configures for. Each owner has its own
// identity on the OS (on Linux, its own route protocol number) and at most
// one live configurator per network namespace, so owners never touch each
// other's routes and a new configurator knows the routes with its identity
// are its dead predecessor's.
type Owner int

const (
	// OwnerOverlay is the data plane's overlay: the TUN's addresses and the
	// overlay routes (TP-008), on a device or in a space worker's namespace.
	OwnerOverlay Owner = iota + 1
	// OwnerSupervisor is a server supervisor's plumbing: the veth ends and
	// their routes (TP-009), in the root namespace and in each space's.
	OwnerSupervisor
	// OwnerRouteTable is route-table enforcement of routing rules (TP-018):
	// direct prefixes and entry endpoints via the physical gateway, split
	// defaults into the TUN.
	OwnerRouteTable
)

// Owners lists every owner.
var Owners = []Owner{OwnerOverlay, OwnerSupervisor, OwnerRouteTable}

func (o Owner) String() string {
	switch o {
	case OwnerOverlay:
		return "overlay"
	case OwnerSupervisor:
		return "supervisor"
	case OwnerRouteTable:
		return "route-table"
	}
	return fmt.Sprintf("Owner(%d)", int(o))
}

// Family is an IP address family.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func (f Family) String() string {
	switch f {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return fmt.Sprintf("Family(%d)", int(f))
}

// FamilyOf returns the family of a, with 4in6 addresses counted as IPv6.
func FamilyOf(a netip.Addr) Family {
	if a.Is4() {
		return IPv4
	}
	return IPv6
}

// Config is the network configuration a Configurator owns: the state Apply
// converges to, not a list of changes.
type Config struct {
	Interfaces []Interface
	Routes     []Route
}

// Interface is the configuration of one existing interface (a TUN, a veth).
// Creating and deleting interfaces is the owner's job, not netcfg's.
type Interface struct {
	Name string
	// Addrs are the interface's addresses with their on-link prefix
	// length, e.g. 100.64.0.7/10 and fd12:3456:789a::7/48. On Linux,
	// removing an IPv4 address that is the primary one of its subnet also
	// removes the subnet's secondary addresses, unless the interface has
	// promote_secondaries set; netcfg only adds addresses to interfaces
	// it is given, so keep foreign addresses out of an owned subnet.
	Addrs []netip.Prefix
	// MTU is set when non-zero; zero leaves the interface's MTU alone.
	MTU int
	// Up brings the interface up; false leaves its state alone.
	Up bool
}

// Route is one route in the main routing table. Its identity is its
// destination and metric (as in the OS routing table); its gateway and
// interface are values. Blocking traffic is the firewall's job, not a route
// type's.
type Route struct {
	// Dst is the destination prefix, masked: 0.0.0.0/0 and ::/0 are the
	// default routes of each family.
	Dst netip.Prefix
	// Gateway is the next hop, in Dst's family; the zero Addr makes the
	// route on-link through Interface.
	Gateway netip.Addr
	// Interface is the outgoing interface. Required for an on-link route;
	// optional with a Gateway (the OS picks the interface that reaches it).
	Interface string
	// Metric orders routes to the same Dst, lower first; 0 is the OS
	// default (1024 for IPv6 on Linux, so 0 and 1024 are the same route).
	Metric int
}

// Family returns the route's address family.
func (r Route) Family() Family { return FamilyOf(r.Dst.Addr()) }

func (r Route) String() string {
	s := r.Dst.String()
	if r.Gateway.IsValid() {
		s += " via " + r.Gateway.String()
	}
	if r.Interface != "" {
		s += " dev " + r.Interface
	}
	if r.Metric != 0 {
		s += fmt.Sprintf(" metric %d", r.Metric)
	}
	return s
}

// minIPv6MTU is the smallest MTU IPv6 works with; below it the OS disables
// IPv6 on the interface.
const minIPv6MTU = 1280

// Validate reports the first problem that makes c impossible to apply, so a
// bad config is rejected before anything is changed.
func (c Config) Validate() error {
	names := make(map[string]bool, len(c.Interfaces))
	for _, ifc := range c.Interfaces {
		if ifc.Name == "" {
			return errors.New("netcfg: interface without a name")
		}
		if names[ifc.Name] {
			return fmt.Errorf("netcfg: interface %s listed twice", ifc.Name)
		}
		names[ifc.Name] = true
		if ifc.MTU < 0 {
			return fmt.Errorf("netcfg: %s: negative MTU %d", ifc.Name, ifc.MTU)
		}
		addrs := make(map[netip.Addr]bool, len(ifc.Addrs))
		for _, p := range ifc.Addrs {
			if !p.IsValid() || p.Addr().Zone() != "" {
				return fmt.Errorf("netcfg: %s: invalid address %v", ifc.Name, p)
			}
			if p.Addr().Is4In6() {
				return fmt.Errorf("netcfg: %s: 4in6 address %v, use the IPv4 form", ifc.Name, p)
			}
			if addrs[p.Addr()] {
				return fmt.Errorf("netcfg: %s: address %v listed twice", ifc.Name, p.Addr())
			}
			addrs[p.Addr()] = true
			if p.Addr().Is6() && ifc.MTU != 0 && ifc.MTU < minIPv6MTU {
				return fmt.Errorf("netcfg: %s: MTU %d is below IPv6's minimum %d", ifc.Name, ifc.MTU, minIPv6MTU)
			}
		}
	}
	type key struct {
		metric int
		dst    netip.Prefix
	}
	routes := make(map[key]bool, len(c.Routes))
	for _, r := range c.Routes {
		if !r.Dst.IsValid() || r.Dst != r.Dst.Masked() || r.Dst.Addr().Is4In6() {
			return fmt.Errorf("netcfg: route %v: destination must be a masked prefix", r)
		}
		if r.Gateway.IsValid() {
			if FamilyOf(r.Gateway) != r.Family() || r.Gateway.Is4In6() {
				return fmt.Errorf("netcfg: route %v: gateway is not in the destination's family", r)
			}
			if r.Gateway.IsUnspecified() || r.Gateway.Zone() != "" {
				return fmt.Errorf("netcfg: route %v: unspecified or zoned gateway", r)
			}
			if r.Gateway.Is6() && r.Gateway.IsLinkLocalUnicast() && r.Interface == "" {
				return fmt.Errorf("netcfg: route %v: a link-local gateway needs an interface", r)
			}
		} else if r.Interface == "" {
			return fmt.Errorf("netcfg: route %v: needs a gateway or an interface", r)
		}
		if r.Metric < 0 || uint64(r.Metric) > math.MaxUint32 {
			return fmt.Errorf("netcfg: route %v: metric out of range", r)
		}
		k := key{r.Metric, r.Dst}
		if routes[k] {
			return fmt.Errorf("netcfg: route %v listed twice", r)
		}
		routes[k] = true
	}
	return nil
}

// Configurator applies a Config to the OS for one Owner and owns what it
// adds.
//
// The contract, on every OS:
//   - At most one configurator per owner is alive in a network namespace;
//     constructing a second fails with ErrBusy. Routes are tagged with the
//     owner's identity, so every route carrying it is this configurator's:
//     added by it, or left by a predecessor that died without Close.
//   - Apply converges the OS to cfg, comparing against what is actually
//     there, not against what it did before: it adds what is missing
//     (including owned state someone else removed, or that went with a
//     recreated interface), changes what differs, and removes owned state
//     cfg doesn't have, a dead predecessor's leftovers included. Re-applying
//     the same config changes nothing.
//   - Apply is all or nothing: when it fails (or ctx ends), everything it
//     changed is undone, so the system is as before the call (a failed
//     first Apply leaves nothing behind but the leftovers it found).
//   - Only owned state is ever changed or removed. An address that already
//     exists is used but not owned; the same address with another prefix
//     length, or a route with the identity of someone else's (another
//     owner's included), fails with ErrConflict. MTU and link state changes
//     are restored, unless someone changed them again since.
//   - Close removes every owned address and route and restores every
//     interface it changed; something already gone (an interface deleted by
//     its owner) counts as removed. Close is idempotent; if it fails, what's
//     left stays recorded and calling Close again retries it. Only a
//     successful Close frees the owner's place in the namespace.
//
// Methods are safe for concurrent use.
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error
	// DefaultRoute returns the usable default route of the family that no
	// configurator owns, preferring the lowest metric: the physical gateway
	// that direct traffic and entry endpoints are routed through.
	DefaultRoute(ctx context.Context, f Family) (Route, error)
	Close() error
}
