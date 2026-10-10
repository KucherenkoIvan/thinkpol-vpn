package netcfg

import (
	"context"
	"errors"
	"fmt"
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
)

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
	// length, e.g. 100.64.0.7/10 and fd12:3456:789a::7/48.
	Addrs []netip.Prefix
	// MTU is set when non-zero; zero leaves the interface's MTU alone.
	MTU int
	// Up brings the interface up; false leaves its state alone.
	Up bool
}

// Route is one route. Its identity, within a table, is its destination and
// metric (as in the OS routing table); its gateway and interface are values.
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
	// Table is the routing table, 0 for the main one. Only Linux has others.
	Table int
	// Metric orders routes to the same Dst, lower first; 0 is the OS default.
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
	if r.Table != 0 {
		s += fmt.Sprintf(" table %d", r.Table)
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
		table, metric int
		dst           netip.Prefix
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
			if r.Gateway.IsUnspecified() {
				return fmt.Errorf("netcfg: route %v: unspecified gateway", r)
			}
		} else if r.Interface == "" {
			return fmt.Errorf("netcfg: route %v: needs a gateway or an interface", r)
		}
		if r.Table < 0 || r.Metric < 0 {
			return fmt.Errorf("netcfg: route %v: negative table or metric", r)
		}
		k := key{r.Table, r.Metric, r.Dst}
		if routes[k] {
			return fmt.Errorf("netcfg: route %v listed twice", r)
		}
		routes[k] = true
	}
	return nil
}

// Configurator applies a Config to the OS and owns what it adds.
//
// The contract, on every OS:
//   - Apply converges to cfg: it adds what is missing, changes what differs
//     and removes what it added earlier that cfg no longer has. Re-applying
//     the same config changes nothing.
//   - Apply is all or nothing: when it fails, everything it changed is
//     undone, so the system is as before the call (a failed first Apply
//     leaves nothing behind).
//   - Only owned state is ever changed or removed. An address that already
//     existed is used but not owned; a route that would replace a foreign
//     one fails with ErrConflict. MTU and link state changes are recorded
//     and restored.
//   - Close removes every owned address and route and restores every
//     interface it changed; something already gone (an interface deleted
//     by its owner) counts as removed. Close is idempotent; if it fails,
//     what's left stays recorded and calling Close again retries it.
//   - A route that is already there and was added by netcfg (left by a
//     process that crashed) is taken over. So two live configurators in one
//     network namespace must never claim the same route (table, Dst, Metric).
//
// Methods are safe for concurrent use.
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error
	// DefaultRoute returns the default route of the family that this
	// configurator doesn't own, preferring the lowest metric: the physical
	// gateway that direct traffic and entry endpoints are routed through.
	DefaultRoute(ctx context.Context, f Family) (Route, error)
	Close() error
}
