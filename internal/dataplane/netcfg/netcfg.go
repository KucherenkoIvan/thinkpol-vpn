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
	// Rules are policy routing rules (Linux): which table a packet's
	// route is looked up in. Without any, every route is in the main
	// table and Route.Table must be zero.
	Rules []Rule
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

// Route is one route in a routing table, the main one unless Table says
// otherwise. Its identity is its table, destination and metric (as in the
// OS routing table); its type, gateway and interface are values. Blocking
// traffic is the firewall's job; RouteUnreachable is only for a table
// that must never fall through to the next rule (policy routing).
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
	// Table is the routing table (Linux: 1–252 or 256 and up); 0 is the
	// main table.
	Table int
	// Type is what the route does; RouteThrow and RouteUnreachable take
	// no Gateway or Interface.
	Type RouteType
}

// RouteType is what a route does with the packets it matches.
type RouteType int

const (
	// RouteUnicast sends them to Gateway or on-link out of Interface.
	RouteUnicast RouteType = iota
	// RouteThrow ends the lookup in this table: the next policy rule
	// decides, as if the table had no route for the destination.
	RouteThrow
	// RouteUnreachable drops them, telling the sender the destination is
	// unreachable.
	RouteUnreachable
)

func (t RouteType) String() string {
	switch t {
	case RouteUnicast:
		return "unicast"
	case RouteThrow:
		return "throw"
	case RouteUnreachable:
		return "unreachable"
	}
	return fmt.Sprintf("RouteType(%d)", int(t))
}

// Rule is a policy routing rule (Linux `ip rule`): packets it matches are
// looked up in Table; a lookup that finds nothing (or a throw route) goes
// on to the next rule. Its identity is all of its fields.
type Rule struct {
	Family Family
	// Priority orders rules, lower first: 1–32765, below the main table's
	// 32766.
	Priority int
	// Dst, when valid, matches only packets to this prefix (`to`), of
	// the rule's family.
	Dst netip.Prefix
	// Oif, when set, matches only lookups for this outgoing interface
	// (`oif`): sockets bound to it, and the kernel resolving the gateway
	// of a route given with this device.
	Oif string
	// Table is the table to look up; 0 is the main table.
	Table int
	// Mark, when non-zero, matches only packets with exactly this
	// firewall mark (sockets set it with SO_MARK).
	Mark uint32
	// Invert matches the packets the rule's selector doesn't (`not
	// fwmark`).
	Invert bool
	// SuppressDefaultRoutes ignores the table's routes with prefix length
	// 0 (`suppress_prefixlength 0`): the lookup finds only more specific
	// routes there.
	SuppressDefaultRoutes bool
}

func (r Rule) String() string {
	s := fmt.Sprintf("%v rule %d", r.Family, r.Priority)
	if r.Invert {
		s += " not"
	}
	if r.Dst.IsValid() {
		s += " to " + r.Dst.String()
	}
	if r.Oif != "" {
		s += " oif " + r.Oif
	}
	if r.Mark != 0 {
		s += fmt.Sprintf(" fwmark %#x", r.Mark)
	} else if !r.Dst.IsValid() && r.Oif == "" {
		s += " all"
	}
	s += fmt.Sprintf(" table %d", r.Table)
	if r.SuppressDefaultRoutes {
		s += " suppress_prefixlength 0"
	}
	return s
}

// Family returns the route's address family.
func (r Route) Family() Family { return FamilyOf(r.Dst.Addr()) }

func (r Route) String() string {
	s := r.Dst.String()
	if r.Type != RouteUnicast {
		s = r.Type.String() + " " + s
	}
	if r.Gateway.IsValid() {
		s += " via " + r.Gateway.String()
	}
	if r.Interface != "" {
		s += " dev " + r.Interface
	}
	if r.Metric != 0 {
		s += fmt.Sprintf(" metric %d", r.Metric)
	}
	if r.Table != 0 {
		s += fmt.Sprintf(" table %d", r.Table)
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
		if err := checkTable(r.Table); err != nil {
			return fmt.Errorf("netcfg: route %v: %w", r, err)
		}
		switch {
		case r.Type == RouteThrow || r.Type == RouteUnreachable:
			if r.Gateway.IsValid() || r.Interface != "" {
				return fmt.Errorf("netcfg: route %v: a %v route has no gateway or interface", r, r.Type)
			}
		case r.Type != RouteUnicast:
			return fmt.Errorf("netcfg: route %v: unknown type", r)
		case r.Gateway.IsValid():
			if FamilyOf(r.Gateway) != r.Family() || r.Gateway.Is4In6() {
				return fmt.Errorf("netcfg: route %v: gateway is not in the destination's family", r)
			}
			if r.Gateway.IsUnspecified() || r.Gateway.Zone() != "" {
				return fmt.Errorf("netcfg: route %v: unspecified or zoned gateway", r)
			}
			if r.Gateway.Is6() && r.Gateway.IsLinkLocalUnicast() && r.Interface == "" {
				return fmt.Errorf("netcfg: route %v: a link-local gateway needs an interface", r)
			}
		case r.Interface == "":
			return fmt.Errorf("netcfg: route %v: needs a gateway or an interface", r)
		}
		if r.Metric < 0 || uint64(r.Metric) > math.MaxUint32 {
			return fmt.Errorf("netcfg: route %v: metric out of range", r)
		}
		k := key{r.Table, r.Metric, r.Dst}
		if routes[k] {
			return fmt.Errorf("netcfg: route %v listed twice", r)
		}
		routes[k] = true
	}
	rules := make(map[Rule]bool, len(c.Rules))
	for _, r := range c.Rules {
		if r.Family != IPv4 && r.Family != IPv6 {
			return fmt.Errorf("netcfg: rule %v: unknown family", r)
		}
		if r.Priority < 1 || r.Priority > maxRulePriority {
			return fmt.Errorf("netcfg: rule %v: priority out of 1–%d", r, maxRulePriority)
		}
		if err := checkTable(r.Table); err != nil {
			return fmt.Errorf("netcfg: rule %v: %w", r, err)
		}
		if r.Dst.IsValid() && (r.Dst != r.Dst.Masked() || FamilyOf(r.Dst.Addr()) != r.Family || r.Dst.Addr().Is4In6()) {
			return fmt.Errorf("netcfg: rule %v: destination must be a masked prefix of the rule's family", r)
		}
		if rules[r] {
			return fmt.Errorf("netcfg: rule %v listed twice", r)
		}
		rules[r] = true
	}
	return nil
}

// maxRulePriority keeps rules ahead of the main table's (32766).
const maxRulePriority = 32765

// The tables Linux reserves: a Route or Rule names main as 0.
const (
	tableDefault = 253
	tableMain    = 254
	tableLocal   = 255
)

func checkTable(t int) error {
	if t < 0 || uint64(t) > math.MaxUint32 || t == tableDefault || t == tableMain || t == tableLocal {
		return fmt.Errorf("table %d is not 0 (main) or one of 1–252, 256 and up", t)
	}
	return nil
}

// ConnectedRoutes are the destinations netcfg routes into a
// point-to-point interface (macOS's utun; Linux's kernel routes the whole network) for one of its networks: the
// network's two halves.
func ConnectedRoutes(network netip.Prefix) []netip.Prefix {
	network = network.Masked()
	if network.Bits() >= network.Addr().BitLen() {
		return []netip.Prefix{network}
	}
	lo := netip.PrefixFrom(network.Addr(), network.Bits()+1)
	b := network.Addr().AsSlice()
	b[network.Bits()/8] |= 0x80 >> (network.Bits() % 8)
	hi, _ := netip.AddrFromSlice(b)
	return []netip.Prefix{lo, netip.PrefixFrom(hi, network.Bits()+1)}
}

// Clear removes what a dead configurator of owner left on this host (a
// crash): it takes the owner's place and closes it with nothing applied,
// which removes every route the owner still holds and, on macOS, empties
// the owner's record, routes gone with their interface included.
// errors.ErrUnsupported where this OS has no adapter for owner; ErrBusy
// while a configurator of owner is alive.
func Clear(owner Owner) error {
	c, err := New(owner)
	if err != nil {
		return err
	}
	return c.Close()
}

// Survey is the OS's own routing, as route-table enforcement needs it.
type Survey struct {
	// OnLink are the main table's routes the OS made for interfaces'
	// addresses (Linux: proto kernel, without a gateway): the subnets
	// reached on-link, both families.
	OnLink []netip.Prefix
	// Links are the namespace's interfaces, loopback included.
	Links []Link
	// ForeignRules are the priorities of policy rules no owner added,
	// but the OS's own (0, 32766, 32767), both families (Linux).
	ForeignRules []int
	// Defaults are the usable default routes no owner added, at most one
	// per family (macOS, whose route-table layout names the gateway).
	Defaults []Route
	// Routes are the other routes of the main table no owner added that
	// may take traffic ahead of routes into the TUN: gateway routes,
	// interface routes not made for an interface's own subnet (another
	// VPN's, a DHCP server's classless routes), host routes (macOS, where
	// everything is looked up in the main table; Linux's policy routing
	// never looks them up ahead of the tunnel).
	Routes []Route
	// Held are the destinations every unscoped route of the main table no
	// owner added holds, whatever it does (reject, local, loopback,
	// redirect routes included): on macOS a route's identity is its
	// destination, so these are what owners' routes must not take.
	Held []netip.Prefix
}

// Link is an interface as Survey sees it.
type Link struct {
	Name string
	// Up says the interface is administratively up (it can hold routes).
	Up bool
}

// Configurator applies a Config to the OS for one Owner and owns what it
// adds.
//
// The contract, on every OS:
//   - At most one configurator per owner is alive in a network namespace;
//     constructing a second fails with ErrBusy. Routes and rules are
//     tagged with the owner's identity, so every one carrying it is this
//     configurator's: added by it, or left by a predecessor that died
//     without Close.
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
//   - Close removes every owned address, route and rule and restores every
//     interface it changed; something already gone (an interface deleted by
//     its owner) counts as removed. Close is idempotent; if it fails, what's
//     left stays recorded and calling Close again retries it. Only a
//     successful Close frees the owner's place in the namespace (Linux;
//     on macOS a failed Close frees it too, and what is left stays in the
//     owner's record for its next configurator to take over).
//
// Methods are safe for concurrent use.
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error
	// DefaultRoute returns the usable default route of the family that no
	// configurator owns, preferring the lowest metric: the physical gateway
	// that direct traffic and entry endpoints are routed through.
	DefaultRoute(ctx context.Context, f Family) (Route, error)
	// Watch reports, coalesced, changes that may call for an Apply: a
	// default route in the main table that is no owner's came, went or
	// changed (the physical gateway); an interface's on-link routes
	// changed (its addresses); an interface came, went or changed state
	// (a link going down takes its routes along, and Linux doesn't say so
	// for IPv4); or a route or rule of this owner was deleted (from
	// outside, or by Apply itself: re-applying then changes nothing). The
	// channel closes when ctx ends or watching fails; ErrUnsupported where
	// an adapter can't watch.
	Watch(ctx context.Context) (<-chan struct{}, error)
	// Survey reports what the OS's own routing holds that route-table
	// enforcement builds on.
	Survey(ctx context.Context) (Survey, error)
	Close() error
}
