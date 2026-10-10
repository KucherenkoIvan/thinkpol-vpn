//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// RouteProtocol is the rtnetlink protocol number on every route netcfg adds
// (`ip route show proto 84`); unassigned in iproute2's rt_protos. It is how
// routes are told apart from everyone else's, also after a crash.
const RouteProtocol netlink.RouteProtocol = 84

// The kernel stores IPv6 routes added with metric 0 under this metric.
const ipv6DefaultMetric = 1024

// New returns a configurator for the network namespace of the calling
// thread.
func New() (Configurator, error) {
	ns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("netcfg: current namespace: %w", err)
	}
	return newLinux(ns, "the current namespace")
}

// NewInNamespace returns a configurator for the network namespace at path
// (e.g. /run/netns/<name> or /proc/<pid>/ns/net), without the caller
// entering it.
func NewInNamespace(path string) (Configurator, error) {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("netcfg: namespace %s: %w", path, err)
	}
	return newLinux(ns, path)
}

// newLinux takes ownership of ns. A configurator holds a shared flock on the
// namespace file for its lifetime: if it can take the lock exclusively
// first, no other configurator is alive in the namespace, and proto-84
// routes there are a crashed one's leftovers it may take over.
func newLinux(ns netns.NsHandle, name string) (Configurator, error) {
	alone := true
	if err := unix.Flock(int(ns), unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
		alone = false
	} else if err != nil {
		_ = ns.Close()
		return nil, fmt.Errorf("netcfg: lock %s: %w", name, err)
	}
	if err := unix.Flock(int(ns), unix.LOCK_SH); err != nil {
		_ = ns.Close()
		return nil, fmt.Errorf("netcfg: lock %s: %w", name, err)
	}
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		_ = ns.Close()
		return nil, fmt.Errorf("netcfg: netlink in %s: %w", name, err)
	}
	return &linuxConfigurator{
		h:        h,
		ns:       ns,
		takeover: alone,
		links:    make(map[string]linkChange),
		addrs:    make(map[addrKey]int),
		routes:   make(map[routeKey]ownedRoute),
	}, nil
}

type linuxConfigurator struct {
	mu       sync.Mutex
	h        *netlink.Handle
	ns       netns.NsHandle // holds the namespace lock
	takeover bool           // until the first successful Apply
	closed   bool

	links  map[string]linkChange // interfaces whose MTU or state we changed
	addrs  map[addrKey]int       // owned addresses → ifindex they were added to
	routes map[routeKey]ownedRoute
}

type linkChange struct {
	index   int
	origMTU int // before our first change
	mtu     int // what we set; 0: MTU untouched
	setUp   bool
}

type addrKey struct {
	link   string
	prefix netip.Prefix
}

// routeKey is a main-table route's identity in the kernel: two routes with
// the same key can't coexist.
type routeKey struct {
	metric int
	dst    netip.Prefix
}

type ownedRoute struct {
	spec Route
	nl   netlink.Route // as sent to the kernel
}

func keyOf(r Route) routeKey { return routeKey{metric: kernelMetric(r), dst: r.Dst} }

func kernelMetric(r Route) int {
	if r.Metric == 0 && r.Family() == IPv6 {
		return ipv6DefaultMetric
	}
	return r.Metric
}

// undoLog collects the inverse of every change Apply makes, so a failed
// Apply can put everything back. A nil log records nothing (Close).
type undoLog []func() error

func (u *undoLog) push(f func() error) {
	if u != nil {
		*u = append(*u, f)
	}
}

func (u undoLog) run() error {
	var errs []error
	for i := len(u) - 1; i >= 0; i-- {
		if err := u[i](); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *linuxConfigurator) Apply(ctx context.Context, cfg Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	keys := make(map[routeKey]Route, len(cfg.Routes))
	for _, r := range cfg.Routes {
		if prev, dup := keys[keyOf(r)]; dup {
			return fmt.Errorf("netcfg: routes %v and %v are the same route in the kernel", prev, r)
		}
		keys[keyOf(r)] = r
	}
	var undo undoLog
	if err := c.apply(ctx, cfg, &undo); err != nil {
		if uerr := undo.run(); uerr != nil {
			return fmt.Errorf("%w; undoing it also failed: %w", err, uerr)
		}
		return err
	}
	c.takeover = false
	return nil
}

func (c *linuxConfigurator) apply(ctx context.Context, cfg Config, u *undoLog) error {
	kroutes, err := c.ownKernelRoutes()
	if err != nil {
		return err
	}
	kaddrs, err := c.kernelAddrs()
	if err != nil {
		return err
	}
	links := make(map[string]netlink.Link)
	link := func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		l, err := c.h.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("netcfg: interface %s: %w", name, err)
		}
		links[name] = l
		return l, nil
	}

	wantLinks := make(map[string]bool)
	wantAddrs := make(map[addrKey]bool)
	for _, ifc := range cfg.Interfaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		l, err := link(ifc.Name)
		if err != nil {
			return err
		}
		idx := l.Attrs().Index
		wantLinks[ifc.Name] = true
		if err := c.configureLink(l, ifc, u); err != nil {
			return err
		}
		for _, p := range ifc.Addrs {
			k := addrKey{ifc.Name, p}
			wantAddrs[k] = true
			present, other := findAddr(kaddrs[idx], p)
			if other.IsValid() {
				return fmt.Errorf("%w: address %v on %s: it is there as %v", ErrConflict, p, ifc.Name, other)
			}
			owned := c.ownsAddr(k, idx)
			switch {
			case present && owned:
			case present: // someone else's: used, not owned
				if _, recorded := c.addrs[k]; recorded {
					c.dropAddrRecord(k, u)
				}
			default:
				if err := c.addAddr(k, idx, u); err != nil {
					return err
				}
			}
		}
	}

	wantRoutes := make(map[routeKey]bool)
	for _, r := range cfg.Routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		idx := 0
		if r.Interface != "" {
			l, err := link(r.Interface)
			if err != nil {
				return fmt.Errorf("netcfg: route %v: %w", r, err)
			}
			idx = l.Attrs().Index
		}
		k := keyOf(r)
		wantRoutes[k] = true
		nr := toNetlinkRoute(r, idx)
		kr, inKernel := kroutes[k]
		cur, owned := c.routes[k]
		if inKernel && !owned && !c.takeover {
			return fmt.Errorf("%w: route %v: another live configurator in this namespace has it", ErrConflict, r)
		}
		if inKernel && sameRoute(kr, nr) {
			if !owned || cur.spec != r {
				c.setRouteRecord(k, ownedRoute{spec: r, nl: nr}, u)
			}
			continue
		}
		if inKernel {
			if err := c.delKernelRoute(k, kr, u); err != nil {
				return err
			}
		}
		if err := c.addKernelRoute(k, r, nr, u); err != nil {
			return err
		}
	}

	for k := range c.routes {
		if wantRoutes[k] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if kr, ok := kroutes[k]; ok {
			if err := c.delKernelRoute(k, kr, u); err != nil {
				return err
			}
		}
		c.dropRouteRecord(k, u)
	}
	for k, idx := range c.addrs {
		if wantAddrs[k] {
			continue
		}
		if present, _ := findAddr(kaddrs[idx], k.prefix); present {
			if err := c.delKernelAddr(k, idx, u); err != nil {
				return err
			}
		}
		c.dropAddrRecord(k, u)
	}
	for name := range c.links {
		if !wantLinks[name] {
			if err := c.restoreLink(name, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// configureLink sets the MTU and brings the link up as asked. Zero values
// leave the link alone; what was changed is restored when the interface
// leaves the config or on Close.
func (c *linuxConfigurator) configureLink(l netlink.Link, ifc Interface, u *undoLog) error {
	attrs := l.Attrs()
	name := ifc.Name
	if ch, ok := c.links[name]; ok && ch.index != attrs.Index {
		c.dropLinkRecord(name, u) // a recreated interface: earlier changes went with the old one
	}
	if ifc.MTU != 0 && attrs.MTU != ifc.MTU {
		old := attrs.MTU
		if err := c.h.LinkSetMTU(l, ifc.MTU); err != nil {
			return fmt.Errorf("netcfg: MTU %d on %s: %w", ifc.MTU, name, err)
		}
		c.updateLinkRecord(name, attrs.Index, func(ch *linkChange) {
			if ch.mtu == 0 {
				ch.origMTU = old
			}
			ch.mtu = ifc.MTU
		}, u, func() error { return c.h.LinkSetMTU(l, old) })
	}
	if ifc.Up && attrs.Flags&net.FlagUp == 0 {
		if err := c.h.LinkSetUp(l); err != nil {
			return fmt.Errorf("netcfg: bring %s up: %w", name, err)
		}
		c.updateLinkRecord(name, attrs.Index, func(ch *linkChange) { ch.setUp = true },
			u, func() error { return c.h.LinkSetDown(l) })
	}
	return nil
}

// restoreLink undoes our MTU and state changes on an interface, each only if
// it still is what we set.
func (c *linuxConfigurator) restoreLink(name string, u *undoLog) error {
	ch := c.links[name]
	l, err := c.h.LinkByIndex(ch.index)
	if gone(err) || (err == nil && l.Attrs().Name != name) {
		c.dropLinkRecord(name, u)
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: interface %s: %w", name, err)
	}
	attrs := l.Attrs()
	if ch.mtu != 0 && attrs.MTU == ch.mtu && ch.origMTU != ch.mtu {
		if err := c.h.LinkSetMTU(l, ch.origMTU); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: restore MTU of %s: %w", name, err)
		}
		c.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.mtu, ch.origMTU = 0, 0 },
			u, func() error { return c.h.LinkSetMTU(l, attrs.MTU) })
	}
	if ch.setUp && attrs.Flags&net.FlagUp != 0 {
		if err := c.h.LinkSetDown(l); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: bring %s down: %w", name, err)
		}
		c.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.setUp = false },
			u, func() error { return c.h.LinkSetUp(l) })
	}
	c.dropLinkRecord(name, u)
	return nil
}

// updateLinkRecord records a change made to a link. Its undo reverts the
// change and only then the record, so a failed revert keeps the record.
func (c *linuxConfigurator) updateLinkRecord(name string, index int, change func(*linkChange), u *undoLog, revert func() error) {
	prev, had := c.links[name]
	ch := prev
	if !had {
		ch = linkChange{index: index}
	}
	change(&ch)
	c.links[name] = ch
	u.push(func() error {
		if err := revert(); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: undo a change to %s: %w", name, err)
		}
		c.restoreLinkRecord(name, prev, had)
		return nil
	})
}

func (c *linuxConfigurator) dropLinkRecord(name string, u *undoLog) {
	prev, had := c.links[name]
	delete(c.links, name)
	u.push(func() error { c.restoreLinkRecord(name, prev, had); return nil })
}

func (c *linuxConfigurator) restoreLinkRecord(name string, ch linkChange, had bool) {
	if had {
		c.links[name] = ch
	} else {
		delete(c.links, name)
	}
}

func (c *linuxConfigurator) ownsAddr(k addrKey, index int) bool {
	idx, ok := c.addrs[k]
	return ok && idx == index
}

func (c *linuxConfigurator) addAddr(k addrKey, index int, u *undoLog) error {
	if err := c.h.AddrAdd(linkAt(index), toNetlinkAddr(k.prefix)); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: address %v on %s: %w", ErrConflict, k.prefix, k.link, err)
		}
		return fmt.Errorf("netcfg: add %v to %s: %w", k.prefix, k.link, err)
	}
	prev, had := c.addrs[k]
	c.addrs[k] = index
	u.push(func() error {
		if err := c.delAddrOrGone(k, index); err != nil {
			return err // still there: keep owning it
		}
		c.restoreAddrRecord(k, prev, had)
		return nil
	})
	return nil
}

// delKernelAddr deletes an address that is there; its undo adds it back.
func (c *linuxConfigurator) delKernelAddr(k addrKey, index int, u *undoLog) error {
	err := c.h.AddrDel(linkAt(index), toNetlinkAddr(k.prefix))
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
	}
	u.push(func() error { return c.h.AddrAdd(linkAt(index), toNetlinkAddr(k.prefix)) })
	return nil
}

func (c *linuxConfigurator) delAddrOrGone(k addrKey, index int) error {
	if err := c.h.AddrDel(linkAt(index), toNetlinkAddr(k.prefix)); err != nil && !gone(err) {
		return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
	}
	return nil
}

func (c *linuxConfigurator) dropAddrRecord(k addrKey, u *undoLog) {
	prev, had := c.addrs[k]
	delete(c.addrs, k)
	u.push(func() error { c.restoreAddrRecord(k, prev, had); return nil })
}

func (c *linuxConfigurator) restoreAddrRecord(k addrKey, index int, had bool) {
	if had {
		c.addrs[k] = index
	} else {
		delete(c.addrs, k)
	}
}

// addKernelRoute adds a route with EXCL (an existing route with the same
// identity is someone else's: ours were in the dump) and owns it.
func (c *linuxConfigurator) addKernelRoute(k routeKey, r Route, nr netlink.Route, u *undoLog) error {
	if err := c.h.RouteAdd(&nr); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: route %v: another route has the same destination and metric", ErrConflict, r)
		}
		return fmt.Errorf("netcfg: add route %v: %w", r, err)
	}
	prev, had := c.routes[k]
	c.routes[k] = ownedRoute{spec: r, nl: nr}
	u.push(func() error {
		if err := c.h.RouteDel(&nr); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove route %v: %w", r, err) // still there: keep owning it
		}
		c.restoreRouteRecord(k, prev, had)
		return nil
	})
	return nil
}

// delKernelRoute deletes exactly the kernel's entry kr (scope, metric,
// nexthop, protocol), so no other route can match; its undo adds it back.
func (c *linuxConfigurator) delKernelRoute(k routeKey, kr netlink.Route, u *undoLog) error {
	del := exactRoute(k, kr)
	err := c.h.RouteDel(&del)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove route %v: %w", del.Dst, err)
	}
	u.push(func() error { return c.h.RouteAdd(&del) })
	return nil
}

func (c *linuxConfigurator) setRouteRecord(k routeKey, o ownedRoute, u *undoLog) {
	prev, had := c.routes[k]
	c.routes[k] = o
	u.push(func() error { c.restoreRouteRecord(k, prev, had); return nil })
}

func (c *linuxConfigurator) dropRouteRecord(k routeKey, u *undoLog) {
	prev, had := c.routes[k]
	delete(c.routes, k)
	u.push(func() error { c.restoreRouteRecord(k, prev, had); return nil })
}

func (c *linuxConfigurator) restoreRouteRecord(k routeKey, o ownedRoute, had bool) {
	if had {
		c.routes[k] = o
	} else {
		delete(c.routes, k)
	}
}

// ownKernelRoutes dumps the main table's proto-84 routes once per Apply or
// Close: every decision is made against it, so a reconcile is O(routes).
func (c *linuxConfigurator) ownKernelRoutes() (map[routeKey]netlink.Route, error) {
	out := make(map[routeKey]netlink.Route)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := c.listRoutes(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN, Protocol: RouteProtocol},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			out[routeKey{metric: r.Priority, dst: dstOf(r, fam)}] = r
		}
	}
	return out, nil
}

// kernelAddrs returns every address in the namespace by interface index.
func (c *linuxConfigurator) kernelAddrs() (map[int][]netip.Prefix, error) {
	var err error
	for range 5 {
		var addrs []netlink.Addr
		addrs, err = c.h.AddrList(nil, netlink.FAMILY_ALL)
		if errors.Is(err, netlink.ErrDumpInterrupted) {
			continue
		}
		if err != nil {
			break
		}
		out := make(map[int][]netip.Prefix)
		for _, a := range addrs {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			if ip.Is4In6() {
				ip = ip.Unmap()
			}
			ones, _ := a.Mask.Size()
			out[a.LinkIndex] = append(out[a.LinkIndex], netip.PrefixFrom(ip, ones))
		}
		return out, nil
	}
	return nil, fmt.Errorf("netcfg: list addresses: %w", err)
}

func (c *linuxConfigurator) DefaultRoute(ctx context.Context, f Family) (Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Route{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	fam := netlink.FAMILY_V4
	if f == IPv6 {
		fam = netlink.FAMILY_V6
	}
	routes, err := c.listRoutes(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return Route{}, err
	}
	const unusable = unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
	var best *netlink.Route
	var gw net.IP
	var index int
	for i, r := range routes {
		if r.Protocol == RouteProtocol || r.Type != unix.RTN_UNICAST || dstOf(r, fam).Bits() != 0 || r.Flags&unusable != 0 {
			continue
		}
		g, idx, ok := r.Gw, r.LinkIndex, true
		if len(r.MultiPath) > 0 {
			ok = false
			for _, nh := range r.MultiPath {
				if nh.Flags&unusable == 0 {
					g, idx, ok = nh.Gw, nh.LinkIndex, true
					break
				}
			}
		}
		if ok && (best == nil || r.Priority < best.Priority) {
			best, gw, index = &routes[i], g, idx
		}
	}
	if best == nil {
		return Route{}, fmt.Errorf("%w (%v)", ErrNoDefaultRoute, f)
	}
	out := Route{Dst: dstOf(*best, fam), Metric: best.Priority}
	if a, ok := netip.AddrFromSlice(gw); ok {
		if f == IPv4 {
			a = a.Unmap()
		}
		out.Gateway = a
	}
	if index != 0 {
		l, err := c.h.LinkByIndex(index)
		if err != nil {
			return Route{}, fmt.Errorf("netcfg: interface of the default route: %w", err)
		}
		out.Interface = l.Attrs().Name
	}
	if !out.Gateway.IsValid() && out.Interface == "" {
		return Route{}, fmt.Errorf("netcfg: the %v default route has neither a gateway nor an interface (a nexthop object?)", f)
	}
	return out, nil
}

func (c *linuxConfigurator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h == nil {
		return nil
	}
	c.closed = true
	kroutes, err := c.ownKernelRoutes()
	if err != nil {
		return err
	}
	kaddrs, err := c.kernelAddrs()
	if err != nil {
		return err
	}
	var errs []error
	for k := range c.routes {
		if kr, ok := kroutes[k]; ok {
			if err := c.delKernelRoute(k, kr, nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(c.routes, k)
	}
	for k, idx := range c.addrs {
		if present, _ := findAddr(kaddrs[idx], k.prefix); present {
			if err := c.delKernelAddr(k, idx, nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(c.addrs, k)
	}
	for name := range c.links {
		if err := c.restoreLink(name, nil); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...) // what's left stays recorded: Close again retries it
	}
	c.h.Close()
	c.h = nil
	return c.ns.Close() // releases the namespace lock
}

// listRoutes retries dumps the kernel interrupted because the table changed
// underneath them.
func (c *linuxConfigurator) listRoutes(fam int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	var err error
	for range 5 {
		var routes []netlink.Route
		routes, err = c.h.RouteListFiltered(fam, filter, mask)
		if err == nil {
			return routes, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	return nil, fmt.Errorf("netcfg: list routes: %w", err)
}

// gone reports errors meaning the thing to remove or restore no longer
// exists, which for cleanup is success.
func gone(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) ||
		errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL)
}

func linkAt(index int) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: index}}
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func toNetlinkAddr(p netip.Prefix) *netlink.Addr {
	a := &netlink.Addr{IPNet: ipNet(p)}
	if p.Addr().Is6() {
		// Usable at once: no duplicate address detection on an overlay.
		a.Flags = unix.IFA_F_NODAD
	}
	return a
}

func toNetlinkRoute(r Route, linkIndex int) netlink.Route {
	nr := netlink.Route{
		Dst:       ipNet(r.Dst),
		LinkIndex: linkIndex,
		Table:     unix.RT_TABLE_MAIN,
		Priority:  kernelMetric(r),
		Protocol:  RouteProtocol,
	}
	if r.Gateway.IsValid() {
		nr.Gw = r.Gateway.AsSlice()
	} else if r.Family() == IPv4 {
		nr.Scope = netlink.SCOPE_LINK
	}
	return nr
}

// exactRoute is the part of a dumped route that identifies it in a delete.
// netlink sends the route's own scope (not "any"), so it must be the
// kernel's.
func exactRoute(k routeKey, kr netlink.Route) netlink.Route {
	return netlink.Route{
		Dst:       ipNet(k.dst),
		Gw:        kr.Gw,
		LinkIndex: kr.LinkIndex,
		Scope:     kr.Scope,
		Table:     unix.RT_TABLE_MAIN,
		Priority:  kr.Priority,
		Protocol:  kr.Protocol,
	}
}

// sameRoute reports whether the kernel's route kr is what nr asks for.
func sameRoute(kr, nr netlink.Route) bool {
	return len(kr.MultiPath) == 0 && kr.Gw.Equal(nr.Gw) && kr.Scope == nr.Scope &&
		(nr.LinkIndex == 0 || kr.LinkIndex == nr.LinkIndex) && kr.Type == unix.RTN_UNICAST
}

// findAddr reports whether p is in addrs, or else the same address with
// another prefix length (a conflict: the kernel holds one per address).
func findAddr(addrs []netip.Prefix, p netip.Prefix) (present bool, other netip.Prefix) {
	for _, a := range addrs {
		if a == p {
			return true, netip.Prefix{}
		}
		if a.Addr() == p.Addr() {
			other = a
		}
	}
	return false, other
}

// dstOf returns a kernel route's destination; the kernel may leave it out
// for default routes.
func dstOf(r netlink.Route, fam int) netip.Prefix {
	if r.Dst == nil {
		if fam == netlink.FAMILY_V6 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	a, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		return netip.Prefix{}
	}
	if fam == netlink.FAMILY_V4 {
		a = a.Unmap()
	}
	ones, _ := r.Dst.Mask.Size()
	return netip.PrefixFrom(a, ones)
}
