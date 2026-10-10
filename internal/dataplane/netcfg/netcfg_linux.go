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
// (`ip route show proto 84`); unassigned in iproute2's rt_protos. Deletes
// carry it too, so the kernel itself never deletes a route that isn't ours.
const RouteProtocol netlink.RouteProtocol = 84

// The kernel stores IPv6 routes added with metric 0 under this metric.
const ipv6DefaultMetric = 1024

// New returns a configurator for the network namespace of the calling
// process.
func New() (Configurator, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netcfg: netlink: %w", err)
	}
	return newLinux(h), nil
}

// NewInNamespace returns a configurator for the network namespace at path
// (e.g. /run/netns/<name> or /proc/<pid>/ns/net), without the caller
// entering it.
func NewInNamespace(path string) (Configurator, error) {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("netcfg: namespace %s: %w", path, err)
	}
	defer func() { _ = ns.Close() }()
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netcfg: netlink in %s: %w", path, err)
	}
	return newLinux(h), nil
}

func newLinux(h *netlink.Handle) *linuxConfigurator {
	return &linuxConfigurator{
		h:      h,
		links:  make(map[string]*linkChange),
		addrs:  make(map[addrKey]int),
		routes: make(map[routeKey]ownedRoute),
	}
}

type linuxConfigurator struct {
	mu     sync.Mutex
	h      *netlink.Handle
	closed bool

	links  map[string]*linkChange // interfaces whose MTU or state we changed
	addrs  map[addrKey]int        // owned addresses → ifindex they were added to
	routes map[routeKey]ownedRoute
}

type linkChange struct {
	index   int
	origMTU int  // 0: MTU untouched
	setUp   bool // we brought it up
}

type addrKey struct {
	link   string
	prefix netip.Prefix
}

// routeKey is a route's identity in the kernel: two routes with the same key
// can't coexist.
type routeKey struct {
	table, metric int
	dst           netip.Prefix
}

type ownedRoute struct {
	spec Route
	nl   netlink.Route
}

func keyOf(r Route) routeKey {
	return routeKey{table: kernelTable(r.Table), metric: kernelMetric(r), dst: r.Dst}
}

func kernelTable(t int) int {
	if t == 0 {
		return unix.RT_TABLE_MAIN
	}
	return t
}

func kernelMetric(r Route) int {
	if r.Metric == 0 && r.Family() == IPv6 {
		return ipv6DefaultMetric
	}
	return r.Metric
}

// undoLog collects the inverse of every change Apply makes, so a failed
// Apply can put everything back.
type undoLog []func() error

func (u *undoLog) push(f func() error) { *u = append(*u, f) }

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
	if err := cfg.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	var undo undoLog
	if err := c.apply(ctx, cfg, &undo); err != nil {
		if uerr := undo.run(); uerr != nil {
			return fmt.Errorf("%w; undoing it also failed: %w", err, uerr)
		}
		return err
	}
	return nil
}

func (c *linuxConfigurator) apply(ctx context.Context, cfg Config, u *undoLog) error {
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
		wantLinks[ifc.Name] = true
		if err := c.configureLink(l, ifc, u); err != nil {
			return err
		}
		existing, err := c.h.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("netcfg: addresses of %s: %w", ifc.Name, err)
		}
		for _, p := range ifc.Addrs {
			k := addrKey{ifc.Name, p}
			wantAddrs[k] = true
			if idx, owned := c.addrs[k]; owned && idx == l.Attrs().Index {
				continue
			}
			if hasAddr(existing, p) {
				continue // someone else's: used, not owned
			}
			if err := c.addAddr(k, l.Attrs().Index, u); err != nil {
				return err
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
		if cur, owned := c.routes[k]; owned {
			if cur.spec == r && cur.nl.LinkIndex == idx {
				continue
			}
			if err := c.delRoute(k, u); err != nil {
				return err
			}
		}
		if err := c.addRoute(k, r, nr, u); err != nil {
			return err
		}
	}

	for k := range c.routes {
		if !wantRoutes[k] {
			if err := c.delRoute(k, u); err != nil {
				return err
			}
		}
	}
	for k := range c.addrs {
		if !wantAddrs[k] {
			if err := c.delAddr(k, u); err != nil {
				return err
			}
		}
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
	prev, had := c.links[ifc.Name]
	ch := &linkChange{index: attrs.Index}
	if had && prev.index == attrs.Index {
		*ch = *prev
	} // else: a recreated interface; earlier changes went with the old one
	c.links[ifc.Name] = ch
	u.push(func() error {
		if had {
			c.links[ifc.Name] = prev
		} else {
			delete(c.links, ifc.Name)
		}
		return nil
	})

	if ifc.MTU != 0 && attrs.MTU != ifc.MTU {
		old := attrs.MTU
		if err := c.h.LinkSetMTU(l, ifc.MTU); err != nil {
			return fmt.Errorf("netcfg: MTU %d on %s: %w", ifc.MTU, ifc.Name, err)
		}
		if ch.origMTU == 0 {
			ch.origMTU = old
		}
		u.push(func() error { return c.h.LinkSetMTU(l, old) })
	}
	if ifc.Up && attrs.Flags&net.FlagUp == 0 {
		if err := c.h.LinkSetUp(l); err != nil {
			return fmt.Errorf("netcfg: bring %s up: %w", ifc.Name, err)
		}
		ch.setUp = true
		u.push(func() error { return c.h.LinkSetDown(l) })
	}
	if ch.origMTU == 0 && !ch.setUp {
		delete(c.links, ifc.Name)
	}
	return nil
}

// restoreLink undoes our MTU and state changes on an interface. Undo
// re-applies them.
func (c *linuxConfigurator) restoreLink(name string, u *undoLog) error {
	ch := c.links[name]
	l, err := c.h.LinkByIndex(ch.index)
	if gone(err) {
		delete(c.links, name)
		u.push(func() error { c.links[name] = ch; return nil })
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: interface %s: %w", name, err)
	}
	attrs := l.Attrs()
	if ch.origMTU != 0 && attrs.MTU != ch.origMTU {
		cur := attrs.MTU
		if err := c.h.LinkSetMTU(l, ch.origMTU); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: restore MTU of %s: %w", name, err)
		}
		u.push(func() error { return c.h.LinkSetMTU(l, cur) })
	}
	if ch.setUp && attrs.Flags&net.FlagUp != 0 {
		if err := c.h.LinkSetDown(l); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: bring %s down: %w", name, err)
		}
		u.push(func() error { return c.h.LinkSetUp(l) })
	}
	delete(c.links, name)
	u.push(func() error { c.links[name] = ch; return nil })
	return nil
}

func (c *linuxConfigurator) addAddr(k addrKey, index int, u *undoLog) error {
	if err := c.h.AddrAdd(linkAt(index), toNetlinkAddr(k.prefix)); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: address %v on %s: the address is there with another prefix length", ErrConflict, k.prefix, k.link)
		}
		return fmt.Errorf("netcfg: add %v to %s: %w", k.prefix, k.link, err)
	}
	c.addrs[k] = index
	u.push(func() error { return c.delAddr(k, nil) })
	return nil
}

func (c *linuxConfigurator) delAddr(k addrKey, u *undoLog) error {
	index := c.addrs[k]
	if err := c.h.AddrDel(linkAt(index), toNetlinkAddr(k.prefix)); err != nil && !gone(err) {
		return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
	}
	delete(c.addrs, k)
	if u != nil {
		u.push(func() error { return c.addAddr(k, index, nil) })
	}
	return nil
}

func (c *linuxConfigurator) addRoute(k routeKey, r Route, nr netlink.Route, u *undoLog) error {
	err := c.h.RouteAdd(&nr)
	if errors.Is(err, unix.EEXIST) {
		// Ours from an earlier run that didn't clean up (a crash) can be
		// taken over; anyone else's is left alone.
		var kr *netlink.Route
		kr, err = c.kernelRoute(k)
		if err == nil && (kr == nil || kr.Protocol != RouteProtocol) {
			return fmt.Errorf("%w: route %v: another route has the same destination and metric", ErrConflict, r)
		}
		if err == nil {
			// The delete must match the route's scope: netlink sends ours,
			// not "any".
			err = c.h.RouteDel(&netlink.Route{
				Dst: nr.Dst, Table: nr.Table, Priority: kr.Priority, Protocol: RouteProtocol,
				Scope: kr.Scope, LinkIndex: kr.LinkIndex, Gw: kr.Gw,
			})
		}
		if err == nil {
			err = c.h.RouteAdd(&nr)
		}
	}
	if err != nil {
		return fmt.Errorf("netcfg: add route %v: %w", r, err)
	}
	c.routes[k] = ownedRoute{spec: r, nl: nr}
	if u != nil {
		u.push(func() error { return c.delRoute(k, nil) })
	}
	return nil
}

func (c *linuxConfigurator) delRoute(k routeKey, u *undoLog) error {
	o := c.routes[k]
	if err := c.h.RouteDel(&o.nl); err != nil && !gone(err) {
		return fmt.Errorf("netcfg: remove route %v: %w", o.spec, err)
	}
	delete(c.routes, k)
	if u != nil {
		u.push(func() error { return c.addRoute(k, o.spec, o.nl, nil) })
	}
	return nil
}

// kernelRoute returns the kernel's route with key k, or nil.
func (c *linuxConfigurator) kernelRoute(k routeKey) (*netlink.Route, error) {
	fam := netlink.FAMILY_V4
	if FamilyOf(k.dst.Addr()) == IPv6 {
		fam = netlink.FAMILY_V6
	}
	routes, err := c.listRoutes(fam, &netlink.Route{Table: k.table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for i, r := range routes {
		if dstOf(r, fam) == k.dst && r.Priority == k.metric {
			return &routes[i], nil
		}
	}
	return nil, nil
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
	var best *netlink.Route
	for i, r := range routes {
		if r.Protocol == RouteProtocol || r.Type != unix.RTN_UNICAST || dstOf(r, fam).Bits() != 0 {
			continue
		}
		if best == nil || r.Priority < best.Priority {
			best = &routes[i]
		}
	}
	if best == nil {
		return Route{}, fmt.Errorf("%w (%v)", ErrNoDefaultRoute, f)
	}
	out := Route{Dst: dstOf(*best, fam), Metric: best.Priority}
	gw, index := best.Gw, best.LinkIndex
	if len(best.MultiPath) > 0 {
		gw, index = best.MultiPath[0].Gw, best.MultiPath[0].LinkIndex
	}
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
	return out, nil
}

func (c *linuxConfigurator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h == nil {
		return nil
	}
	c.closed = true
	var errs []error
	for k := range c.routes {
		if err := c.delRoute(k, nil); err != nil {
			errs = append(errs, err)
		}
	}
	for k := range c.addrs {
		if err := c.delAddr(k, nil); err != nil {
			errs = append(errs, err)
		}
	}
	for name := range c.links {
		if err := c.restoreLink(name, &undoLog{}); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...) // what's left stays recorded: Close again retries it
	}
	c.h.Close()
	c.h = nil
	return nil
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

func toNetlinkAddr(p netip.Prefix) *netlink.Addr {
	a := &netlink.Addr{IPNet: &net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}}
	if p.Addr().Is6() {
		// Usable at once: no duplicate address detection on an overlay.
		a.Flags = unix.IFA_F_NODAD
	}
	return a
}

func toNetlinkRoute(r Route, linkIndex int) netlink.Route {
	nr := netlink.Route{
		Dst: &net.IPNet{
			IP:   r.Dst.Addr().AsSlice(),
			Mask: net.CIDRMask(r.Dst.Bits(), r.Dst.Addr().BitLen()),
		},
		LinkIndex: linkIndex,
		Table:     kernelTable(r.Table),
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

func hasAddr(addrs []netlink.Addr, p netip.Prefix) bool {
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		if p.Addr().Is4() {
			ip = ip.Unmap()
		}
		ones, _ := a.Mask.Size()
		if ip == p.Addr() && ones == p.Bits() {
			return true
		}
	}
	return false
}

// dstOf returns a kernel route's destination; the kernel leaves it out for
// default routes.
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
