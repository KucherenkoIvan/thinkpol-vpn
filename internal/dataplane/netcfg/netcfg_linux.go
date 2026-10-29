//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// RouteProtocol returns the rtnetlink protocol number on every route the
// owner's configurators add (`ip route show proto 84`): 84 overlay, 85
// supervisor, 86 route-table, all unassigned in iproute2's rt_protos. It is
// how routes are told apart from everyone else's, also after a crash.
func (o Owner) RouteProtocol() netlink.RouteProtocol { return netlink.RouteProtocol(83 + int(o)) }

func (o Owner) valid() bool { return o >= OwnerOverlay && o <= OwnerRouteTable }

// isOwnerProtocol reports whether p is any owner's route protocol.
func isOwnerProtocol(p netlink.RouteProtocol) bool {
	_, ok := ownerOf(p)
	return ok
}

// LockDir holds the lock files that keep one configurator per owner and
// namespace; they are empty and outlive their configurators harmlessly.
const LockDir = "/run/thinkpol/netcfg"

// The kernel stores IPv6 routes added with metric 0 under this metric.
const ipv6DefaultMetric = 1024

// New returns a configurator for owner in the network namespace of the
// calling thread.
func New(owner Owner) (Configurator, error) {
	// The namespace handle and the netlink socket must come from one
	// thread's namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := currentNamespace()
	if err != nil {
		return nil, fmt.Errorf("netcfg: current namespace: %w", err)
	}
	return newLinux(ns, "the current namespace", true, owner)
}

// currentNamespace opens the calling (locked) thread's network namespace. Without
// /proc (a sandboxed server worker has none) it asks a socket of this
// thread for its namespace (SIOCGSKNS, which needs CAP_NET_ADMIN there).
func currentNamespace() (netns.NsHandle, error) {
	ns, err := netns.Get()
	if err == nil {
		return ns, nil
	}
	sock, serr := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if serr != nil {
		return netns.None(), errors.Join(err, serr)
	}
	defer func() { _ = unix.Close(sock) }()
	fd, ierr := unix.IoctlRetInt(sock, unix.SIOCGSKNS)
	if ierr != nil {
		return netns.None(), errors.Join(err, fmt.Errorf("SIOCGSKNS: %w", ierr))
	}
	unix.CloseOnExec(fd)
	return netns.NsHandle(fd), nil
}

// NewInNamespace returns a configurator for owner in the network namespace
// at path (e.g. /run/netns/<name> or /proc/<pid>/ns/net), without the
// caller entering it.
func NewInNamespace(path string, owner Owner) (Configurator, error) {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("netcfg: namespace %s: %w", path, err)
	}
	return newLinux(ns, path, false, owner)
}

// newLinux makes owner's configurator for ns; current says ns is the calling
// thread's, where the netlink sockets are opened without switching
// namespaces (netlink's switch needs /proc to find its way back). The
// sockets stay in ns whatever thread uses them later.
func newLinux(ns netns.NsHandle, name string, current bool, owner Owner) (Configurator, error) {
	defer func() { _ = ns.Close() }()
	if !owner.valid() {
		return nil, fmt.Errorf("netcfg: unknown owner %v", owner)
	}
	// Watch subscribes in the namespace later, from any thread.
	watchNS, err := unix.FcntlInt(uintptr(ns), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("netcfg: namespace of %s: %w", name, err)
	}
	lock, err := lockOwner(ns, owner)
	if err != nil {
		_ = unix.Close(watchNS)
		return nil, fmt.Errorf("netcfg: %v in %s: %w", owner, name, err)
	}
	at := ns
	if current {
		at = netns.None()
	}
	h, err := netlink.NewHandleAt(at, unix.NETLINK_ROUTE)
	if err != nil {
		_ = unix.Close(lock)
		_ = unix.Close(watchNS)
		return nil, fmt.Errorf("netcfg: netlink in %s: %w", name, err)
	}
	rules, err := newRuleSocket(at)
	if err != nil {
		h.Close()
		_ = unix.Close(lock)
		_ = unix.Close(watchNS)
		return nil, fmt.Errorf("netcfg: rule socket in %s: %w", name, err)
	}
	return &linuxConfigurator{
		h:         h,
		rules:     rules,
		ns:        netns.NsHandle(watchNS),
		lock:      lock,
		proto:     owner.RouteProtocol(),
		closeDump: dumpRulesOnce,
		links:     newLedger(),
	}, nil
}

// lockOwner takes the exclusive flock for (namespace, owner), held until
// the configurator closes or its process dies. Namespaces are told apart by
// their nsfs inode, the same for every path to one namespace.
func lockOwner(ns netns.NsHandle, owner Owner) (int, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(ns), &st); err != nil {
		return -1, err
	}
	if err := os.MkdirAll(LockDir, 0o700); err != nil {
		return -1, err
	}
	path := filepath.Join(LockDir, fmt.Sprintf("%d-%d.%s.lock", st.Dev, st.Ino, owner))
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return -1, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return -1, ErrBusy
		}
		return -1, err
	}
	return fd, nil
}

type linuxConfigurator struct {
	mu sync.Mutex
	h  *netlink.Handle
	// rules is the socket for rule dumps and requests (rawrule_linux.go),
	// opened in the namespace with h; mu serialises its use.
	rules  *nl.SocketHandle
	ns     netns.NsHandle // the namespace, for Watch
	lock   int            // the owner's lock file, flocked
	proto  netlink.RouteProtocol
	closed bool
	// protoKept: a check of added rules (judgeAdded) has seen them come
	// back with proto, so this kernel keeps rule protocols.
	protoKept bool
	// closeDump is the rule dump Close's rules step takes, dumpRulesOnce;
	// a field so a test can make that step fail.
	closeDump func(*nl.SocketHandle, int) ([]rawRule, error)

	// Every route with proto is ours, so routes need no records.
	links ledger
}

// routeKey is a route's identity in the kernel: two routes with the same
// key can't coexist.
type routeKey struct {
	table  int
	metric int
	dst    netip.Prefix
}

func keyOf(r Route) routeKey {
	return routeKey{table: kernelTable(r.Table), metric: kernelMetric(r), dst: r.Dst}
}

// kernelTable is the kernel's number for a Route's or Rule's table.
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
		if r.Scope != "" {
			return fmt.Errorf("netcfg: route %v: scoped routes on linux: %w", r, errors.ErrUnsupported)
		}
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
	return nil
}

func (c *linuxConfigurator) apply(ctx context.Context, cfg Config, u *undoLog) error {
	kroutes, err := c.ownKernelRoutes()
	if err != nil {
		return err
	}
	krules, err := c.ownKernelRules()
	if err != nil {
		return err
	}
	ops, err := c.newNetlinkOps()
	if err != nil {
		return err
	}
	want, err := c.links.configure(ctx, ops, cfg.Interfaces, u)
	if err != nil {
		return err
	}
	if err := c.reconcileRoutes(ctx, ops, cfg.Routes, kroutes, u); err != nil {
		return err
	}
	// Rules go in after the routes they lead to, and leave before.
	if err := c.reconcileRules(ctx, cfg.Rules, krules, u); err != nil {
		return err
	}
	return c.links.release(ops, want, u)
}

// reconcileRoutes adds or changes the routes cfg wants and removes the
// owner's routes it doesn't.
func (c *linuxConfigurator) reconcileRoutes(ctx context.Context, ops *netlinkOps, routes []Route, kroutes map[routeKey]netlink.Route, u *undoLog) error {
	wantRoutes := make(map[routeKey]bool)
	for _, r := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		idx := 0
		if r.Interface != "" {
			l, err := ops.link(r.Interface)
			if err != nil {
				return fmt.Errorf("netcfg: route %v: %w", r, err)
			}
			idx = l.Attrs().Index
		}
		k := keyOf(r)
		wantRoutes[k] = true
		nr := c.toNetlinkRoute(r, idx)
		if kr, ours := kroutes[k]; ours {
			if sameRoute(kr, nr) {
				continue
			}
			if err := c.delKernelRoute(k, kr, u); err != nil {
				return err
			}
		}
		if err := c.addKernelRoute(r, nr, u); err != nil {
			return err
		}
	}
	// Ours but not wanted: dropped from the config, or a dead
	// predecessor's leftovers.
	for k, kr := range kroutes {
		if wantRoutes[k] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.delKernelRoute(k, kr, u); err != nil {
			return err
		}
	}
	return nil
}

// newNetlinkOps returns the ledger's linkOps for one Apply or Close: c's
// netlink handle and the namespace's addresses, dumped once here, so every
// decision is made against that dump.
func (c *linuxConfigurator) newNetlinkOps() (*netlinkOps, error) {
	kaddrs, err := c.kernelAddrs()
	if err != nil {
		return nil, err
	}
	return &netlinkOps{h: c.h, kaddrs: kaddrs, byName: make(map[string]netlink.Link)}, nil
}

// netlinkOps is linkOps over netlink for one Apply or Close.
type netlinkOps struct {
	h      *netlink.Handle
	kaddrs map[int][]netip.Prefix // the namespace's addresses by interface index
	byName map[string]netlink.Link
}

// link looks an interface up by name once per Apply.
func (o *netlinkOps) link(name string) (netlink.Link, error) {
	if l, ok := o.byName[name]; ok {
		return l, nil
	}
	l, err := o.h.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("netcfg: interface %s: %w", name, err)
	}
	o.byName[name] = l
	return l, nil
}

func stateOf(l netlink.Link) linkState {
	a := l.Attrs()
	return linkState{name: a.Name, index: a.Index, mtu: a.MTU, up: a.Flags&net.FlagUp != 0}
}

func (o *netlinkOps) linkByName(name string) (linkState, error) {
	l, err := o.link(name)
	if err != nil {
		return linkState{}, err
	}
	return stateOf(l), nil
}

func (o *netlinkOps) linkByIndex(index int) (linkState, error) {
	l, err := o.h.LinkByIndex(index)
	if err != nil {
		return linkState{}, err
	}
	return stateOf(l), nil
}

func (o *netlinkOps) setMTU(l linkState, mtu int) error {
	return o.h.LinkSetMTU(linkAt(l.index), mtu)
}

func (o *netlinkOps) setUp(l linkState, up bool) error {
	if up {
		return o.h.LinkSetUp(linkAt(l.index))
	}
	return o.h.LinkSetDown(linkAt(l.index))
}

func (o *netlinkOps) addrs(index int) ([]netip.Prefix, error) { return o.kaddrs[index], nil }

func (o *netlinkOps) addAddr(index int, p netip.Prefix) error {
	return o.h.AddrAdd(linkAt(index), toNetlinkAddr(p))
}

func (o *netlinkOps) delAddr(index int, p netip.Prefix) error {
	return o.h.AddrDel(linkAt(index), toNetlinkAddr(p))
}

// addKernelRoute adds a route with EXCL: an existing route with the same
// identity is someone else's (ours were in the dump), so that's a conflict.
func (c *linuxConfigurator) addKernelRoute(r Route, nr netlink.Route, u *undoLog) error {
	if err := c.h.RouteAdd(&nr); err != nil {
		if exists(err) {
			return fmt.Errorf("%w: route %v: another owner's or a foreign route has the same destination and metric", ErrConflict, r)
		}
		return fmt.Errorf("netcfg: add route %v: %w", r, err)
	}
	u.push(func() error {
		if err := c.h.RouteDel(&nr); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove route %v: %w", r, err)
		}
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

// ownKernelRoutes dumps every table's routes with our protocol once per
// Apply or Close: every decision is made against it, so a reconcile is
// O(routes).
func (c *linuxConfigurator) ownKernelRoutes() (map[routeKey]netlink.Route, error) {
	out := make(map[routeKey]netlink.Route)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := listRoutes(c.h, fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC, Protocol: c.proto},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			out[routeKey{table: r.Table, metric: r.Priority, dst: dstOf(r, fam)}] = r
		}
	}
	return out, nil
}

// kernelAddrs returns every address in the namespace by interface index.
func (c *linuxConfigurator) kernelAddrs() (map[int][]netip.Prefix, error) {
	var err error
	for range dumpRetries {
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
	routes, err := listRoutes(c.h, fam, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return Route{}, err
	}
	const unusable = unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
	var best *netlink.Route
	var gw net.IP
	var index int
	for i, r := range routes {
		if isOwnerProtocol(r.Protocol) || r.Type != unix.RTN_UNICAST || dstOf(r, fam).Bits() != 0 || r.Flags&unusable != 0 {
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
	err := c.removeOwned()
	// Whatever happens, the owner's place is freed: what is left carries
	// the owner's protocol (and the ledger forgets it), so the next
	// configurator of the owner takes it over, as after a crash.
	c.h.Close()
	c.h = nil
	c.rules.Close()
	_ = c.ns.Close()
	if lerr := unix.Close(c.lock); err == nil {
		err = lerr
	}
	return err
}

// removeOwned removes every rule, route and address of the owner and
// restores every interface it changed, going on past failures to remove
// one. Rules never hold up the rest: they go by removeOwnRules, whose
// failure (someone's rule churn can't cause it) is returned with the
// others'. A failure to list the routes or the links leaves everything to
// the owner's next configurator, as after a crash.
func (c *linuxConfigurator) removeOwned() error {
	kroutes, err := c.ownKernelRoutes()
	if err != nil {
		return err
	}
	ops, err := c.newNetlinkOps()
	if err != nil {
		return err
	}
	var errs []error
	// Rules leave before the routes they lead to.
	dumpOwn := func() ([]rawRule, error) { return c.own(dumpFamilies(c.rules, c.closeDump)) }
	if err := removeOwnRules(dumpOwn, func(kr rawRule) error { return c.delKernelRule(kr, nil) }); err != nil {
		errs = append(errs, err)
	}
	for k, kr := range kroutes {
		if err := c.delKernelRoute(k, kr, nil); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, c.links.closeAll(ops)...)
	return errors.Join(errs...)
}

// dumpRetries is how many times a dump the kernel interrupted (what it
// lists changed underneath it) is taken before it fails, how many rule
// dumps dumpRules takes at most to find two in a row that agree, and how
// many rounds of deletes removeOwnRules makes room for.
const dumpRetries = 5

// listRoutes lists routes through h, retrying dumps the kernel
// interrupted.
func listRoutes(h *netlink.Handle, fam int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	var err error
	for range dumpRetries {
		var routes []netlink.Route
		routes, err = h.RouteListFiltered(fam, filter, mask)
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
// exists, which for cleanup is success. ENXIO is an IPv6 address on an
// interface the kernel has turned IPv6 off on (an MTU below 1280 does that,
// taking the addresses along).
func gone(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) ||
		errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL) ||
		errors.Is(err, unix.ENXIO)
}

// exists reports an add's error meaning what it adds is there already.
func exists(err error) bool { return errors.Is(err, unix.EEXIST) }

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

func (c *linuxConfigurator) toNetlinkRoute(r Route, linkIndex int) netlink.Route {
	nr := netlink.Route{
		Dst:       ipNet(r.Dst),
		LinkIndex: linkIndex,
		Table:     kernelTable(r.Table),
		Priority:  kernelMetric(r),
		Protocol:  c.proto,
		Type:      unix.RTN_UNICAST,
	}
	switch r.Type {
	case RouteThrow:
		nr.Type = unix.RTN_THROW
	case RouteUnreachable:
		nr.Type = unix.RTN_UNREACHABLE
	}
	if nr.Type != unix.RTN_UNICAST {
		return nr
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
		Table:     k.table,
		Priority:  kr.Priority,
		Protocol:  kr.Protocol,
		Type:      kr.Type,
	}
}

// sameRoute reports whether the kernel's route kr is what nr asks for.
func sameRoute(kr, nr netlink.Route) bool {
	if kr.Type != nr.Type {
		return false
	}
	if nr.Type != unix.RTN_UNICAST {
		return true // a throw or unreachable route is its key and type
	}
	return len(kr.MultiPath) == 0 && kr.Gw.Equal(nr.Gw) && kr.Scope == nr.Scope &&
		(nr.LinkIndex == 0 || kr.LinkIndex == nr.LinkIndex) && kr.Type == unix.RTN_UNICAST
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
