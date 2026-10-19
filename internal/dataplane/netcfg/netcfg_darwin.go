package netcfg

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// StateDir holds what thinkpol keeps on macOS outside the node's state
// directory: the agent's lock and LockDir. /private/var/db is root's alone
// all the way up (/var is a symlink to /private/var, which the walk would
// refuse), unlike /var/run, which is root:daemon 0775 and not sticky:
// there anyone of group daemon could rename a lock's directory away from
// under its holder, or swap it for a symlink.
const StateDir = "/private/var/db/thinkpol"

// LockDir holds, per owner, the lock that keeps one configurator per owner
// alive and the record of the routes it owns. Both outlive a reboot,
// which the routes don't: a record carries its boot session, and one of
// an earlier boot holds nothing.
const LockDir = StateDir + "/netcfg"

// routeFlag tags every route a thinkpol configurator adds. It alone isn't
// ownership: other software uses the protocol flags too (RTF_PROTO1 is
// common among VPN clients, RTF_PROTO3 is the kernel's mark on cloned
// routes it expires). A route is an owner's only if it carries routeFlag
// and is in that owner's record.
const routeFlag = unix.RTF_PROTO2

// New returns a configurator for owner on this host's routing table:
// overlay and route table (a supervisor needs Linux).
func New(owner Owner) (Configurator, error) {
	if owner != OwnerOverlay && owner != OwnerRouteTable {
		return nil, fmt.Errorf("netcfg: %v on darwin: %w", owner, errors.ErrUnsupported)
	}
	k, err := openKernel()
	if err != nil {
		return nil, err
	}
	c, err := newDarwin(owner, k, LockDir)
	if err != nil {
		_ = k.close()
		return nil, err
	}
	return c, nil
}

// kroute is a route as the kernel's routing table holds it. Its identity
// is its destination (with its mask) and, for a scoped route
// (RTF_IFSCOPE: only sockets bound to the interface use it), its
// interface (rkey).
type kroute struct {
	dst netip.Prefix
	// gw is the gateway's address (RTF_GATEWAY, or a reject route's
	// loopback) without a zone; gwZone is the interface index of an
	// IPv6 link-local gateway.
	gw     netip.Addr
	gwZone int
	// link is the interface index of an interface route's link-layer
	// gateway (`route add -interface`).
	link int
	// index is the route's interface (rtm_index).
	index int
	flags int
}

// ignored reports routes that are no one's to own or conflict with: the
// kernel's clones (neighbours, host caches; they inherit their parent's
// flags, routeFlag included).
func (r kroute) ignored() bool { return r.flags&unix.RTF_WASCLONED != 0 }

// rkey is a route's identity: its destination and, for a scoped route,
// its interface's index (0: unscoped). A scoped route never shares an
// identity with an unscoped one.
type rkey struct {
	dst   netip.Prefix
	scope int
}

func unscoped(dst netip.Prefix) rkey { return rkey{dst: dst} }

func (k rkey) String() string {
	if k.scope == 0 {
		return k.dst.String()
	}
	return fmt.Sprintf("%v scope %d", k.dst, k.scope)
}

func (r kroute) key() rkey {
	if r.flags&unix.RTF_IFSCOPE != 0 {
		return rkey{dst: r.dst, scope: r.index}
	}
	return unscoped(r.dst)
}

func (r kroute) String() string {
	s := r.dst.String()
	switch {
	case r.flags&unix.RTF_REJECT != 0:
		s = "reject " + s
	case r.gw.IsValid():
		s += " via " + r.gw.String()
	case r.link != 0:
		s += fmt.Sprintf(" link#%d", r.link)
	}
	return s
}

// kifc is an interface as the kernel reports it.
type kifc struct {
	name              string
	index, mtu        int
	up, p2p, loopback bool
}

// kernel is what the configurator asks of the OS (routing socket, RIB
// dumps, interface ioctls), so its logic is tested against a fake.
type kernel interface {
	// routes dumps the routing table, both families.
	routes() ([]kroute, error)
	// add adds a route; an existing route with its identity fails with
	// EEXIST.
	add(kroute) error
	// del deletes the route with r's identity; ESRCH if there is none.
	del(r kroute) error
	// change points the route with r's identity where r says
	// (RTM_CHANGE); ESRCH if there is none.
	change(r kroute) error
	interfaces() ([]kifc, error)
	// addrs are an interface's addresses with their prefix lengths.
	addrs(index int) ([]netip.Prefix, error)
	addAddr(ifc kifc, p netip.Prefix) error
	delAddr(ifc kifc, p netip.Prefix) error
	setMTU(name string, mtu int) error
	setUp(name string, up bool) error
	// watch signals routing changes (see Configurator.Watch) until ctx
	// ends; the channel closes then or when watching fails.
	watch(ctx context.Context) (<-chan struct{}, error)
	close() error
}

type darwinConfigurator struct {
	mu     sync.Mutex
	k      kernel
	owner  Owner
	dir    *os.File // the lock directory, opened by trusteddir
	boot   string   // the boot session, stamped on records
	lock   *ownerLock
	closed bool

	// owned are the identities of the routes this owner has (or may
	// have, while an Apply runs) in the kernel, as its record says.
	owned map[rkey]bool
	// pinned are routes an Apply's undo failed to remove: they stay in
	// the record, whatever the write-ahead's undo says.
	pinned map[rkey]bool
	links  map[string]linkChange // interfaces whose MTU or state we changed
	addrs  map[addrKey]int       // owned addresses → index they were added to
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

// newDarwin takes owner's place in path (its lock and its record; the
// directory is made if missing, and it and everything above it must pass
// trusteddir, since the record decides which routes are deleted) and
// returns its configurator on k.
func newDarwin(owner Owner, k kernel, path string) (*darwinConfigurator, error) {
	boot, err := bootSession()
	if err != nil {
		return nil, fmt.Errorf("netcfg: %v: %w", owner, err)
	}
	dir, err := trusteddir.Make(path)
	if err != nil {
		return nil, fmt.Errorf("netcfg: %v: %w", owner, err)
	}
	lock, err := lockOwner(dir, owner)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("netcfg: %v: %w", owner, err)
	}
	owned, err := readRecord(dir, recordName(owner), boot)
	if err != nil {
		_ = lock.release()
		_ = dir.Close()
		return nil, fmt.Errorf("netcfg: reading %v's route record: %w", owner, err)
	}
	return &darwinConfigurator{
		k: k, owner: owner, dir: dir, boot: boot, lock: lock, owned: owned, pinned: make(map[rkey]bool),
		links: make(map[string]linkChange), addrs: make(map[addrKey]int),
	}, nil
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

// checkDarwin rejects what macOS routing can't hold: there are no route
// metrics, tables, throw routes or policy rules.
func checkDarwin(cfg Config) error {
	if len(cfg.Rules) > 0 {
		return fmt.Errorf("netcfg: policy rules on darwin: %w", errors.ErrUnsupported)
	}
	for _, r := range cfg.Routes {
		switch {
		case r.Scope != "" && r.Interface != "" && r.Interface != r.Scope:
			return fmt.Errorf("netcfg: route %v: a scoped route leaves through its scope's interface", r)
		case r.Table != 0:
			return fmt.Errorf("netcfg: route %v: tables on darwin: %w", r, errors.ErrUnsupported)
		case r.Metric != 0:
			return fmt.Errorf("netcfg: route %v: metrics on darwin: %w", r, errors.ErrUnsupported)
		case r.Type == RouteThrow:
			return fmt.Errorf("netcfg: route %v: throw routes on darwin: %w", r, errors.ErrUnsupported)
		case r.Dst.Bits() == 0:
			// The OS's own default routes would conflict; split routes
			// (0.0.0.0/1 + 128.0.0.0/1) take their place.
			return fmt.Errorf("netcfg: route %v: a default route on darwin: %w", r, errors.ErrUnsupported)
		}
	}
	return nil
}

func (c *darwinConfigurator) Apply(ctx context.Context, cfg Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkDarwin(cfg); err != nil {
		return err
	}
	clear(c.pinned)
	var undo undoLog
	err := c.apply(ctx, cfg, &undo)
	if err != nil {
		if uerr := undo.run(); uerr != nil {
			err = fmt.Errorf("%w; undoing it also failed: %w", err, uerr)
		}
	}
	if serr := c.saveRecord(); serr != nil && err == nil {
		err = serr
	}
	return err
}

// view is the kernel's routing table as Apply and Survey see it.
type view struct {
	routes map[rkey]kroute // not cloned
	ifcs   map[string]kifc
	byIdx  map[int]kifc
}

func (c *darwinConfigurator) view() (view, error) {
	rs, err := c.k.routes()
	if err != nil {
		return view{}, fmt.Errorf("netcfg: list routes: %w", err)
	}
	v := view{routes: make(map[rkey]kroute), ifcs: make(map[string]kifc), byIdx: make(map[int]kifc)}
	for _, r := range rs {
		if !r.ignored() && r.dst.IsValid() {
			v.routes[r.key()] = r
		}
	}
	ifcs, err := c.k.interfaces()
	if err != nil {
		return view{}, fmt.Errorf("netcfg: list interfaces: %w", err)
	}
	for _, i := range ifcs {
		v.ifcs[i.name], v.byIdx[i.index] = i, i
	}
	return v, nil
}

// ours reports whether the kernel's route r is this owner's.
func (c *darwinConfigurator) ours(r kroute) bool {
	return r.flags&routeFlag != 0 && c.owned[r.key()]
}

func (c *darwinConfigurator) apply(ctx context.Context, cfg Config, u *undoLog) error {
	v, err := c.view()
	if err != nil {
		return err
	}
	// Recorded routes that aren't there (or aren't ours any more) are
	// forgotten: a crashed predecessor's, gone with an interface.
	for k := range c.owned {
		if r, ok := v.routes[k]; !ok || r.flags&routeFlag == 0 {
			c.forget(k, u)
		}
	}

	wantLinks := make(map[string]bool)
	wantAddrs := make(map[addrKey]bool)
	routes := slices.Clone(cfg.Routes)
	for _, ifc := range cfg.Interfaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		l, ok := v.ifcs[ifc.Name]
		if !ok {
			return fmt.Errorf("netcfg: interface %s: %w", ifc.Name, errNoInterface)
		}
		wantLinks[ifc.Name] = true
		if err := c.configureLink(l, ifc, u); err != nil {
			return err
		}
		have, err := c.k.addrs(l.index)
		if err != nil {
			return fmt.Errorf("netcfg: addresses of %s: %w", ifc.Name, err)
		}
		for _, p := range ifc.Addrs {
			k := addrKey{ifc.Name, p}
			wantAddrs[k] = true
			present, other := findAddr(have, p)
			if other.IsValid() {
				return fmt.Errorf("%w: address %v on %s: it is there as %v", ErrConflict, p, ifc.Name, other)
			}
			owned := c.ownsAddr(k, l.index)
			switch {
			case present && owned:
			case present: // someone else's: used, not owned
				if _, recorded := c.addrs[k]; recorded {
					c.dropAddrRecord(k, u)
				}
			default:
				if err := c.addAddr(l, k, u); err != nil {
					return err
				}
			}
		}
		routes = append(routes, c.connected(v, l, ifc)...)
	}

	desired := make(map[rkey]bool, len(routes))
	wants := make([]kroute, len(routes))
	for i, r := range routes {
		want, err := c.toKernel(v, r)
		if err != nil {
			return err
		}
		if desired[want.key()] {
			return fmt.Errorf("netcfg: route %v: another route has the same destination", r)
		}
		desired[want.key()], wants[i] = true, want
	}
	// Ownership is decided on what was recorded before this Apply, and
	// an identity someone else's route holds is a conflict before
	// anything is recorded: the record must never name another's route.
	prior := maps.Clone(c.owned)
	ours := func(r kroute) bool { return r.flags&routeFlag != 0 && prior[r.key()] }
	for i, r := range routes {
		if cur, ok := v.routes[wants[i].key()]; ok && !ours(cur) {
			return fmt.Errorf("%w: route %v: another owner's or a foreign route has the same destination (%v)", ErrConflict, r, cur)
		}
	}
	// Write ahead: the record holds every route this Apply may leave, so a
	// crash halfway leaves none unrecorded.
	for k := range desired {
		if !c.owned[k] {
			c.owned[k] = true
			u.push(func() error {
				if !c.pinned[k] {
					delete(c.owned, k)
				}
				return nil
			})
		}
	}
	if err := c.saveRecord(); err != nil {
		return err
	}

	for i, r := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := wants[i]
		if cur, ok := v.routes[want.key()]; ok {
			if sameRoute(cur, want) {
				continue
			}
			if sameKind(cur, want) {
				if err := c.changeRoute(cur, want, u); err == nil {
					continue
				}
				// The kernel wouldn't change it in place: delete and add.
			}
			if err := c.delRoute(cur, u); err != nil {
				return err
			}
		}
		if err := c.addRoute(r, want, u); err != nil {
			return err
		}
	}
	// Ours but not wanted: dropped from the config, or a dead
	// predecessor's leftovers.
	for k := range c.owned {
		if desired[k] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if cur, ok := v.routes[k]; ok && ours(cur) {
			if err := c.delRoute(cur, u); err != nil {
				return err
			}
		}
		c.forget(k, u)
	}
	for k, idx := range c.addrs {
		if wantAddrs[k] {
			continue
		}
		have, err := c.k.addrs(idx)
		if err != nil && !gone(err) {
			return fmt.Errorf("netcfg: addresses of %s: %w", k.link, err)
		}
		if present, _ := findAddr(have, k.prefix); present {
			if err := c.delAddr(k, idx, v, u); err != nil {
				return err
			}
		}
		c.dropAddrRecord(k, u)
	}
	for name := range c.links {
		if !wantLinks[name] {
			if err := c.restoreLink(name, v, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// connected are the routes a point-to-point interface (a utun) needs for
// the networks of its addresses, which macOS doesn't add for it (it routes
// only the peer address): owned like any other route, unless the kernel
// already routes the network through the interface. They are each
// network's two halves (ConnectedRoutes), so that a route for the whole
// network, such as route-table enforcement's reject route that outlives
// the utun, can sit behind them.
func (c *darwinConfigurator) connected(v view, l kifc, ifc Interface) []Route {
	if !l.p2p {
		return nil
	}
	var out []Route
	for _, p := range ifc.Addrs {
		dst := p.Masked()
		if dst.Bits() == p.Addr().BitLen() {
			continue
		}
		if r, ok := v.routes[unscoped(dst)]; ok && !c.ours(r) && r.flags&unix.RTF_GATEWAY == 0 && (r.link == l.index || r.index == l.index) {
			continue // the kernel's (or another's) route into it does
		}
		for _, h := range ConnectedRoutes(dst) {
			out = append(out, Route{Dst: h, Interface: l.name})
		}
	}
	return out
}

// loopback is a reject route's gateway, as route(8) makes them.
func loopback(f Family) netip.Addr {
	if f == IPv4 {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

// toKernel is r as the kernel's route to add.
func (c *darwinConfigurator) toKernel(v view, r Route) (kroute, error) {
	k := kroute{dst: r.Dst, flags: unix.RTF_UP | unix.RTF_STATIC | routeFlag}
	if r.Dst.Bits() == r.Dst.Addr().BitLen() {
		k.flags |= unix.RTF_HOST
	}
	index := 0
	ifc := r.Interface
	if r.Scope != "" {
		ifc = r.Scope
	}
	if ifc != "" {
		l, ok := v.ifcs[ifc]
		if !ok {
			return kroute{}, fmt.Errorf("netcfg: route %v: interface %s: %w", r, ifc, errNoInterface)
		}
		index = l.index
	}
	if r.Scope != "" {
		// route(8)'s -ifscope: the flag, and the scope's index in
		// rtm_index.
		k.flags |= unix.RTF_IFSCOPE
	}
	switch {
	case r.Type == RouteUnreachable:
		k.flags |= unix.RTF_REJECT | unix.RTF_GATEWAY
		k.gw = loopback(r.Family())
	case r.Gateway.IsValid():
		k.flags |= unix.RTF_GATEWAY
		k.gw = r.Gateway
		if r.Gateway.Is6() && (r.Gateway.IsLinkLocalUnicast() || r.Gateway.IsLinkLocalMulticast()) {
			k.gwZone = index
		}
	default:
		k.link = index
	}
	k.index = index
	return k, nil
}

// sameRoute reports whether the kernel's route is what want asks for;
// flags the kernel adds on its own (cloning, global) don't count.
func sameRoute(kr, want kroute) bool {
	const kind = unix.RTF_REJECT | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_BLACKHOLE
	if kr.flags&kind != want.flags&kind || kr.gw != want.gw {
		return false
	}
	if want.gwZone != 0 && kr.gwZone != want.gwZone {
		return false
	}
	if want.link != 0 {
		link := kr.link
		if link == 0 {
			link = kr.index
		}
		return link == want.link
	}
	return true
}

func (c *darwinConfigurator) addRoute(r Route, k kroute, u *undoLog) error {
	if err := c.k.add(k); err != nil {
		if errors.Is(err, unix.EEXIST) {
			delete(c.owned, k.key()) // whoever it is, it isn't ours
			return fmt.Errorf("%w: route %v: another owner's or a foreign route has the same destination", ErrConflict, r)
		}
		return fmt.Errorf("netcfg: add route %v: %w", r, err)
	}
	c.owned[k.key()] = true
	u.push(func() error {
		if err := c.k.del(k); err != nil && !gone(err) {
			c.pinned[k.key()] = true // still there, still ours: Close or the next Apply removes it
			return fmt.Errorf("netcfg: remove route %v: %w", r, err)
		}
		return nil
	})
	return nil
}

// changeRoute moves the kernel's route kr, ours, to want in place
// (RTM_CHANGE), so traffic never falls through to the next route
// meanwhile: a new gateway or interface for a route of the same kind. Its
// undo moves it back.
func (c *darwinConfigurator) changeRoute(kr, want kroute, u *undoLog) error {
	if err := c.k.change(want); err != nil {
		return err
	}
	u.push(func() error { return c.k.change(kr) })
	return nil
}

// sameKind reports whether two routes differ only in where they lead.
func sameKind(a, b kroute) bool {
	const kind = unix.RTF_REJECT | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_BLACKHOLE
	return a.flags&kind == b.flags&kind
}

// delRoute deletes the kernel's route kr, ours; its undo adds it back.
func (c *darwinConfigurator) delRoute(kr kroute, u *undoLog) error {
	err := c.k.del(kr)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove route %v: %w", kr, err)
	}
	u.push(func() error { return c.k.add(kr) })
	return nil
}

// forget drops k from the record; its undo puts it back.
func (c *darwinConfigurator) forget(k rkey, u *undoLog) {
	if !c.owned[k] {
		return
	}
	delete(c.owned, k)
	u.push(func() error { c.owned[k] = true; return nil })
}

// configureLink sets the MTU and brings the link up as asked. Zero values
// leave the link alone; what was changed is restored when the interface
// leaves the config or on Close.
func (c *darwinConfigurator) configureLink(l kifc, ifc Interface, u *undoLog) error {
	if ch, ok := c.links[l.name]; ok && ch.index != l.index {
		c.dropLinkRecord(l.name, u) // a recreated interface: earlier changes went with the old one
	}
	if ifc.MTU != 0 && l.mtu != ifc.MTU {
		old := l.mtu
		if err := c.k.setMTU(l.name, ifc.MTU); err != nil {
			return fmt.Errorf("netcfg: MTU %d on %s: %w", ifc.MTU, l.name, err)
		}
		c.updateLinkRecord(l.name, l.index, func(ch *linkChange) {
			if ch.mtu == 0 {
				ch.origMTU = old
			}
			ch.mtu = ifc.MTU
		}, u, func() error { return c.k.setMTU(l.name, old) })
	}
	if ifc.Up && !l.up {
		if err := c.k.setUp(l.name, true); err != nil {
			return fmt.Errorf("netcfg: bring %s up: %w", l.name, err)
		}
		c.updateLinkRecord(l.name, l.index, func(ch *linkChange) { ch.setUp = true },
			u, func() error { return c.k.setUp(l.name, false) })
	}
	return nil
}

// restoreLink undoes our MTU and state changes on an interface, each only
// if it still is what we set.
func (c *darwinConfigurator) restoreLink(name string, v view, u *undoLog) error {
	ch := c.links[name]
	l, ok := v.byIdx[ch.index]
	if !ok || l.name != name {
		c.dropLinkRecord(name, u)
		return nil
	}
	if ch.mtu != 0 && l.mtu == ch.mtu && ch.origMTU != ch.mtu {
		if err := c.k.setMTU(name, ch.origMTU); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: restore MTU of %s: %w", name, err)
		}
		c.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.mtu, ch.origMTU = 0, 0 },
			u, func() error { return c.k.setMTU(name, l.mtu) })
	}
	if ch.setUp && l.up {
		if err := c.k.setUp(name, false); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: bring %s down: %w", name, err)
		}
		c.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.setUp = false },
			u, func() error { return c.k.setUp(name, true) })
	}
	c.dropLinkRecord(name, u)
	return nil
}

// updateLinkRecord records a change made to a link. Its undo reverts the
// change and only then the record, so a failed revert keeps the record.
func (c *darwinConfigurator) updateLinkRecord(name string, index int, change func(*linkChange), u *undoLog, revert func() error) {
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

func (c *darwinConfigurator) dropLinkRecord(name string, u *undoLog) {
	prev, had := c.links[name]
	delete(c.links, name)
	u.push(func() error { c.restoreLinkRecord(name, prev, had); return nil })
}

func (c *darwinConfigurator) restoreLinkRecord(name string, ch linkChange, had bool) {
	if had {
		c.links[name] = ch
	} else {
		delete(c.links, name)
	}
}

func (c *darwinConfigurator) ownsAddr(k addrKey, index int) bool {
	idx, ok := c.addrs[k]
	return ok && idx == index
}

func (c *darwinConfigurator) addAddr(l kifc, k addrKey, u *undoLog) error {
	if err := c.k.addAddr(l, k.prefix); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: address %v on %s: %w", ErrConflict, k.prefix, k.link, err)
		}
		return fmt.Errorf("netcfg: add %v to %s: %w", k.prefix, k.link, err)
	}
	prev, had := c.addrs[k]
	c.addrs[k] = l.index
	u.push(func() error {
		if err := c.k.delAddr(l, k.prefix); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
		}
		c.restoreAddrRecord(k, prev, had)
		return nil
	})
	return nil
}

// delAddr deletes an address that is there; its undo adds it back.
func (c *darwinConfigurator) delAddr(k addrKey, index int, v view, u *undoLog) error {
	l, ok := v.byIdx[index]
	if !ok {
		return nil
	}
	err := c.k.delAddr(l, k.prefix)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
	}
	u.push(func() error { return c.k.addAddr(l, k.prefix) })
	return nil
}

func (c *darwinConfigurator) dropAddrRecord(k addrKey, u *undoLog) {
	prev, had := c.addrs[k]
	delete(c.addrs, k)
	u.push(func() error { c.restoreAddrRecord(k, prev, had); return nil })
}

func (c *darwinConfigurator) restoreAddrRecord(k addrKey, index int, had bool) {
	if had {
		c.addrs[k] = index
	} else {
		delete(c.addrs, k)
	}
}

// findAddr reports whether p is in addrs, or else the same address with
// another prefix length (a conflict: an address has one prefix length).
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

func (c *darwinConfigurator) DefaultRoute(ctx context.Context, f Family) (Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Route{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	v, err := c.view()
	if err != nil {
		return Route{}, err
	}
	thinkpol, err := c.thinkpolRoutes()
	if err != nil {
		return Route{}, err
	}
	return defaultRoute(v, thinkpol, f)
}

// thinkpolRoutes are the identities every owner's record holds. A record
// that can't be read is an error, not an empty one: with its owner's
// identities unknown, the owner's routes must be left alone rather than
// mistaken for foreign ones.
func (c *darwinConfigurator) thinkpolRoutes() (map[rkey]bool, error) {
	out := make(map[rkey]bool)
	for _, o := range Owners {
		rec, err := readRecord(c.dir, recordName(o), c.boot)
		if err != nil {
			return nil, fmt.Errorf("netcfg: reading %v's route record: %w", o, err)
		}
		for p := range rec {
			out[p] = true
		}
	}
	return out, nil
}

func isThinkpol(r kroute, thinkpol map[rkey]bool) bool {
	return r.flags&routeFlag != 0 && thinkpol[r.key()]
}

// usable reports a route packets can take: up, neither reject nor
// blackhole.
func usable(r kroute) bool {
	return r.flags&unix.RTF_UP != 0 && r.flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) == 0
}

// defaultRoute is the family's unscoped default route: the primary
// service's, which macOS keeps unscoped (the others' are scoped to their
// interfaces).
func defaultRoute(v view, thinkpol map[rkey]bool, f Family) (Route, error) {
	dst := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if f == IPv6 {
		dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	r, ok := v.routes[unscoped(dst)]
	if !ok || !usable(r) || isThinkpol(r, thinkpol) {
		return Route{}, fmt.Errorf("%w (%v)", ErrNoDefaultRoute, f)
	}
	return routeOf(v, r), nil
}

// routeOf is the kernel's route as a Route.
func routeOf(v view, r kroute) Route {
	out := Route{Dst: r.dst}
	if r.flags&unix.RTF_GATEWAY != 0 && r.gw.IsValid() {
		out.Gateway = r.gw
	}
	idx := r.index
	if !out.Gateway.IsValid() && r.link != 0 {
		idx = r.link
	}
	if l, ok := v.byIdx[idx]; ok {
		out.Interface = l.name
	}
	if r.flags&unix.RTF_REJECT != 0 {
		out = Route{Dst: r.dst, Type: RouteUnreachable}
	}
	return out
}

// Survey reports, besides the interfaces: OnLink, the interfaces' subnets
// (the kernel's cloning routes for their addresses); Defaults, the
// unscoped default routes; and Routes, every other unscoped route no
// thinkpol owner added that could take traffic ahead of the tunnel's split
// routes (another VPN's, a DHCP server's classless routes, static ones).
// Loopback's routes, reject and blackhole routes (they leak nothing), the
// kernel's clones, local and broadcast entries and ICMP redirects' host
// routes are left out.
func (c *darwinConfigurator) Survey(ctx context.Context) (Survey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Survey{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Survey{}, err
	}
	v, err := c.view()
	if err != nil {
		return Survey{}, err
	}
	thinkpol, err := c.thinkpolRoutes()
	if err != nil {
		return Survey{}, err
	}
	return survey(v, thinkpol), nil
}

func survey(v view, thinkpol map[rkey]bool) Survey {
	var s Survey
	for _, l := range v.ifcs {
		s.Links = append(s.Links, Link{Name: l.name, Up: l.up})
	}
	slices.SortFunc(s.Links, func(a, b Link) int { return strings.Compare(a.Name, b.Name) })
	for _, f := range []Family{IPv4, IPv6} {
		if d, err := defaultRoute(v, thinkpol, f); err == nil {
			s.Defaults = append(s.Defaults, d)
		}
	}
	const skip = unix.RTF_REJECT | unix.RTF_BLACKHOLE | unix.RTF_LOCAL | unix.RTF_BROADCAST
	for _, r := range v.routes {
		if r.key().scope != 0 {
			// Only sockets bound to its interface use a scoped route.
			if !isThinkpol(r, thinkpol) {
				if l, ok := v.byIdx[r.index]; ok {
					s.HeldScoped = append(s.HeldScoped, Route{Dst: r.dst, Scope: l.name})
				}
			}
			continue
		}
		if !isThinkpol(r, thinkpol) {
			s.Held = append(s.Held, r.dst)
		}
		if r.dst.Bits() == 0 || isThinkpol(r, thinkpol) || r.flags&skip != 0 || r.flags&unix.RTF_UP == 0 {
			continue
		}
		if r.flags&unix.RTF_DYNAMIC != 0 && r.flags&unix.RTF_HOST != 0 {
			continue // an ICMP redirect's: only for destinations already routed by that gateway
		}
		idx := r.index
		if r.link != 0 {
			idx = r.link
		}
		if l, ok := v.byIdx[idx]; ok && l.loopback {
			continue
		}
		if r.flags&unix.RTF_GATEWAY == 0 && r.flags&unix.RTF_CLONING != 0 {
			s.OnLink = append(s.OnLink, r.dst)
			continue
		}
		s.Routes = append(s.Routes, routeOf(v, r))
	}
	slices.SortFunc(s.OnLink, comparePrefixes)
	slices.SortFunc(s.Held, comparePrefixes)
	slices.SortFunc(s.Routes, func(a, b Route) int { return comparePrefixes(a.Dst, b.Dst) })
	return s
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

func (c *darwinConfigurator) Watch(ctx context.Context) (<-chan struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	ch, err := c.k.watch(ctx)
	if err != nil {
		return nil, fmt.Errorf("netcfg: watch routes: %w", err)
	}
	return ch, nil
}

func (c *darwinConfigurator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lock == nil {
		return nil
	}
	c.closed = true
	// Whatever happens, the owner's place is freed: a configurator that
	// failed to close is dropped by its caller, and its record lets the
	// next one of the owner take over what is left.
	defer func() {
		_ = c.k.close()
		_ = c.lock.release()
		_ = c.dir.Close()
		c.lock = nil
	}()
	v, err := c.view()
	if err != nil {
		return err
	}
	var errs []error
	for k := range c.owned {
		r, ok := v.routes[k]
		if ok && c.ours(r) {
			if err := c.delRoute(r, nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(c.owned, k)
	}
	for k, idx := range c.addrs {
		have, err := c.k.addrs(idx)
		if err != nil && !gone(err) {
			errs = append(errs, err)
			continue
		}
		if present, _ := findAddr(have, k.prefix); present {
			if err := c.delAddr(k, idx, v, nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(c.addrs, k)
	}
	for name := range c.links {
		if err := c.restoreLink(name, v, nil); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.saveRecord(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...) // what's left stays recorded for the next configurator
}

func (c *darwinConfigurator) saveRecord() error {
	if err := writeRecord(c.dir, recordName(c.owner), c.boot, c.owned); err != nil {
		return fmt.Errorf("netcfg: record of %v's routes: %w", c.owner, err)
	}
	return nil
}

// errNoInterface: the interface doesn't exist (any more).
var errNoInterface = errors.New("no such interface")

// gone reports errors meaning the thing to remove or restore no longer
// exists, which for cleanup is success.
func gone(err error) bool {
	return errors.Is(err, errNoInterface) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENODEV)
}
