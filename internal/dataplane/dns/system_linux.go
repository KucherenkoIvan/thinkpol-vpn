//go:build linux && !android

package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	etcResolvConf = "/etc/resolv.conf"
	// resolvedUplink lists the servers systemd-resolved itself uses.
	resolvedUplink = "/run/systemd/resolve/resolv.conf"
)

// SetSystem points the OS resolver at c.Servers until Restore. Whenever
// systemd-resolved runs, the TUN becomes its link for every name (over
// D-Bus); unless /etc/resolv.conf sends everything to resolved's stub, it
// is rewritten too, and watched, and rewritten again if another program
// replaces it.
func SetSystem(c SystemConfig) (System, error) {
	if len(c.Servers) == 0 {
		return nil, errors.New("dns: no resolver address to point the system at")
	}
	var parts systems
	stub := usesResolvedStub()
	if conn, err := resolvedBus(); err == nil {
		r, err := setResolved(conn, c, stub)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if !stub || len(parts) == 0 {
		rc, err := setResolvConf(etcResolvConf, resolvedUplink, c)
		if err != nil {
			_ = parts.Restore()
			return nil, err
		}
		parts = append(parts, rc)
	}
	return parts, nil
}

// RestoreSystem puts back a resolv.conf the node left managed (it crashed,
// or the machine went down while it ran). Call it when the node starts.
func RestoreSystem() error { return restoreResolvConf(etcResolvConf) }

// SystemUpstreams are the resolvers the OS uses on its own: the servers
// /etc/resolv.conf named before the node managed it, or, when it names
// systemd-resolved's stub, the servers resolved uses. Addresses in
// exclude (the node's own) and the stub are left out.
func SystemUpstreams(exclude []netip.Addr) ([]netip.Addr, error) {
	return upstreamsFrom(etcResolvConf, resolvedUplink, exclude)
}

func usesResolvedStub() bool {
	content, err := originalResolvConf(etcResolvConf)
	return err == nil && onlyStubs(nameservers(content))
}

// systems is a configuration in several parts, all applied.
type systems []System

func (s systems) Update(c SystemConfig) error {
	var errs []error
	for _, p := range s {
		errs = append(errs, p.Update(c))
	}
	return errors.Join(errs...)
}

func (s systems) Problem() error {
	var errs []error
	for _, p := range s {
		errs = append(errs, p.Problem())
	}
	return errors.Join(errs...)
}

func (s systems) Restore() error {
	var errs []error
	for _, p := range s {
		errs = append(errs, p.Restore())
	}
	return errors.Join(errs...)
}

const (
	resolvedName    = "org.freedesktop.resolve1"
	resolvedPath    = "/org/freedesktop/resolve1"
	resolvedManager = "org.freedesktop.resolve1.Manager"
	// resolvedCheck is how often resolved's other links are checked.
	resolvedCheck = 5 * time.Second
)

// resolvedBus connects to the system bus if systemd-resolved owns its
// name there.
func resolvedBus() (*dbus.Conn, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	var running bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, resolvedName).Store(&running); err != nil || !running {
		_ = conn.Close()
		return nil, errors.New("dns: systemd-resolved is not running")
	}
	return conn, nil
}

// resolved is the overlay link's configuration in systemd-resolved.
type resolved struct {
	conn  *dbus.Conn
	index int32
	// uplink: resolved is the OS's resolver (resolv.conf names its stub),
	// so its servers are the OS's own.
	uplink bool

	mu      sync.Mutex
	cfg     SystemConfig
	problem error
	servers []netip.Addr // the uplink servers last seen
	// untold: cfg.Upstreams has no servers yet, its caller's own read
	// having failed (UpstreamsUnknown). The first good read of the uplink
	// tells it, whether or not the servers changed; until then Problem
	// reports ErrUpstreamsStale.
	untold  bool
	stop    chan struct{}
	stopped chan struct{}
}

type resolvedAddr struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Domain      string
	RoutingOnly bool
}

type resolvedLinkAddr struct {
	Ifindex int32
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Ifindex     int32
	Domain      string
	RoutingOnly bool
}

func setResolved(conn *dbus.Conn, c SystemConfig, uplink bool) (*resolved, error) {
	ifc, err := net.InterfaceByName(c.Interface)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := &resolved{conn: conn, index: int32(ifc.Index), uplink: uplink, stop: make(chan struct{}), stopped: make(chan struct{}),
		untold: uplink && c.UpstreamsUnknown && c.Upstreams != nil}
	var tellFirst []netip.Addr
	tellNow := false
	if b, err := os.ReadFile(resolvedUplink); err == nil {
		r.servers = nameservers(b)
		if r.untold {
			// A good read now is the first one the caller hears of: told
			// from the watch goroutine, whatever a later read finds.
			r.untold = false
			tellFirst, tellNow = upstreamsFromContent(b, resolvedUplink, c.Servers), true
		}
	}
	if err := r.Update(c); err != nil {
		_ = r.call("RevertLink")
		_ = conn.Close()
		return nil, err
	}
	go r.watch(tellFirst, tellNow)
	return r, nil
}

// Update configures the link: the resolver's addresses, every name
// ("~.") plus the search domains, the default route; nothing resolved
// would add on its own (LLMNR, mDNS, its own DNS-over-TLS or DNSSEC
// checks, which the node's resolver doesn't answer).
func (r *resolved) Update(c SystemConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = c
	var addrs []resolvedAddr
	for _, a := range c.Servers {
		family := int32(2) // AF_INET
		if a.Is6() {
			family = 10 // AF_INET6
		}
		addrs = append(addrs, resolvedAddr{family, a.AsSlice()})
	}
	domains := []resolvedDomain{{".", true}}
	for _, d := range c.Search {
		domains = append(domains, resolvedDomain{d, false})
	}
	steps := []struct {
		method string
		arg    any
	}{
		{"SetLinkDNS", addrs},
		{"SetLinkDomains", domains},
		{"SetLinkDefaultRoute", true},
		{"SetLinkLLMNR", "no"},
		{"SetLinkMulticastDNS", "no"},
		{"SetLinkDNSOverTLS", "no"},
		{"SetLinkDNSSEC", "no"},
	}
	for _, s := range steps {
		if err := r.call(s.method, s.arg); err != nil {
			return fmt.Errorf("dns: systemd-resolved %s: %w", s.method, err)
		}
	}
	r.problem = r.check()
	return nil
}

func (r *resolved) call(method string, args ...any) error {
	return r.conn.Object(resolvedName, resolvedPath).Call(resolvedManager+"."+method, 0, append([]any{r.index}, args...)...).Err
}

// check finds what can take names past the link: a domain configured on
// any other link, or globally, where there are servers to send its names
// to. resolved sends a name to the links whose domain matches it best,
// all of them on a tie: another link's domain beats the link's "~." for
// the names under it, and another "~." (which NetworkManager adds to the
// connection with the default route) shares every name. Links without
// domains get names only when no domain matches, which "~." rules out;
// a domain without servers sends its names nowhere.
func (r *resolved) check() error {
	manager := r.conn.Object(resolvedName, resolvedPath)
	var domains []resolvedLinkDomain
	var servers []resolvedLinkAddr
	for _, p := range []struct {
		name string
		to   any
	}{{"Domains", &domains}, {"DNS", &servers}} {
		v, err := manager.GetProperty(resolvedManager + "." + p.name)
		if err == nil {
			err = v.Store(p.to)
		}
		if err != nil {
			return fmt.Errorf("%w: reading systemd-resolved's %s: %v", ErrUnprotected, p.name, err)
		}
	}
	served := map[int32]bool{}
	for _, s := range servers {
		served[s.Ifindex] = true
	}
	var others []string
	for _, d := range domains {
		if d.Ifindex == r.index || !served[d.Ifindex] {
			continue
		}
		name := d.Domain
		if d.RoutingOnly {
			name = "~" + name
		}
		where := fmt.Sprintf("link %d", d.Ifindex)
		if d.Ifindex == 0 {
			where = "global"
		}
		others = append(others, where+" "+name)
	}
	if len(others) > 0 {
		return fmt.Errorf("%w: systemd-resolved routes some names elsewhere (%v)", ErrUnprotected, others)
	}
	return nil
}

func (r *resolved) watch(tellFirst []netip.Addr, tellNow bool) {
	defer close(r.stopped)
	r.mu.Lock()
	upstreams := r.cfg.Upstreams
	r.mu.Unlock()
	if tellNow && upstreams != nil {
		upstreams(tellFirst)
	}
	t := time.NewTicker(resolvedCheck)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
		}
		r.mu.Lock()
		r.problem = r.check()
		var changed, found []netip.Addr
		tellUntold := false
		if b, err := os.ReadFile(resolvedUplink); err == nil && r.uplink {
			servers := upstreamsFromContent(b, resolvedUplink, r.cfg.Servers)
			found = servers
			if !slices.Equal(servers, r.servers) {
				r.servers, changed = servers, servers
			}
			// A good read, told or not: the next change alone is told.
			tellUntold, r.untold = r.untold, false
		}
		upstreams := r.cfg.Upstreams
		r.mu.Unlock()
		switch {
		case changed != nil && upstreams != nil:
			upstreams(changed)
		case tellUntold && upstreams != nil:
			// The first good read is told whatever it found: the caller
			// has no upstreams of its own until one.
			upstreams(found)
		}
	}
}

func (r *resolved) Problem() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.problem, staleUpstreams(r.untold))
}

// Restore reverts the link's configuration (resolved also drops it when
// the TUN goes away).
func (r *resolved) Restore() error {
	select {
	case <-r.stop:
		return nil
	default:
	}
	close(r.stop)
	<-r.stopped
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.call("RevertLink")
	_ = r.conn.Close()
	return err
}
