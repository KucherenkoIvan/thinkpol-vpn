//go:build linux && !android

package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/godbus/dbus/v5"
)

const (
	etcResolvConf = "/etc/resolv.conf"
	// resolvedUplink lists the servers systemd-resolved itself uses.
	resolvedUplink = "/run/systemd/resolve/resolv.conf"
)

// SetSystem points the OS resolver at c.Servers until Restore: through
// systemd-resolved when the OS resolves through its stub (c.Interface
// becomes the link every name goes to), otherwise by rewriting
// /etc/resolv.conf, which is watched and rewritten again if another
// program replaces it.
func SetSystem(c SystemConfig) (System, error) {
	if len(c.Servers) == 0 {
		return nil, errors.New("dns: no resolver address to point the system at")
	}
	if usesResolvedStub() {
		s, err := setResolved(c)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, errNoResolved) {
			return nil, err
		}
	}
	return setResolvConf(etcResolvConf, c)
}

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

var errNoResolved = errors.New("dns: systemd-resolved is not running")

const (
	resolvedName    = "org.freedesktop.resolve1"
	resolvedPath    = "/org/freedesktop/resolve1"
	resolvedManager = "org.freedesktop.resolve1.Manager"
)

// resolved is the overlay link's configuration in systemd-resolved.
type resolved struct {
	conn  *dbus.Conn
	index int32
}

type resolvedAddr struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Domain      string
	RoutingOnly bool
}

func setResolved(c SystemConfig) (*resolved, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoResolved, err)
	}
	var running bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, resolvedName).Store(&running); err != nil || !running {
		_ = conn.Close()
		return nil, errNoResolved
	}
	ifc, err := net.InterfaceByName(c.Interface)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := &resolved{conn: conn, index: int32(ifc.Index)}
	var addrs []resolvedAddr
	for _, a := range c.Servers {
		family := int32(2) // AF_INET
		if a.Is6() {
			family = 10 // AF_INET6
		}
		addrs = append(addrs, resolvedAddr{family, a.AsSlice()})
	}
	// "." routing-only: every name is resolved through this link.
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
			_ = r.Restore()
			return nil, fmt.Errorf("dns: systemd-resolved %s: %w", s.method, err)
		}
	}
	return r, nil
}

func (r *resolved) call(method string, args ...any) error {
	return r.conn.Object(resolvedName, resolvedPath).Call(resolvedManager+"."+method, 0, append([]any{r.index}, args...)...).Err
}

// Restore reverts the link's configuration (resolved also drops it when
// the TUN goes away).
func (r *resolved) Restore() error {
	if r.conn == nil {
		return nil
	}
	err := r.call("RevertLink")
	_ = r.conn.Close()
	r.conn = nil
	return err
}
