//go:build linux && !android

package dns

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// Inspect reads /etc/resolv.conf and, while it runs, systemd-resolved's
// global and per-link servers and domains (over D-Bus, read only).
func Inspect(ctx context.Context) HostReport {
	return HostReport{Sources: []HostSource{inspectResolvConf(etcResolvConf), inspectResolved(ctx, dbus.ConnectSystemBus, systemBusSocket)}}
}

// systemBusSocket is where the system bus listens unless
// DBUS_SYSTEM_BUS_ADDRESS says otherwise.
const systemBusSocket = "/var/run/dbus/system_bus_socket"

func inspectResolvConf(path string) HostSource {
	src := HostSource{Name: "resolv.conf"}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return src
	case err != nil:
		src.Unreadable = err.Error()
		return src
	}
	src.Present = true
	src.Resolvers = []HostResolver{resolvConfReport(b)}
	return src
}

// inspectResolved reads systemd-resolved's Manager properties DNS and
// Domains, per link (0: global). No system bus (its socket isn't there
// and no address is set), or no resolved on it, is no resolved.
func inspectResolved(ctx context.Context, connect func(...dbus.ConnOption) (*dbus.Conn, error), socket string) HostSource {
	src := HostSource{Name: "systemd-resolved"}
	if _, err := os.Stat(socket); errors.Is(err, fs.ErrNotExist) && os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") == "" {
		return src
	}
	conn, err := connect(dbus.WithContext(ctx))
	if err != nil {
		src.Unreadable = "the system bus: " + err.Error()
		return src
	}
	defer func() { _ = conn.Close() }()
	var running bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, resolvedName).Store(&running); err != nil {
		src.Unreadable = "the system bus: " + err.Error()
		return src
	}
	if !running {
		return src
	}
	src.Present = true
	manager := conn.Object(resolvedName, resolvedPath)
	var domains []resolvedLinkDomain
	var servers []resolvedLinkAddr
	for _, p := range []struct {
		name string
		to   any
	}{{"DNS", &servers}, {"Domains", &domains}} {
		var v dbus.Variant
		err := manager.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, resolvedManager, p.name).Store(&v)
		if err == nil {
			err = v.Store(p.to)
		}
		if err != nil {
			return HostSource{Name: src.Name, Unreadable: fmt.Sprintf("systemd-resolved's %s: %v", p.name, err)}
		}
	}
	src.Resolvers, err = resolvedLinks(servers, domains)
	if err != nil {
		return HostSource{Name: src.Name, Unreadable: err.Error()}
	}
	return src
}

// resolvedLinks groups resolved's servers and domains by link, global
// (index 0, Interface "") first: the domains as resolved reports them,
// "~" before a routing-only one. A server address it can't read makes
// them unreadable.
func resolvedLinks(servers []resolvedLinkAddr, domains []resolvedLinkDomain) ([]HostResolver, error) {
	byLink := map[int32]*HostResolver{}
	link := func(i int32) *HostResolver {
		if r, ok := byLink[i]; ok {
			return r
		}
		r := &HostResolver{}
		if i != 0 {
			r.Interface = "if" + strconv.Itoa(int(i))
			if ifc, err := net.InterfaceByIndex(int(i)); err == nil {
				r.Interface = ifc.Name
			}
		}
		byLink[i] = r
		return r
	}
	for _, s := range servers {
		a, ok := netip.AddrFromSlice(s.Address)
		if !ok || s.Family == unix.AF_INET && !a.Unmap().Is4() || s.Family == unix.AF_INET6 && len(s.Address) != 16 ||
			s.Family != unix.AF_INET && s.Family != unix.AF_INET6 {
			return nil, fmt.Errorf("systemd-resolved lists a server that can't be read: family %d, %d bytes", s.Family, len(s.Address))
		}
		if s.Family == unix.AF_INET {
			a = a.Unmap()
		}
		link(s.Ifindex).Servers = append(link(s.Ifindex).Servers, a.String())
	}
	for _, d := range domains {
		name := d.Domain
		if d.RoutingOnly {
			name = "~" + name
		}
		link(d.Ifindex).Domains = append(link(d.Ifindex).Domains, name)
	}
	var out []HostResolver
	keys := make([]int32, 0, len(byLink))
	for k := range byLink {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out = append(out, *byLink[k])
	}
	return out, nil
}
