//go:build linux && !android

package egress

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FindUplink finds the uplink of the current network namespace: the
// interface of its preferred IPv4 default route (lowest metric), or of the
// IPv6 one on a node without IPv4. IPv6 is on only when an IPv6 default
// route leaves by the same interface: one uplink carries both families.
func FindUplink() (Uplink, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return Uplink{}, fmt.Errorf("egress: %w", err)
	}
	defer h.Close()
	return findUplink(h)
}

func findUplink(h *netlink.Handle) (Uplink, error) {
	v4, err := defaultLink(h, netlink.FAMILY_V4)
	if err != nil {
		return Uplink{}, err
	}
	v6, err := defaultLink(h, netlink.FAMILY_V6)
	if err != nil {
		return Uplink{}, err
	}
	var up Uplink
	index := v4
	switch {
	case v4 != 0:
		up.IPv4 = true
	case v6 != 0:
		index = v6
	default:
		return Uplink{}, ErrNoUplink
	}
	link, err := h.LinkByIndex(index)
	if err != nil {
		return Uplink{}, fmt.Errorf("egress: uplink %d: %w", index, err)
	}
	up.Name = link.Attrs().Name
	if v6 == index {
		addrs, err := h.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return Uplink{}, fmt.Errorf("egress: addresses of %s: %w", up.Name, err)
		}
		up.IPv6 = slices.ContainsFunc(addrs, func(a netlink.Addr) bool {
			ip, ok := netip.AddrFromSlice(a.IP)
			return ok && ip.Is6() && !ip.Is4In6() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback()
		})
	}
	return up, nil
}

// defaultLink is the interface index of the family's preferred default
// route in the main table, 0 without one. A multipath route counts by its
// first next hop.
func defaultLink(h *netlink.Handle, family int) (int, error) {
	var routes []netlink.Route
	var err error
	for range 10 {
		routes, err = h.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return 0, fmt.Errorf("egress: default routes: %w", err)
	}
	best, index := -1, 0
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		link := r.LinkIndex
		if link == 0 && len(r.MultiPath) > 0 {
			link = r.MultiPath[0].LinkIndex
		}
		if link == 0 {
			continue
		}
		if best < 0 || r.Priority < best {
			best, index = r.Priority, link
		}
	}
	return index, nil
}
