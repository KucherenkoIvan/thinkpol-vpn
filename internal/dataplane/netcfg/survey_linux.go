//go:build linux && !android

package netcfg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (c *linuxConfigurator) Survey(ctx context.Context) (Survey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Survey{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Survey{}, err
	}
	var s Survey
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := c.listRoutes(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_KERNEL},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return Survey{}, err
		}
		for _, r := range routes {
			p := dstOf(r, fam)
			if r.Type != unix.RTN_UNICAST || r.Gw != nil || len(r.MultiPath) > 0 || !p.IsValid() || p.Bits() == 0 {
				continue
			}
			s.OnLink = append(s.OnLink, p)
		}
		rules, err := c.listRules(fam)
		if err != nil {
			return Survey{}, err
		}
		for _, r := range rules {
			if r.Priority == 0 || r.Priority == 32766 || r.Priority == 32767 || isOwnerProtocol(netlink.RouteProtocol(r.Protocol)) {
				continue
			}
			s.ForeignRules = append(s.ForeignRules, r.Priority)
		}
	}
	slices.SortFunc(s.OnLink, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	s.OnLink = slices.Compact(s.OnLink)
	slices.Sort(s.ForeignRules)
	links, err := c.h.LinkList()
	if err != nil {
		return Survey{}, fmt.Errorf("netcfg: list links: %w", err)
	}
	for _, l := range links {
		a := l.Attrs()
		s.Links = append(s.Links, Link{Name: a.Name, Up: a.Flags&net.FlagUp != 0})
	}
	slices.SortFunc(s.Links, func(a, b Link) int { return strings.Compare(a.Name, b.Name) })
	return s, nil
}
