//go:build linux && !android

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// wiring is one worker process's veth pair and the space end's
// configuration. The pair lives exactly as long as the process's network
// namespace: the root end goes with it, and with the root end everything
// the root namespace knows about the space (addresses, connected routes).
type wiring struct {
	link  string
	space netcfg.Configurator
}

// wire creates w's veth pair with one end in the namespace ns, addresses
// both ends and gives the space default routes via the root end. The space
// end is configured through netcfg as OwnerSupervisor, so the routes are
// tagged as the supervisor's and the worker's own configurator (overlay)
// can't take them; the root end needs no such care: the supervisor created
// the link, and everything on it is its own.
func (s *Supervisor) wire(w *worker, ns *os.File) (*wiring, error) {
	wd := &wiring{}
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: w.link},
		PeerName:      SpaceInterface,
		PeerNamespace: netlink.NsFd(int(ns.Fd())),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("add veth %s: %w", w.link, err)
	}
	wd.link = w.link
	link, err := netlink.LinkByName(w.link)
	if err != nil {
		return wd, err
	}
	for _, p := range w.transit.root {
		// No duplicate address detection: the pair has two ends and both
		// addresses are ours.
		addr := &netlink.Addr{IPNet: ipNet(p), Flags: unix.IFA_F_NODAD}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return wd, fmt.Errorf("address %v on %s: %w", p, w.link, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return wd, fmt.Errorf("bring %s up: %w", w.link, err)
	}

	cfg, err := netcfg.NewInNamespace(fmt.Sprintf("/proc/self/fd/%d", ns.Fd()), netcfg.OwnerSupervisor)
	if err != nil {
		return wd, err
	}
	wd.space = cfg
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = cfg.Apply(ctx, netcfg.Config{
		Interfaces: []netcfg.Interface{
			{Name: "lo", Up: true},
			{Name: SpaceInterface, Addrs: w.transit.space[:], Up: true},
		},
		Routes: []netcfg.Route{
			{Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Gateway: w.transit.root[0].Addr(), Interface: SpaceInterface},
			{Dst: netip.PrefixFrom(netip.IPv6Unspecified(), 0), Gateway: w.transit.root[1].Addr(), Interface: SpaceInterface},
		},
	})
	if err != nil {
		return wd, fmt.Errorf("configure the space's end: %w", err)
	}
	return wd, nil
}

// unwire undoes wire: it releases the space end's configurator (the
// namespace is still held, so that succeeds) and deletes the pair.
func (wd *wiring) unwire() error {
	if wd == nil {
		return nil
	}
	var errs []error
	if wd.space != nil {
		errs = append(errs, wd.space.Close())
	}
	if wd.link != "" {
		if l, err := netlink.LinkByName(wd.link); err == nil {
			if err := netlink.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
				errs = append(errs, fmt.Errorf("delete %s: %w", wd.link, err))
			}
		} else if !errors.As(err, new(netlink.LinkNotFoundError)) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
