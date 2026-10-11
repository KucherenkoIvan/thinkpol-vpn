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
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// wiring is one worker process's veth pair and the space end's
// configuration. The pair lives exactly as long as the process's network
// namespace: the root end goes with it, and with the root end everything
// the root namespace knows about the space (addresses, neighbours, routes).
type wiring struct {
	link  string
	space netcfg.Configurator
}

// wire creates w's veth pair with one end in the namespace ns, addresses
// both ends, gives the space default routes via the root end and installs
// permanent neighbour entries on both ends, so real traffic needs no ARP or
// ND (which the isolation tables drop from spaces). The space end is
// configured through netcfg as OwnerSupervisor, so the routes are tagged as
// the supervisor's and the worker's own configurator (overlay) can't take
// them.
func (s *Supervisor) wire(w *worker, ns *os.File) (*wiring, error) {
	wd := &wiring{}
	// A slot is reused after a space leaves, and a crashed incarnation's
	// cleanup may have raced; delete any leftover of the name, of any link
	// type, before adding.
	if old, err := netlink.LinkByName(w.link); err == nil {
		_ = netlink.LinkDel(old)
	}
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: w.link},
		PeerName:      SpaceInterface,
		PeerNamespace: netlink.NsFd(int(ns.Fd())),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("add veth %s: %w", w.link, err)
	}
	wd.link = w.link
	rootLink, err := netlink.LinkByName(w.link)
	if err != nil {
		return wd, err
	}
	for _, p := range w.transit.root {
		// No duplicate address detection: the pair has two ends and both
		// addresses are ours.
		if err := netlink.AddrAdd(rootLink, &netlink.Addr{IPNet: ipNet(p), Flags: unix.IFA_F_NODAD}); err != nil {
			return wd, fmt.Errorf("address %v on %s: %w", p, w.link, err)
		}
	}
	if err := netlink.LinkSetUp(rootLink); err != nil {
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
	if err := s.addNeighbours(w, ns, rootLink); err != nil {
		return wd, fmt.Errorf("neighbours: %w", err)
	}
	// The worker has no /proc, so the supervisor sets the space's network
	// sysctls here, by entering its namespace.
	if err := setNetSysctls(int(ns.Fd()), baselineSysctls); err != nil {
		return wd, fmt.Errorf("space sysctls: %w", err)
	}
	return wd, nil
}

// addNeighbours puts a permanent entry for each far end on both ends, so
// neither sends ARP or ND for the other.
func (s *Supervisor) addNeighbours(w *worker, ns *os.File, rootLink netlink.Link) error {
	h, err := netlink.NewHandleAt(netns.NsHandle(ns.Fd()))
	if err != nil {
		return err
	}
	defer h.Close()
	spaceLink, err := h.LinkByName(SpaceInterface)
	if err != nil {
		return err
	}
	rootMAC, spaceMAC := rootLink.Attrs().HardwareAddr, spaceLink.Attrs().HardwareAddr
	for i := range w.transit.root {
		rootAddr, spaceAddr := w.transit.root[i].Addr(), w.transit.space[i].Addr()
		// The root end learns the space end; the space end learns the root
		// end (its default gateway).
		if err := netlink.NeighSet(&netlink.Neigh{
			LinkIndex: rootLink.Attrs().Index, State: unix.NUD_PERMANENT,
			IP: net.IP(spaceAddr.AsSlice()), HardwareAddr: spaceMAC,
		}); err != nil {
			return fmt.Errorf("root end for %v: %w", spaceAddr, err)
		}
		if err := h.NeighSet(&netlink.Neigh{
			LinkIndex: spaceLink.Attrs().Index, State: unix.NUD_PERMANENT,
			IP: net.IP(rootAddr.AsSlice()), HardwareAddr: rootMAC,
		}); err != nil {
			return fmt.Errorf("space end for %v: %w", rootAddr, err)
		}
	}
	return nil
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
