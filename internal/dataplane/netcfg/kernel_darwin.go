package netcfg

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// osKernel is the kernel through a PF_ROUTE socket (routes), sysctl RIB
// dumps (golang.org/x/net/route) and interface ioctls. One fallback execs
// a tool: removing an IPv6 address (`ifconfig <if> inet6 <addr> -alias`),
// because the size of the in6_ifreq that SIOCDIFADDR_IN6 takes isn't
// stable across macOS releases.
type osKernel struct {
	mu  sync.Mutex
	rt  int // routing socket for writes; its read side is shut
	seq atomic.Int32
}

func openKernel() (*osKernel, error) {
	fd, err := socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("netcfg: routing socket: %w", err)
	}
	// Writes only: every routing change would otherwise queue here.
	_ = unix.Shutdown(fd, unix.SHUT_RD)
	return &osKernel{rt: fd}, nil
}

// socket opens a socket that exec'd children don't inherit (macOS has no
// SOCK_CLOEXEC; ForkLock keeps a fork from happening in between).
func socket(family, typ, proto int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(family, typ, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return fd, err
}

func (k *osKernel) close() error { return unix.Close(k.rt) }

func (k *osKernel) routes() ([]kroute, error) {
	b, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return nil, err
	}
	var out []kroute
	for _, m := range msgs {
		if rm, ok := m.(*route.RouteMessage); ok {
			if r, ok := kernelRoute(rm); ok {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (k *osKernel) add(r kroute) error {
	return k.write(routeMessage(unix.RTM_ADD, r, int(k.seq.Add(1))))
}
func (k *osKernel) del(r kroute) error {
	return k.write(routeMessage(unix.RTM_DELETE, r, int(k.seq.Add(1))))
}

func (k *osKernel) change(r kroute) error {
	return k.write(routeMessage(unix.RTM_CHANGE, r, int(k.seq.Add(1))))
}

func (k *osKernel) write(m *route.RouteMessage) error {
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_, err = unix.Write(k.rt, b)
	return err
}

// routeMessage is the routing message that adds or deletes r, as route(8)
// writes it: a host route without a netmask, an IPv6 link-local gateway
// with its zone embedded in the address (the KAME form the kernel
// keeps), an interface route with a link-layer gateway naming its index.
func routeMessage(typ int, r kroute, seq int) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = inetAddr(r.dst.Addr(), 0)
	switch {
	case r.gw.IsValid():
		addrs[unix.RTAX_GATEWAY] = inetAddr(r.gw, r.gwZone)
	case r.link != 0:
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: r.link}
	}
	if r.dst.Bits() != r.dst.Addr().BitLen() {
		addrs[unix.RTAX_NETMASK] = inetAddr(maskOf(r.dst), 0)
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   r.flags,
		Index:   r.index,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
}

func inetAddr(a netip.Addr, zone int) route.Addr {
	if a.Is4() {
		return &route.Inet4Addr{IP: a.As4()}
	}
	ip := a.As16()
	if zone != 0 && (a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast()) {
		ip[2], ip[3] = byte(zone>>8), byte(zone)
	}
	return &route.Inet6Addr{IP: ip}
}

// maskOf is p's netmask as an address.
func maskOf(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		m := ^uint32(0) << (32 - p.Bits())
		if p.Bits() == 0 {
			m = 0
		}
		return netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)})
	}
	var b [16]byte
	for i := 0; i < p.Bits(); i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom16(b)
}

// kernelRoute reads a routing message's route; false for one that isn't
// IPv4 or IPv6, or whose netmask isn't a prefix.
func kernelRoute(m *route.RouteMessage) (kroute, bool) {
	if len(m.Addrs) <= unix.RTAX_NETMASK {
		return kroute{}, false
	}
	var dst netip.Addr
	switch a := m.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		dst = netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		dst = netip.AddrFrom16(a.IP)
	default:
		return kroute{}, false
	}
	n := dst.BitLen()
	switch mask := m.Addrs[unix.RTAX_NETMASK].(type) {
	case *route.Inet4Addr:
		var ok bool
		if n, ok = maskBits(mask.IP[:]); !ok {
			return kroute{}, false
		}
	case *route.Inet6Addr:
		var ok bool
		if n, ok = maskBits(mask.IP[:]); !ok {
			return kroute{}, false
		}
	case nil:
		if m.Flags&unix.RTF_HOST == 0 && dst.IsUnspecified() {
			n = 0
		}
	default:
		return kroute{}, false
	}
	if n > dst.BitLen() {
		return kroute{}, false
	}
	r := kroute{dst: netip.PrefixFrom(dst, n).Masked(), index: m.Index, flags: m.Flags}
	switch g := m.Addrs[unix.RTAX_GATEWAY].(type) {
	case *route.Inet4Addr:
		r.gw = netip.AddrFrom4(g.IP)
	case *route.Inet6Addr:
		r.gw, r.gwZone = netip.AddrFrom16(g.IP), g.ZoneID
	case *route.LinkAddr:
		r.link = g.Index
	}
	return r, true
}

// maskBits is the prefix length of a netmask; the kernel may cut its
// trailing zero bytes off.
func maskBits(b []byte) (int, bool) {
	n, ended := 0, false
	for _, x := range b {
		ones := bits.LeadingZeros8(^x)
		if ended && x != 0 || ones < 8 && x != byte(0xff<<(8-ones)) {
			return 0, false
		}
		n += ones
		ended = ended || ones < 8
	}
	return n, true
}

func (k *osKernel) interfaces() ([]kifc, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]kifc, 0, len(ifcs))
	for _, i := range ifcs {
		out = append(out, kifc{
			name: i.Name, index: i.Index, mtu: i.MTU,
			up: i.Flags&net.FlagUp != 0, p2p: i.Flags&net.FlagPointToPoint != 0, loopback: i.Flags&net.FlagLoopback != 0,
		})
	}
	return out, nil
}

func (k *osKernel) addrs(index int) ([]netip.Prefix, error) {
	i, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoInterface, err)
	}
	as, err := i.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range as {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return out, nil
}

// ifaliasreq is SIOCAIFADDR's argument; on a point-to-point interface
// dst is the peer, here the address itself.
type ifaliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	Dst  unix.RawSockaddrInet4
	Mask unix.RawSockaddrInet4
}

// in6Aliasreq is SIOCAIFADDR_IN6's argument (struct in6_aliasreq).
type in6Aliasreq struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet6
	Dst      unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    int32
	Lifetime struct {
		Expire, Preferred int64
		Vltime, Pltime    uint32
	}
}

// ifreqAddr is SIOCDIFADDR's argument; ifreqFlags SIOC[GS]IFFLAGS'.
type ifreqAddr struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [14]byte
}

const (
	// siocAIFADDRIn6 is _IOW('i', 26, struct in6_aliasreq).
	siocAIFADDRIn6 = 0x80000000 | uint(unsafe.Sizeof(in6Aliasreq{}))<<16 | 'i'<<8 | 26
	in6IFFNoDAD    = 0x20       // IN6_IFF_NODAD: an overlay address is usable at once
	nd6Infinite    = 0xffffffff // ND6_INFINITE_LIFETIME
)

func sockaddr4(a netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Addr: a.As4()}
}

func sockaddr6(a netip.Addr) unix.RawSockaddrInet6 {
	return unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: a.As16()}
}

func ifname(name string) (b [unix.IFNAMSIZ]byte, err error) {
	if len(name) >= unix.IFNAMSIZ {
		return b, fmt.Errorf("interface name %q too long", name)
	}
	copy(b[:], name)
	return b, nil
}

// ioctl runs req on a socket of family. x/sys has libSystem wrappers for a
// few interface ioctls only (the MTU's), not for the address and flag
// ones, so this one is a direct syscall, which still works on macOS.
func ioctl(family int, req uint, arg unsafe.Pointer) error {
	fd, err := socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	//nolint:staticcheck // SYS_IOCTL: no wrapper for these requests (see above)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

func (k *osKernel) addAddr(ifc kifc, p netip.Prefix) error {
	name, err := ifname(ifc.name)
	if err != nil {
		return err
	}
	mask := maskOf(p)
	if p.Addr().Is4() {
		req := ifaliasreq{Name: name, Addr: sockaddr4(p.Addr()), Mask: sockaddr4(mask)}
		if ifc.p2p {
			req.Dst = sockaddr4(p.Addr())
		}
		return ioctl(unix.AF_INET, unix.SIOCAIFADDR, unsafe.Pointer(&req))
	}
	req := in6Aliasreq{Name: name, Addr: sockaddr6(p.Addr()), Mask: sockaddr6(mask), Flags: in6IFFNoDAD}
	req.Lifetime.Vltime, req.Lifetime.Pltime = nd6Infinite, nd6Infinite
	return ioctl(unix.AF_INET6, siocAIFADDRIn6, unsafe.Pointer(&req))
}

func (k *osKernel) delAddr(ifc kifc, p netip.Prefix) error {
	if p.Addr().Is4() {
		name, err := ifname(ifc.name)
		if err != nil {
			return err
		}
		req := ifreqAddr{Name: name, Addr: sockaddr4(p.Addr())}
		return ioctl(unix.AF_INET, unix.SIOCDIFADDR, unsafe.Pointer(&req))
	}
	out, err := exec.Command("/sbin/ifconfig", ifc.name, "inet6", p.Addr().String(), "-alias").CombinedOutput()
	if err != nil {
		if _, ierr := net.InterfaceByName(ifc.name); ierr != nil {
			return errNoInterface
		}
		return fmt.Errorf("ifconfig %s inet6 %s -alias: %w: %s", ifc.name, p.Addr(), err, out)
	}
	return nil
}

func (k *osKernel) setMTU(name string, mtu int) error {
	n, err := ifname(name)
	if err != nil {
		return err
	}
	fd, err := socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.IoctlSetIfreqMTU(fd, &unix.IfreqMTU{Name: n, MTU: int32(mtu)})
}

func (k *osKernel) setUp(name string, up bool) error {
	n, err := ifname(name)
	if err != nil {
		return err
	}
	req := ifreqFlags{Name: n}
	if err := ioctl(unix.AF_INET, unix.SIOCGIFFLAGS, unsafe.Pointer(&req)); err != nil {
		return err
	}
	if up {
		req.Flags |= unix.IFF_UP
	} else {
		req.Flags &^= unix.IFF_UP
	}
	return ioctl(unix.AF_INET, unix.SIOCSIFFLAGS, unsafe.Pointer(&req))
}

// watchBuffer is the subscription's receive buffer: an Apply of tens of
// thousands of routes floods it, which is still only a change (ENOBUFS
// signals too).
const watchBuffer = 4 << 20

func (k *osKernel) watch(ctx context.Context) (<-chan struct{}, error) {
	fd, err := socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, watchBuffer)
	// Reads wake up now and then to notice ctx ending.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	out := make(chan struct{}, 1)
	signal := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	go func() {
		defer close(out)
		defer func() { _ = unix.Close(fd) }()
		buf := make([]byte, 16<<10)
		for ctx.Err() == nil {
			n, err := unix.Read(fd, buf)
			switch {
			case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.ENOBUFS):
				signal() // events were lost: assume they mattered
				continue
			case err != nil:
				return
			}
			msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
			if err != nil {
				signal()
				continue
			}
			for _, m := range msgs {
				if relevant(m) {
					signal()
					break
				}
			}
		}
	}()
	return out, nil
}

// relevant reports whether a routing message may call for an Apply: an
// interface that changed or whose addresses changed (its subnets), an
// unscoped route that came, went or changed, but for thinkpol's own adds,
// or a scoped route of thinkpol's that went.
// The kernel's clones (neighbours, host caches) come and go all the time
// and never matter.
func relevant(m route.Message) bool {
	switch m := m.(type) {
	case *route.InterfaceMessage, *route.InterfaceAddrMessage:
		return true
	case *route.RouteMessage:
		switch m.Type {
		case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		default:
			return false
		}
		if m.Flags&unix.RTF_WASCLONED != 0 {
			return false
		}
		if m.Flags&unix.RTF_IFSCOPE != 0 {
			// Only a thinkpol route's going matters: another's scoped
			// routes never compete with the tunnel's.
			return m.Type == unix.RTM_DELETE && m.Flags&routeFlag != 0
		}
		return m.Type != unix.RTM_ADD || m.Flags&routeFlag == 0
	}
	return false
}

// getSeq numbers DefaultInterface's lookups.
var getSeq atomic.Int32

// DefaultInterface is the interface of the family's unscoped default route
// (the primary network service's): what the links' sockets are bound to
// on macOS (IP_BOUND_IF), asked of the kernel per call (RTM_GET, as
// `route -n get default` does), so a socket opened after the network
// changed follows it. ErrNoDefaultRoute when the family has none.
func DefaultInterface(f Family) (name string, index int, err error) {
	fd, err := socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return "", 0, err
	}
	unspecified := netip.IPv4Unspecified()
	if f == IPv6 {
		unspecified = netip.IPv6Unspecified()
	}
	// Replies go to every routing socket of the process: each lookup
	// takes only its own (sequence number and family). A flood of
	// routing messages can overflow the socket (ENOBUFS) or hold the
	// reply up: the question is asked again, a few times.
	buf := make([]byte, 4096)
	for range 3 {
		seq := int(getSeq.Add(1))
		m := routeMessage(unix.RTM_GET, kroute{dst: netip.PrefixFrom(unspecified, 0), flags: unix.RTF_UP | unix.RTF_GATEWAY}, seq)
		b, err := m.Marshal()
		if err != nil {
			return "", 0, err
		}
		if _, err := unix.Write(fd, b); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return "", 0, fmt.Errorf("%w (%v)", ErrNoDefaultRoute, f)
			}
			return "", 0, err
		}
		deadline := time.Now().Add(time.Second)
	read:
		for time.Now().Before(deadline) {
			n, err := unix.Read(fd, buf)
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.ENOBUFS), errors.Is(err, unix.EAGAIN):
				break read // lost or late: ask again
			case err != nil:
				return "", 0, err
			}
			msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
			if err != nil {
				continue
			}
			for _, msg := range msgs {
				rm, ok := msg.(*route.RouteMessage)
				if !ok || rm.Type != unix.RTM_GET || rm.Seq != seq || rm.ID != uintptr(os.Getpid()) {
					continue
				}
				if rm.Err != nil {
					return "", 0, rm.Err
				}
				r, ok := kernelRoute(rm)
				if ok && FamilyOf(r.dst.Addr()) != f {
					continue
				}
				if !ok || r.dst.Bits() != 0 || !usable(r) || r.flags&routeFlag != 0 {
					return "", 0, fmt.Errorf("%w (%v)", ErrNoDefaultRoute, f)
				}
				i, err := net.InterfaceByIndex(r.index)
				if err != nil {
					return "", 0, err
				}
				return i.Name, i.Index, nil
			}
		}
	}
	return "", 0, fmt.Errorf("netcfg: no answer from the routing socket about the %v default route", f)
}
