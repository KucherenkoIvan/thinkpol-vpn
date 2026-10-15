package router

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/checksum"
)

// MaxPacket is the longest packet the router reads from the TUN and the
// largest MTU an egress takes. The overlay's MTU is always below it: a
// WireGuard message the path layer carries is at most path.MaxMessageSize,
// less WireGuard's own 32 bytes.
const MaxPacket = 8192

// readOffset is the headroom left in front of each packet read from the
// TUN: Linux TUNs with offloads put a virtio header there.
const readOffset = 16

// QueueLen is how many packets wait for an egress's WireGuard device before
// the router drops new ones for it.
const QueueLen = 512

// ErrClosed is returned by a closed router or egress.
var ErrClosed = errors.New("router: closed")

// Router moves packets between the TUN and the egresses' WireGuard
// devices. All its methods are safe for concurrent use.
type Router struct {
	tun   tun.Device
	table atomic.Pointer[compiled]

	mu       sync.Mutex
	egresses map[*Egress]struct{}
	closed   bool

	stop chan struct{} // closed by Close
	done chan struct{} // closed when the read loop exits
	// linkUp is signalled, coalesced, when the TUN reports its link up;
	// linkDown is set while its last report was down.
	linkUp   chan struct{}
	linkDown atomic.Bool

	c counters
}

// Counters are packet counts since the router started.
type Counters struct {
	Routed     uint64 // read from the TUN and queued on an egress
	Delivered  uint64 // written to the TUN by egresses (a failed write counts none)
	Forwarded  uint64 // of Delivered, for the internet: the node forwards them (Table.Forward)
	NotLocal   uint64 // decrypted by a WireGuard device for a destination not the node's own
	NoRoute    uint64 // nothing routes the destination, an overlay address no peer has, or a closed egress
	Blocked    uint64 // routed by a route without an egress
	Direct     uint64 // routed by a Direct route: a destination meant to go around the tunnel
	Malformed  uint64 // not an IPv4 or IPv6 packet
	TooLarge   uint64 // longer than MaxPacket, or than the WireGuard device's buffer
	QueueFull  uint64 // the egress's queue was full
	ReadErrors uint64 // the TUN failed a read
	Reflected  uint64 // read from the TUN from and for Local addresses and written back to it (Table.ReflectLocal)
	// ReflectFailed: to be reflected, but the TUN failed the write.
	ReflectFailed uint64
	// ForeignSource: read from the TUN with a source no peer accepts
	// from this node, so never handed to WireGuard: a link-local one
	// (the OS's own neighbour and multicast traffic on the TUN), or,
	// with Table.LocalSourcesOnly, any but a Local address.
	ForeignSource uint64
}

type counters struct {
	routed, delivered, forwarded, notLocal, noRoute, blocked, direct, malformed, tooLarge, queueFull, readErrors atomic.Uint64
	reflected, reflectFailed, foreignSource                                                                      atomic.Uint64
}

// New starts a router reading t, with an empty table: every packet is
// dropped until SetTable. The router owns t and closes it on Close.
func New(t tun.Device) *Router {
	r := &Router{
		tun:      t,
		egresses: make(map[*Egress]struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		linkUp:   make(chan struct{}, 1),
	}
	r.table.Store(&compiled{})
	go r.read()
	go func() {
		// A TUN blocks its own goroutines when nobody takes its events;
		// the router sets MTUs itself, and passes on only the link up.
		for ev := range t.Events() {
			if ev&tun.EventDown != 0 {
				r.linkDown.Store(true)
			}
			if ev&tun.EventUp != 0 {
				r.linkDown.Store(false)
				select {
				case r.linkUp <- struct{}{}:
				default:
				}
			}
		}
	}()
	return r
}

// LinkUp is signalled, coalesced, when the TUN reports its link up
// (tun.EventUp). Linux's TUN reports it when the link comes up and again
// on later changes of a running link (its MTU, say), so it says "check
// the interface", not "it was down".
func (r *Router) LinkUp() <-chan struct{} { return r.linkUp }

// LinkDown reports whether the TUN's last link report was down (false
// before any). Linux's TUN may report a quick bounce as up alone, and a
// link that stays down only within a second.
func (r *Router) LinkDown() bool { return r.linkDown.Load() }

// SetTable replaces the routing table; packets already queued on an egress
// stay there. It fails, changing nothing, on an invalid prefix, a prefix
// routed twice in one list, or an egress of another router.
func (r *Router) SetTable(t Table) error {
	c, err := r.compile(t)
	if err != nil {
		return err
	}
	r.table.Store(c)
	return nil
}

// Counters returns the router's packet counts.
func (r *Router) Counters() Counters {
	return Counters{
		Routed:     r.c.routed.Load(),
		Delivered:  r.c.delivered.Load(),
		Forwarded:  r.c.forwarded.Load(),
		NotLocal:   r.c.notLocal.Load(),
		NoRoute:    r.c.noRoute.Load(),
		Blocked:    r.c.blocked.Load(),
		Direct:     r.c.direct.Load(),
		Malformed:  r.c.malformed.Load(),
		TooLarge:   r.c.tooLarge.Load(),
		QueueFull:  r.c.queueFull.Load(),
		ReadErrors: r.c.readErrors.Load(),
		Reflected:  r.c.reflected.Load(),

		ReflectFailed: r.c.reflectFailed.Load(),
		ForeignSource: r.c.foreignSource.Load(),
	}
}

// Close closes the TUN and every egress, and waits for the read loop.
func (r *Router) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.done
		return nil
	}
	r.closed = true
	close(r.stop)
	egresses := make([]*Egress, 0, len(r.egresses))
	for e := range r.egresses {
		egresses = append(egresses, e)
	}
	r.mu.Unlock()

	err := r.tun.Close()
	for _, e := range egresses {
		_ = e.Close()
	}
	<-r.done
	return err
}

func (r *Router) read() {
	defer close(r.done)
	batch := max(r.tun.BatchSize(), 1)
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, readOffset+MaxPacket)
	}
	failures := 0
	for {
		n, err := r.tun.Read(bufs, sizes, readOffset)
		for i := range n {
			r.route(bufs[i][:readOffset+sizes[i]])
		}
		if err == nil {
			failures = 0
			continue
		}
		select {
		case <-r.stop:
			return
		default:
		}
		if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return
		}
		r.c.readErrors.Add(1)
		if errors.Is(err, tun.ErrTooManySegments) {
			continue
		}
		// Back off so a persistently failing TUN doesn't spin.
		failures = min(failures+1, 8)
		select {
		case <-r.stop:
			return
		case <-time.After(time.Millisecond << failures):
		}
	}
}

// route classifies the packet at buf[readOffset:]; the headroom in front
// of it lets a reflected packet go back to the TUN with checksums fixed.
func (r *Router) route(buf []byte) {
	p := buf[readOffset:]
	src, dst, ok := addresses(p)
	if !ok {
		r.c.malformed.Add(1)
		return
	}
	c := r.table.Load()
	if !c.sendsFrom(src) {
		r.c.foreignSource.Add(1)
		return
	}
	// Both ends local: the OS talking to itself. Anything else for a
	// local address (a source injected on the TUN, a peer's address) is
	// never delivered as if WireGuard had authenticated it.
	if c.reflect && c.local[dst] && c.local[src] {
		// One packet at a time: a TUN with offloads may coalesce a batch
		// in place, and these are rare (the node talking to itself).
		checksum.Fix(p)
		if _, err := r.tun.Write([][]byte{buf}, readOffset); err != nil {
			r.c.reflectFailed.Add(1)
		} else {
			r.c.reflected.Add(1)
		}
		return
	}
	e, ok := c.classify(dst)
	switch {
	case !ok:
		r.c.noRoute.Add(1)
	case e == nil:
		r.c.blocked.Add(1)
	case e == direct:
		r.c.direct.Add(1)
	case len(p) > MaxPacket:
		r.c.tooLarge.Add(1)
	default:
		e.enqueue(p)
	}
}

// Egresses reports on every egress, by name.
func (r *Router) Egresses() []EgressStatus {
	r.mu.Lock()
	out := make([]EgressStatus, 0, len(r.egresses))
	for e := range r.egresses {
		out = append(out, e.Status())
	}
	r.mu.Unlock()
	slices.SortFunc(out, func(a, b EgressStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// addresses reads the source and destination addresses of an IPv4 or
// IPv6 packet.
func addresses(p []byte) (src, dst netip.Addr, ok bool) {
	if len(p) == 0 {
		return src, dst, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) >= 20 {
			return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
		}
	case 6:
		if len(p) >= 40 {
			return netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40])), true
		}
	}
	return src, dst, false
}

// destination reads the destination address of an IPv4 or IPv6 packet.
func destination(p []byte) (netip.Addr, bool) {
	if len(p) == 0 {
		return netip.Addr{}, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) >= 20 {
			return netip.AddrFrom4([4]byte(p[16:20])), true
		}
	case 6:
		if len(p) >= 40 {
			return netip.AddrFrom16([16]byte(p[24:40])), true
		}
	}
	return netip.Addr{}, false
}
