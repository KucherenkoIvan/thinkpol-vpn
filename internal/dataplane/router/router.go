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

	c counters
}

// Counters are packet counts since the router started.
type Counters struct {
	Routed     uint64 // read from the TUN and queued on an egress
	Delivered  uint64 // written to the TUN by egresses
	NotLocal   uint64 // decrypted by a WireGuard device for a destination not the node's own
	NoRoute    uint64 // nothing routes the destination, an overlay address no peer has, or a closed egress
	Blocked    uint64 // routed by a route without an egress
	Direct     uint64 // routed by a Direct route: a destination meant to go around the tunnel
	Malformed  uint64 // not an IPv4 or IPv6 packet
	TooLarge   uint64 // longer than MaxPacket, or than the WireGuard device's buffer
	QueueFull  uint64 // the egress's queue was full
	ReadErrors uint64 // the TUN failed a read
}

type counters struct {
	routed, delivered, notLocal, noRoute, blocked, direct, malformed, tooLarge, queueFull, readErrors atomic.Uint64
}

// New starts a router reading t, with an empty table: every packet is
// dropped until SetTable. The router owns t and closes it on Close.
func New(t tun.Device) *Router {
	r := &Router{
		tun:      t,
		egresses: make(map[*Egress]struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	r.table.Store(&compiled{})
	go r.read()
	go func() {
		// A TUN blocks its own goroutines when nobody takes its events;
		// the router sets MTUs itself and has no use for them.
		for range t.Events() {
		}
	}()
	return r
}

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
		NotLocal:   r.c.notLocal.Load(),
		NoRoute:    r.c.noRoute.Load(),
		Blocked:    r.c.blocked.Load(),
		Direct:     r.c.direct.Load(),
		Malformed:  r.c.malformed.Load(),
		TooLarge:   r.c.tooLarge.Load(),
		QueueFull:  r.c.queueFull.Load(),
		ReadErrors: r.c.readErrors.Load(),
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
			r.route(bufs[i][readOffset : readOffset+sizes[i]])
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

func (r *Router) route(p []byte) {
	dst, ok := destination(p)
	if !ok {
		r.c.malformed.Add(1)
		return
	}
	e, ok := r.table.Load().classify(dst)
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
