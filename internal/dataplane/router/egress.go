package router

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// egressBatch is how many packets an egress hands its WireGuard device per
// read.
const egressBatch = 32

// Egress is the virtual TUN of one WireGuard device: it reads the packets
// the router queued for it, and its writes go to the router's TUN, for the
// node's own addresses only. It implements tun.Device; the WireGuard device
// owns it and closes it.
type Egress struct {
	r     *Router
	name  string
	queue chan *[]byte
	mtu   atomic.Int32
	pool  sync.Pool // packet buffers with room for an MTU

	emu    sync.Mutex // events against Close
	events chan tun.Event
	closed chan struct{}
	isDone atomic.Bool
	once   sync.Once

	routed, delivered, notLocal, queueFull, tooLarge atomic.Uint64
}

var _ tun.Device = (*Egress)(nil)

// EgressStatus is what an egress did since it was added.
type EgressStatus struct {
	Name      string
	MTU       int
	Queued    int    // packets waiting for the WireGuard device now
	Routed    uint64 // queued for the WireGuard device
	Delivered uint64 // decrypted by the device and written to the TUN
	NotLocal  uint64 // decrypted for a destination not the node's own, dropped
	QueueFull uint64 // dropped: the device fell behind
	TooLarge  uint64 // dropped: longer than the device's buffer
}

// NewEgress adds an egress named name, unique among the router's egresses,
// whose WireGuard device sees an MTU of mtu. Route destinations to it with
// SetTable.
func (r *Router) NewEgress(name string, mtu int) (*Egress, error) {
	if mtu <= 0 || mtu > MaxPacket {
		return nil, fmt.Errorf("router: egress %q: MTU %d out of range (1 to %d)", name, mtu, MaxPacket)
	}
	e := &Egress{
		r:      r,
		name:   name,
		queue:  make(chan *[]byte, QueueLen),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	e.mtu.Store(int32(mtu))
	e.pool.New = func() any {
		b := make([]byte, 0, e.mtu.Load())
		return &b
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	for other := range r.egresses {
		if other.name == name {
			return nil, fmt.Errorf("router: egress %q exists", name)
		}
	}
	r.egresses[e] = struct{}{}
	return e, nil
}

// SetMTU changes the MTU the egress's WireGuard device sees; it learns
// of it from an event.
func (e *Egress) SetMTU(mtu int) error {
	if mtu <= 0 || mtu > MaxPacket {
		return fmt.Errorf("router: egress %q: MTU %d out of range (1 to %d)", e.name, mtu, MaxPacket)
	}
	if int(e.mtu.Swap(int32(mtu))) == mtu {
		return nil
	}
	e.emu.Lock()
	defer e.emu.Unlock()
	select {
	case <-e.closed:
		return ErrClosed
	default:
	}
	select {
	case e.events <- tun.EventMTUUpdate:
	default: // one pending event is enough: the device reads MTU() then
	}
	return nil
}

// Status reports on the egress.
func (e *Egress) Status() EgressStatus {
	return EgressStatus{
		Name:      e.name,
		MTU:       int(e.mtu.Load()),
		Queued:    len(e.queue),
		Routed:    e.routed.Load(),
		Delivered: e.delivered.Load(),
		NotLocal:  e.notLocal.Load(),
		QueueFull: e.queueFull.Load(),
		TooLarge:  e.tooLarge.Load(),
	}
}

func (e *Egress) enqueue(p []byte) {
	if e.isDone.Load() {
		// Closed after the table was read: as if it had no route.
		e.r.c.noRoute.Add(1)
		return
	}
	b := e.pool.Get().(*[]byte)
	*b = append((*b)[:0], p...)
	select {
	case e.queue <- b:
		e.routed.Add(1)
		e.r.c.routed.Add(1)
	default:
		e.pool.Put(b)
		e.queueFull.Add(1)
		e.r.c.queueFull.Add(1)
	}
}

// Read implements tun.Device: it blocks until a packet is queued, then
// hands over as many queued packets as bufs hold.
func (e *Egress) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var first *[]byte
	select {
	case first = <-e.queue:
	case <-e.closed:
		return 0, os.ErrClosed
	}
	n := 0
	for p := first; ; {
		if len(*p) > len(bufs[n])-offset {
			e.tooLarge.Add(1)
			e.r.c.tooLarge.Add(1)
		} else {
			sizes[n] = copy(bufs[n][offset:], *p)
			n++
		}
		e.pool.Put(p)
		if n == len(bufs) {
			return n, nil
		}
		select {
		case p = <-e.queue:
		default:
			return n, nil
		}
	}
}

// Write implements tun.Device: packets for the node's own addresses go to
// the router's TUN, anything else is dropped and counted (NotLocal). It
// reports every packet as written.
func (e *Egress) Write(bufs [][]byte, offset int) (int, error) {
	if e.isDone.Load() {
		return 0, os.ErrClosed
	}
	local := e.r.table.Load().local
	out := bufs
	for i, b := range bufs {
		if dst, ok := destination(b[offset:]); !ok || !local[dst] {
			out = e.keepLocal(bufs[:i], bufs[i:], offset, local)
			break
		}
	}
	if len(out) == 0 {
		return len(bufs), nil
	}
	n, err := e.r.tun.Write(out, offset)
	e.delivered.Add(uint64(n))
	e.r.c.delivered.Add(uint64(n))
	if err != nil {
		return n, err
	}
	return len(bufs), nil
}

// keepLocal returns the local packets of kept and rest, counting the others.
func (e *Egress) keepLocal(kept, rest [][]byte, offset int, local map[netip.Addr]bool) [][]byte {
	out := make([][]byte, len(kept), len(kept)+len(rest))
	copy(out, kept)
	for _, b := range rest {
		if dst, ok := destination(b[offset:]); ok && local[dst] {
			out = append(out, b)
			continue
		}
		e.notLocal.Add(1)
		e.r.c.notLocal.Add(1)
	}
	return out
}

// MTU implements tun.Device.
func (e *Egress) MTU() (int, error) { return int(e.mtu.Load()), nil }

// Name implements tun.Device.
func (e *Egress) Name() (string, error) { return e.name, nil }

// Events implements tun.Device.
func (e *Egress) Events() <-chan tun.Event { return e.events }

// File implements tun.Device; an egress has no file.
func (e *Egress) File() *os.File { return nil }

// BatchSize implements tun.Device.
func (e *Egress) BatchSize() int { return egressBatch }

// Close implements tun.Device: the egress leaves the router, and packets
// still routed to it are dropped.
func (e *Egress) Close() error {
	e.once.Do(func() {
		e.isDone.Store(true)
		e.emu.Lock()
		close(e.closed)
		close(e.events)
		e.emu.Unlock()
		e.r.mu.Lock()
		delete(e.r.egresses, e)
		e.r.mu.Unlock()
		for {
			select {
			case p := <-e.queue:
				e.pool.Put(p)
			default:
				return
			}
		}
	})
	return nil
}
