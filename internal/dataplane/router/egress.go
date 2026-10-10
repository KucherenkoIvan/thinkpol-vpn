package router

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// egressBatch is how many packets an egress hands its WireGuard device per
// read.
const egressBatch = 32

// Egress is the virtual TUN of one WireGuard device: it reads the packets
// the router queued for it, and its writes go to the router's TUN. It
// implements tun.Device; the WireGuard device owns it and closes it.
type Egress struct {
	r     *Router
	name  string
	queue chan *[]byte
	mtu   atomic.Int32

	emu    sync.Mutex // events against Close
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

var _ tun.Device = (*Egress)(nil)

// NewEgress adds an egress named name (for status and logs) whose WireGuard
// device sees an MTU of mtu. Route destinations to it with SetTable.
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
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

func (e *Egress) enqueue(p []byte) {
	b := packets.Get().(*[]byte)
	*b = append((*b)[:0], p...)
	select {
	case e.queue <- b:
		e.r.c.routed.Add(1)
	default:
		packets.Put(b)
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
			e.r.c.tooLarge.Add(1)
		} else {
			sizes[n] = copy(bufs[n][offset:], *p)
			n++
		}
		packets.Put(p)
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

// Write implements tun.Device: the packets go to the router's TUN.
func (e *Egress) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-e.closed:
		return 0, os.ErrClosed
	default:
	}
	n, err := e.r.tun.Write(bufs, offset)
	e.r.c.delivered.Add(uint64(n))
	return n, err
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
				packets.Put(p)
			default:
				return
			}
		}
	})
	return nil
}
