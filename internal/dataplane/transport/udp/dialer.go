package udp

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Dial implements transport.Dialer: each link gets its own connected
// socket. There is no handshake: Dial only opens the socket, and the
// listener learns of the link from its first packet. A redial with the same
// credential carries on the listener's existing link.
func (t *Transport) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("udp: dial %s: %w", endpoint, err)
	}
	if err := t.CheckEndpoint(endpoint, cfg); err != nil {
		return nil, err
	}
	nd := net.Dialer{Control: t.control}
	conn, err := nd.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("udp: dial: %w", err)
	}
	secret := cfg.Credential
	return &dialLink{
		t:       t,
		conn:    conn,
		secret:  secret,
		out:     &rotatingID{secret: secret, dir: toListener},
		sender:  newSenderID(t.now()),
		send:    newAEAD(secret, toListener),
		recv:    newAEAD(secret, toDialer),
		padding: cfg.Shaping.Padding,
		rbuf:    make([]byte, maxDatagram+1),
	}, nil
}

// dialLink is the dialer's end of a link.
type dialLink struct {
	t       *Transport
	conn    net.Conn
	secret  []byte
	out     *rotatingID
	sender  senderID
	send    cipher.AEAD
	recv    cipher.AEAD
	padding transport.Padding

	counter  atomic.Uint64
	closed   atomic.Bool
	counters counters
	meter    transport.SendMeter

	readMu  sync.Mutex
	rbuf    []byte
	pending []byte  // frames of the last datagram not yet read, in rbuf
	senders senders // a restarted listener is a new sender
	in      idWindow
}

// Sent reports what the link sent and what its padding cost.
func (dl *dialLink) Sent() transport.SendStats { return dl.meter.Stats() }

// Counters reports what the link dropped and why.
func (dl *dialLink) Counters() Counters { return dl.counters.snapshot() }

func (dl *dialLink) ReadPacket(p []byte) (int, error) {
	dl.readMu.Lock()
	defer dl.readMu.Unlock()
	var b backoff
	for {
		if packet, rest := nextFrame(dl.pending); packet != nil {
			dl.pending = rest
			if len(packet) > len(p) {
				return 0, io.ErrShortBuffer
			}
			return copy(p, packet), nil
		}
		n, err := dl.conn.Read(dl.rbuf)
		if err != nil {
			if dl.closed.Load() || errors.Is(err, net.ErrClosed) {
				return 0, transport.ClosedError(nil)
			}
			var netErr net.Error
			if errors.As(err, &netErr) {
				b.wait() // e.g. ECONNREFUSED from an ICMP error: the listener may come back
				continue
			}
			_ = dl.Close()
			return 0, transport.ClosedError(fmt.Errorf("udp: read: %w", err))
		}
		b.reset()
		dl.pending = dl.receive(dl.rbuf[:n])
	}
}

// receive returns the frames of an authenticated datagram, or nil.
func (dl *dialLink) receive(d []byte) []byte {
	now := dl.t.now()
	id, ok := idOf(d)
	if !ok || !dl.in.recognises(dl.secret, toDialer, epochOf(now), id) {
		dl.counters.unauthenticated.Add(1)
		return nil
	}
	// Opened in place: nothing else needs the datagram.
	o, err := open(d[clearSize:clearSize], dl.recv, d)
	switch {
	case err != nil:
		dl.counters.unauthenticated.Add(1)
		return nil
	case !o.fresh(now):
		dl.counters.staleTimestamp.Add(1)
		return nil
	}
	switch dl.senders.admit(o.sender, o.counter, now) {
	case dropReplay:
		dl.counters.replayed.Add(1)
		return nil
	case dropStale:
		dl.counters.staleSender.Add(1)
		return nil
	}
	dl.counters.received(o.packets)
	return o.frames
}

func (dl *dialLink) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	if dl.closed.Load() {
		return transport.ClosedError(nil)
	}
	now := dl.t.now()
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], dl.send, dl.out.at(epochOf(now)), dl.sender, now, dl.counter.Add(1)-1, p, dl.padding)
	if _, err := dl.conn.Write(*bp); err != nil {
		if dl.closed.Load() {
			return transport.ClosedError(nil)
		}
		return fmt.Errorf("udp: write: %w", err)
	}
	dl.meter.Sent(1, len(p), len(*bp)-Overhead-len(p), len(*bp))
	return nil
}

func (dl *dialLink) Close() error {
	if dl.closed.Swap(true) {
		return nil
	}
	return dl.conn.Close()
}

func (dl *dialLink) LocalAddr() net.Addr  { return dl.conn.LocalAddr() }
func (dl *dialLink) RemoteAddr() net.Addr { return dl.conn.RemoteAddr() }
