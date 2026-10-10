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
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Dialer opens udp links, each on its own connected socket.
type Dialer struct {
	// Control, if set, is called on each link's socket before it connects,
	// e.g. to set a firewall mark so the socket bypasses the tunnel.
	Control func(network, address string, c syscall.RawConn) error
}

// Dial implements transport.Dialer. There is no handshake: Dial only opens
// the socket, and the listener learns of the link from its first packet. A
// redial with the same credential carries on the listener's existing link.
func (d *Dialer) Dial(ctx context.Context, endpoint string, cfg transport.LinkConfig) (transport.Link, error) {
	if err := cfg.Credential.Validate(); err != nil {
		return nil, err
	}
	nd := net.Dialer{Control: d.Control}
	conn, err := nd.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("udp: dial: %w", err)
	}
	secret := cfg.Credential.Secret
	return &dialLink{
		conn:   conn,
		outID:  connIDFor(secret, toListener),
		inID:   connIDFor(secret, toDialer),
		sender: newSenderID(),
		send:   newAEAD(secret, toListener),
		recv:   newAEAD(secret, toDialer),
		rbuf:   make([]byte, maxDatagram+1),
	}, nil
}

// dialLink is the dialer's end of a link.
type dialLink struct {
	conn   net.Conn
	outID  ConnID
	inID   ConnID
	sender senderID
	send   cipher.AEAD
	recv   cipher.AEAD

	counter atomic.Uint64
	closed  atomic.Bool

	readMu  sync.Mutex
	rbuf    []byte
	senders senderWindows // a restarted listener is a new sender
}

func (dl *dialLink) ReadPacket(p []byte) (int, error) {
	dl.readMu.Lock()
	defer dl.readMu.Unlock()
	for {
		n, err := dl.conn.Read(dl.rbuf)
		if err != nil {
			if dl.closed.Load() || errors.Is(err, net.ErrClosed) {
				return 0, transport.ClosedError(nil)
			}
			var netErr net.Error
			if errors.As(err, &netErr) {
				continue // e.g. ECONNREFUSED from an ICMP error: the listener may come back
			}
			return 0, fmt.Errorf("udp: read: %w", err)
		}
		d := dl.rbuf[:n]
		if id, ok := connIDOf(d); !ok || id != dl.inID {
			continue
		}
		// Opened in place: nothing else needs the datagram.
		sender, counter, packet, err := open(d[clearSize:clearSize], dl.recv, d)
		if err != nil {
			continue
		}
		if fresh, _ := dl.senders.accept(sender, counter); !fresh {
			continue
		}
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}

func (dl *dialLink) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	if dl.closed.Load() {
		return transport.ClosedError(nil)
	}
	c := dl.counter.Add(1) - 1
	if c >= rejectAfterMessages {
		return transport.ClosedError(errors.New("udp: counter exhausted, redial"))
	}
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], dl.send, dl.outID, dl.sender, c, p)
	if _, err := dl.conn.Write(*bp); err != nil {
		if dl.closed.Load() {
			return transport.ClosedError(nil)
		}
		return fmt.Errorf("udp: write: %w", err)
	}
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
