package reality

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// closeNotifyWait bounds how long Close waits to send TLS's close_notify
// to a peer that isn't reading.
const closeNotifyWait = time.Second

// link is one end of a reality link: frames over an established TLS
// connection (uTLS's on the dialing end, REALITY's on the listening end).
type link struct {
	tls  net.Conn
	tcp  net.Conn
	peer transport.Identity // on the listening end

	shaping atomic.Pointer[transport.Shaping]
	meter   *transport.SendMeter

	rmu sync.Mutex
	r   *bufio.Reader

	wmu  sync.Mutex
	wbuf []byte

	once    sync.Once
	done    chan struct{}
	cause   error // set before done closes
	onClose func(*link)
}

var _ transport.Link = (*link)(nil)

func newLink(tlsConn, tcp net.Conn, s transport.Shaping, meter *transport.SendMeter, onClose func(*link)) *link {
	l := &link{
		tls:     tlsConn,
		tcp:     tcp,
		meter:   meter,
		r:       bufio.NewReaderSize(tlsConn, maxPlaintext),
		done:    make(chan struct{}),
		onClose: onClose,
	}
	l.shaping.Store(&s)
	return l
}

func (l *link) setShaping(s transport.Shaping) { l.shaping.Store(&s) }

func (l *link) ReadPacket(p []byte) (int, error) {
	l.rmu.Lock()
	defer l.rmu.Unlock()
	if l.isClosed() {
		return 0, l.closedErr()
	}
	n, err := readPacket(l.r, p)
	switch {
	case err == nil, errors.Is(err, io.ErrShortBuffer):
		return n, err
	case l.isClosed():
		return 0, l.closedErr()
	}
	l.close(err)
	return 0, l.closedErr()
}

func (l *link) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.isClosed() {
		return l.closedErr()
	}
	l.wbuf = appendUnit(l.wbuf[:0], p, l.shaping.Load().Padding)
	if _, err := l.tls.Write(l.wbuf); err != nil {
		if !l.isClosed() {
			l.close(err)
		}
		return l.closedErr()
	}
	if l.meter != nil {
		pad := len(l.wbuf) - frameHeader - len(p)
		l.meter.Sent(1, len(p), pad, len(l.wbuf)+recordOverhead)
	}
	return nil
}

func (l *link) Close() error {
	l.close(nil)
	return nil
}

// close closes the link once, with cause: nil when closed on purpose.
func (l *link) close(cause error) {
	l.once.Do(func() {
		l.cause = cause
		close(l.done)
		_ = l.tcp.SetWriteDeadline(time.Now().Add(closeNotifyWait))
		_ = l.tls.Close()
		_ = l.tcp.Close()
		if l.onClose != nil {
			l.onClose(l)
		}
	})
}

func (l *link) isClosed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *link) closedErr() error {
	<-l.done
	return transport.ClosedError(l.cause)
}

func (l *link) LocalAddr() net.Addr  { return l.tcp.LocalAddr() }
func (l *link) RemoteAddr() net.Addr { return l.tcp.RemoteAddr() }
