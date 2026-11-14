package reality

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// spliceLinger is how long a splice whose one direction ended waits for
// data on the other, an idle timeout: a client that stays silent once the
// target closed would otherwise hold its connection, and the target's, for
// good, while an answer still flowing after the client's FIN isn't cut. A
// listener reads it at Listen.
var spliceLinger = 5 * time.Second

// spliceWriteTimeout bounds how long a splice's write waits without
// progress, nginx's send_timeout (between two successive writes, each
// that makes progress resetting it): a client that stops reading (a zero
// window its kernel keeps acknowledging) would otherwise hold its splice,
// and its slot, for good, while one that reads slowly isn't cut. A write
// past it closes both connections. A listener reads it at Listen.
var spliceWriteTimeout = 60 * time.Second

// mirror is a connection whose target was dialled at accept, before the
// ClientHello is read, as REALITY's own server does: every chunk read from
// the client goes on to the target as it arrives, and whatever the target
// sends, or its closing, reaches the client as it would from the site. A
// prober that stalls is answered when the target answers, not on a timer
// of the listener's. The hello either authenticates, and the target is
// handed to REALITY, or the mirror becomes a splice.
//
// The target's FIN, even before it sent anything, is passed on as a
// half-close: what the client still sends goes on to the target, and the
// target is watched on, so its reset (a site that closed whole, or ended
// its lingering close, being sent more) resets the client at once, as the
// site's own would, and a site still reading gets it all (REALITY's server
// closes both there). The client's FIN before its hello was whole closes
// both; once spliced, each side's FIN is passed on as a half-close. The
// target's reset, or a write to it failing on one, resets the client; any
// other error, and a write past spliceWriteTimeout, closes both.
type mirror struct {
	client, target *idleConn
	linger         time.Duration

	mu    sync.Mutex
	state mirrorState
	held  []byte // what the target sent after the hand-off, REALITY's to read

	toClientDone chan struct{} // closed once the target → client direction ended
	fromTarget   chan struct{} // closed once nothing reads the target any more
}

type mirrorState uint8

const (
	gathering mirrorState = iota // reading the hello, forwarding it
	spliced                      // joined to the target for good
	handedOff                    // the hello authenticated: REALITY's
)

func newPair(client, target net.Conn, linger, writeTimeout time.Duration) *mirror {
	return &mirror{
		client:       &idleConn{Conn: client, writeTimeout: writeTimeout},
		target:       &idleConn{Conn: target, writeTimeout: writeTimeout},
		linger:       linger,
		toClientDone: make(chan struct{}),
		fromTarget:   make(chan struct{}),
	}
}

func newMirror(client, target net.Conn, linger, writeTimeout time.Duration) *mirror {
	m := newPair(client, target, linger, writeTimeout)
	go m.copyFromTarget()
	return m
}

// heldBack is how much of a whole ClientHello gather keeps from the target
// until authenticate decided. Without it a fast target answers the hello
// before REALITY runs, and REALITY's target → client goroutine, finding
// the connection not yet authenticated, splices the target's real
// ServerHello to the authenticated client. REALITY's own MirrorConn
// writes the tail under its lock, so the target can't answer before
// REALITY took the connection, as with REALITY's own listener.
const heldBack = 1

// targetWriteError is a write to the target that failed while the hello
// was gathered.
type targetWriteError struct{ error }

func (e targetWriteError) Unwrap() error { return e.error }

// gather reads the first TLS record from the client, at most
// maxHelloRecord bytes, forwarding each chunk as it is read (whatever one
// read returns, so the target sees the client's segments as the site
// would, not a record header on its own), except the last heldBack bytes
// of a whole record. Once the record is whole, authenticate decides: true
// hands the connection off, the tail still held back; anything else
// forwards the tail and splices it. A client sending past its hello
// before any answer isn't a dialer (ours sends nothing more until the
// ServerHello) and is spliced, its hello decided all the same, so the
// caller can tell a replay. It returns the bytes read and the error
// that ended it, if any (reading from the client, or a
// targetWriteError); the target speaking or closing first splices too.
func (m *mirror) gather(authenticate func(record []byte) bool) (record []byte, authenticated bool, err error) {
	buf := make([]byte, recordHeaderSize+maxHelloRecord)
	have, need := 0, 0 // need: the whole record's length, once its header is read
	for {
		n, rerr := m.client.Read(buf[have:])
		m.mu.Lock()
		from := have
		have += n
		if m.state == gathering && need == 0 && have >= recordHeaderSize {
			size := int(buf[3])<<8 | int(buf[4])
			if buf[0] != recordTypeHandshake || size > maxHelloRecord {
				m.state = spliced
			}
			need = recordHeaderSize + size
		}
		whole := m.state == gathering && rerr == nil && need > 0 && have == need
		upto := have
		if whole {
			upto = max(from, have-heldBack)
		}
		readTimedOut := isTimeout(rerr)
		if werr := m.forward(buf[from:upto]); werr != nil && (rerr == nil || readTimedOut) {
			rerr, readTimedOut = werr, false
		}
		switch {
		case m.state != gathering:
		case readTimedOut:
			// The read deadline of whoever routes the connection: the
			// hello can no longer authenticate, and the connection stays
			// the target's, whose own timeouts end it.
			m.state = spliced
			rerr = nil
		case rerr != nil:
			m.state = spliced
		case need > 0 && have > need:
			// Decided for the caller's verdict (a replay is still one),
			// spliced whatever it says.
			authenticate(buf[:need])
			m.state = spliced
		case whole:
			// Decided under the lock: copyFromTarget waits, and a target
			// without the tail has nothing to answer yet.
			if authenticate(buf[:have]) {
				m.state = handedOff
			} else {
				m.state = spliced
				rerr = m.forward(buf[upto:have])
			}
		}
		state := m.state
		m.mu.Unlock()
		if state != gathering {
			return buf[:have], state == handedOff, rerr
		}
	}
}

func (m *mirror) forward(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if _, err := m.target.Write(b); err != nil {
		return targetWriteError{err}
	}
	return nil
}

// copyFromTarget is the target → client direction: while the hello is
// gathered, anything from the target, its FIN included, splices the
// connection; after a hand-off it stops, keeping what it read for
// REALITY.
func (m *mirror) copyFromTarget() {
	defer close(m.fromTarget)
	buf := make([]byte, 32<<10)
	n, err := m.target.Read(buf)
	m.mu.Lock()
	if m.state == handedOff {
		m.held = append(m.held, buf[:n]...)
		m.mu.Unlock()
		close(m.toClientDone)
		return
	}
	m.state = spliced
	m.mu.Unlock()
	m.toClient(buf[:n], err)
}

// toClient is the target → client direction of a splice: first, which
// the target sent with err, then whatever else it sends. The target's FIN
// half-closes the client, and the target is watched until its reset,
// which resets the client, or until it is closed.
func (m *mirror) toClient(first []byte, err error) {
	var werr error
	if len(first) > 0 {
		_, werr = m.client.Write(first)
	}
	if werr == nil && err == nil {
		err, werr = pump(m.client, m.target)
	}
	switch {
	case werr != nil:
		m.closeBoth()
	case isReset(err):
		m.abortClient()
		m.closeBoth()
	case err != nil && err != io.EOF:
		m.closeBoth()
	default:
		m.endDirection(m.client, nil)
		close(m.toClientDone)
		if targetReset(m.target.Conn) {
			m.abortClient()
		}
		return
	}
	close(m.toClientDone)
}

// splice joins the client → target direction once gather didn't hand the
// connection off, rerr being the error that ended gather, if any: the
// client's FIN, or anything else, while the hello was read closes both,
// and the target's reset resets the client. It returns once both
// directions ended and both connections are closed.
func (m *mirror) splice(rerr error) {
	var werr error
	if rerr == nil {
		rerr, werr = pump(m.target, m.client)
	} else if tw := (targetWriteError{}); errors.As(rerr, &tw) {
		rerr, werr = nil, tw.error
	}
	switch {
	case isReset(werr):
		m.abortClient()
		m.closeBoth()
	case werr != nil || rerr != nil:
		m.closeBoth()
	default:
		m.endDirection(m.target, nil)
	}
	<-m.toClientDone
	m.closeBoth()
	<-m.fromTarget
}

// pump copies src to dst until src's EOF (nil, nil), a read error or a
// write error.
func pump(dst, src *idleConn) (rerr, werr error) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return nil, werr
			}
		}
		switch {
		case err == io.EOF:
			return nil, nil
		case err != nil:
			return err, nil
		}
	}
}

// endDirection ends the direction writing to dst. A clean end of its
// source half-closes dst, so each side's FIN reaches the other, and the
// other direction, which reads from dst, ends once dst is idle for
// m.linger; an error closes both ways.
func (m *mirror) endDirection(dst *idleConn, err error) {
	if cw, ok := dst.Conn.(interface{ CloseWrite() error }); ok && err == nil {
		_ = cw.CloseWrite()
		dst.idleAfter(m.linger)
		return
	}
	m.closeBoth()
}

// idleConn is a spliced connection whose reads, once idleAfter set a
// timeout, each end after that long without data, and whose writes each
// end once they waited writeTimeout without progress.
type idleConn struct {
	net.Conn
	timeout      atomic.Int64 // a time.Duration; 0 is none
	writeTimeout time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if d := time.Duration(c.timeout.Load()); d > 0 {
		_ = c.SetReadDeadline(time.Now().Add(d))
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if c.writeTimeout <= 0 {
		return c.Conn.Write(p)
	}
	return writeRearming(c.Conn, p, c.writeTimeout)
}

// writeRearmingByDeadline is writeRearming for a connection without a
// descriptor: each write that timed out having made progress gets another
// timeout, so a write stalls between timeout and twice that after its
// last progress.
func writeRearmingByDeadline(c net.Conn, p []byte, timeout time.Duration) (int, error) {
	written := 0
	for {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		n, err := c.Write(p[written:])
		written += n
		if err == nil || n == 0 || !isTimeout(err) {
			return written, err
		}
	}
}

// idleAfter bounds every read from now on, one already waiting included,
// to d without data.
func (c *idleConn) idleAfter(d time.Duration) {
	c.timeout.Store(int64(d))
	_ = c.SetReadDeadline(time.Now().Add(d))
}

func (m *mirror) closeBoth() {
	_ = m.client.Close()
	_ = m.target.Close()
}

// abortClient resets the client, as the site's own reset would reach it.
func (m *mirror) abortClient() {
	if tc, ok := m.client.Conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = m.client.Close()
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// spliceJoined joins client and target both ways, toTarget sent to the
// target and toClient to the client first, and returns once both
// directions ended and both connections are closed: a pair decided
// elsewhere, spliced as a mirror that became a splice is.
func spliceJoined(client, target net.Conn, linger, writeTimeout time.Duration, toTarget, toClient []byte) {
	m := newPair(client, target, linger, writeTimeout)
	m.state = spliced
	if err := m.forward(toTarget); err != nil {
		if isReset(err) {
			m.abortClient()
		}
		m.closeBoth()
		return
	}
	go func() {
		defer close(m.fromTarget)
		m.toClient(toClient, nil)
	}()
	m.splice(nil)
}

// stop stops the target → client direction for a hello that
// authenticated and returns the target connection, which has all of the
// hello but its held-back tail, and what the target sent after the
// hand-off, not yet passed on.
func (m *mirror) stop() (net.Conn, []byte) {
	_ = m.target.SetReadDeadline(time.Now())
	<-m.fromTarget
	_ = m.target.SetReadDeadline(time.Time{})
	_ = m.target.SetWriteDeadline(time.Time{})
	return m.target.Conn, m.held
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// handedTarget is the target connection REALITY's server gets from its
// DialContext: the one the listener dialled at accept, which already has
// the ClientHello but its held-back tail. REALITY forwards the hello it
// reads again; all of it but the tail is dropped, so the target sees the
// hello once, as from REALITY's own listener. What the target sent before
// REALITY reads is read first.
type handedTarget struct {
	net.Conn
	held []byte
	skip int
}

func (c *handedTarget) Read(p []byte) (int, error) {
	if len(c.held) > 0 {
		n := copy(p, c.held)
		c.held = c.held[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *handedTarget) Write(p []byte) (int, error) {
	if c.skip > 0 {
		n := min(c.skip, len(p))
		c.skip -= n
		if n == len(p) {
			return n, nil
		}
		m, err := c.Conn.Write(p[n:])
		return n + m, err
	}
	return c.Conn.Write(p)
}

func (c *handedTarget) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
