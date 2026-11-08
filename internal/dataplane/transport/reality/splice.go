package reality

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// spliceLinger is how long a splice whose one direction ended waits for
// data on the other, an idle timeout: a client that stays silent once the
// target closed would otherwise hold its connection, and the target's, for
// good, while an answer still flowing after the client's FIN isn't cut. A
// listener reads it at Listen.
var spliceLinger = 5 * time.Second

// mirror is a connection whose target was dialled at accept, before the
// ClientHello is read, as REALITY's own server does: every chunk read from
// the client goes on to the target as it arrives, and whatever the target
// sends, or its closing, reaches the client as it would from the site. A
// prober that stalls is answered when the target answers, not on a timer
// of the listener's. The hello either authenticates, and the target is
// handed to REALITY, or the mirror becomes a splice.
//
// Before the hello is decided, either side closing closes both whole, as
// REALITY's server does: the target closing before it sent anything
// closes the client, and the client's FIN before its hello was whole
// closes the target. Once spliced, each side's FIN is passed on as a
// half-close.
type mirror struct {
	client, target *idleConn
	linger         time.Duration

	mu    sync.Mutex
	state mirrorState
	held  []byte // what the target sent after the hand-off, REALITY's to read

	fromTarget chan struct{} // closed once the target → client direction ended
}

type mirrorState uint8

const (
	gathering mirrorState = iota // reading the hello, forwarding it
	spliced                      // joined to the target for good
	handedOff                    // the hello authenticated: REALITY's
)

func newMirror(client, target net.Conn, linger time.Duration) *mirror {
	m := &mirror{client: &idleConn{Conn: client}, target: &idleConn{Conn: target}, linger: linger, fromTarget: make(chan struct{})}
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

// gather reads the first TLS record from the client, at most
// maxHelloRecord bytes and never past it, forwarding each chunk as it is
// read, except the last heldBack bytes of a whole record. Once the record
// is whole, authenticate decides: true hands the connection off, the tail
// still held back; anything else forwards the tail and splices it. It
// returns the bytes read and the error that ended it, if any (reading
// from the client or writing to the target); the target speaking or
// closing first splices too.
func (m *mirror) gather(authenticate func(record []byte) bool) (record []byte, authenticated bool, err error) {
	buf := make([]byte, recordHeaderSize+maxHelloRecord)
	have, need := 0, recordHeaderSize
	for {
		n, rerr := m.client.Read(buf[have:need])
		m.mu.Lock()
		from := have
		have += n
		if m.state == gathering && rerr == nil && have == recordHeaderSize && need == recordHeaderSize {
			size := int(buf[3])<<8 | int(buf[4])
			if buf[0] != recordTypeHandshake || size > maxHelloRecord {
				m.state = spliced
			}
			need += size
		}
		whole := m.state == gathering && rerr == nil && have == need
		upto := have
		if whole {
			upto = max(from, have-heldBack)
		}
		if werr := m.forward(buf[from:upto]); werr != nil && rerr == nil {
			rerr = werr
		}
		switch {
		case m.state != gathering:
		case isTimeout(rerr):
			// The read deadline of whoever routes the connection: the
			// hello can no longer authenticate, and the connection stays
			// the target's, whose own timeouts end it.
			m.state = spliced
			rerr = nil
		case rerr != nil:
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
	_, err := m.target.Write(b)
	return err
}

// copyFromTarget is the target → client direction: while the hello is
// gathered, anything from the target splices the connection, and its
// closing before it sent anything closes both; after a hand-off it stops,
// keeping what it read for REALITY.
func (m *mirror) copyFromTarget() {
	defer close(m.fromTarget)
	buf := make([]byte, 32<<10)
	n, err := m.target.Read(buf)
	m.mu.Lock()
	if m.state == handedOff {
		m.held = append(m.held, buf[:n]...)
		m.mu.Unlock()
		return
	}
	m.state = spliced
	m.mu.Unlock()
	if n == 0 && err != nil {
		m.closeBoth()
		return
	}
	if n > 0 {
		if _, werr := m.client.Write(buf[:n]); werr != nil {
			m.closeBoth()
			return
		}
	}
	switch err {
	case nil:
		_, err = io.Copy(m.client, m.target)
	case io.EOF:
		err = nil
	}
	m.endDirection(m.client, err)
}

// splice joins the client → target direction once gather didn't hand the
// connection off, rerr being the error that ended gather, if any: the
// client's FIN, or anything else, while the hello was read closes both. It
// returns once both directions ended and both connections are closed.
func (m *mirror) splice(rerr error) {
	if rerr != nil {
		m.closeBoth()
	} else {
		_, err := io.Copy(m.target, m.client)
		m.endDirection(m.target, err)
	}
	<-m.fromTarget
	m.closeBoth()
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
// timeout, each end after that long without data.
type idleConn struct {
	net.Conn
	timeout atomic.Int64 // a time.Duration; 0 is none
}

func (c *idleConn) Read(p []byte) (int, error) {
	if d := time.Duration(c.timeout.Load()); d > 0 {
		_ = c.SetReadDeadline(time.Now().Add(d))
	}
	return c.Conn.Read(p)
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

// handOff stops the target → client direction for a hello that
// authenticated and returns the target as REALITY must see it.
func (m *mirror) handOff(hello []byte) *handedTarget {
	target, held := m.stop()
	return &handedTarget{Conn: target, held: held, skip: len(hello) - heldBack}
}

// stop stops the target → client direction for a hello that
// authenticated and returns the target connection, which has all of the
// hello but its held-back tail, and what the target sent after the
// hand-off, not yet passed on.
func (m *mirror) stop() (net.Conn, []byte) {
	_ = m.target.SetReadDeadline(time.Now())
	<-m.fromTarget
	_ = m.target.SetReadDeadline(time.Time{})
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
