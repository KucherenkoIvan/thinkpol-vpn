package reality

import (
	"io"
	"net"
	"sync"
	"time"
)

// spliceLinger is how long a splice whose one direction ended waits on the
// other: a client that stays silent once the target closed would otherwise
// hold its connection, and the target's, for good. A listener reads it at
// Listen.
var spliceLinger = 5 * time.Second

// mirror is a connection whose target was dialled at accept, before the
// ClientHello is read, as REALITY's own server does: every chunk read from
// the client goes on to the target as it arrives, and whatever the target
// sends, or its closing, reaches the client as it would from the site. A
// prober that stalls is answered when the target answers, not on a timer
// of the listener's. The hello either authenticates, and the target is
// handed to REALITY, or the mirror becomes a splice.
type mirror struct {
	client, target net.Conn
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
	m := &mirror{client: client, target: target, linger: linger, fromTarget: make(chan struct{})}
	go m.copyFromTarget()
	return m
}

// gather reads the first TLS record from the client, at most
// maxHelloRecord bytes and never past it, forwarding each chunk as it is
// read. Once the record is whole, authenticate decides: true hands the
// connection off, anything else splices it. It returns the bytes read and
// the client's read error, if that is what ended it; the target speaking
// or closing first splices too.
func (m *mirror) gather(authenticate func(record []byte) bool) (record []byte, authenticated bool, err error) {
	buf := make([]byte, recordHeaderSize+maxHelloRecord)
	have, need := 0, recordHeaderSize
	for {
		n, rerr := m.client.Read(buf[have:need])
		m.mu.Lock()
		if n > 0 {
			if _, werr := m.target.Write(buf[have : have+n]); werr != nil && rerr == nil {
				rerr = werr
			}
			have += n
		}
		switch {
		case m.state != gathering:
		case rerr != nil:
			m.state = spliced
		case have == recordHeaderSize && need == recordHeaderSize:
			size := int(buf[3])<<8 | int(buf[4])
			if buf[0] != recordTypeHandshake || size > maxHelloRecord {
				m.state = spliced
			}
			need += size
		}
		if m.state == gathering && have == need {
			// Decided under the lock: the target, now holding the whole
			// hello, answers it, and that answer is REALITY's to read.
			m.state = spliced
			if authenticate(buf[:have]) {
				m.state = handedOff
			}
		}
		state := m.state
		m.mu.Unlock()
		if state != gathering {
			return buf[:have], state == handedOff, rerr
		}
	}
}

// copyFromTarget is the target → client direction: while the hello is
// gathered, anything from the target, its closing included, splices the
// connection; after a hand-off it stops, keeping what it read for REALITY.
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
// connection off, rerr being the client error that ended gather, if any;
// it returns once both directions ended and both connections are closed.
func (m *mirror) splice(rerr error) {
	switch rerr {
	case nil:
		_, rerr = io.Copy(m.target, m.client)
	case io.EOF:
		rerr = nil
	}
	m.endDirection(m.target, rerr)
	<-m.fromTarget
	m.closeBoth()
}

// endDirection ends the direction writing to dst. A clean end of its
// source half-closes dst, so each side's FIN reaches the other, and gives
// the other direction, which reads from dst, m.linger more; an error
// closes both ways.
func (m *mirror) endDirection(dst net.Conn, err error) {
	if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
		_ = cw.CloseWrite()
		_ = dst.SetReadDeadline(time.Now().Add(m.linger))
		return
	}
	m.closeBoth()
}

func (m *mirror) closeBoth() {
	_ = m.client.Close()
	_ = m.target.Close()
}

// handOff stops the target → client direction for a hello that
// authenticated and returns the target as REALITY must see it.
func (m *mirror) handOff(hello []byte) *handedTarget {
	_ = m.target.SetReadDeadline(time.Now())
	<-m.fromTarget
	_ = m.target.SetReadDeadline(time.Time{})
	return &handedTarget{Conn: m.target, held: m.held, skip: len(hello)}
}

// handedTarget is the target connection REALITY's server gets from its
// DialContext: the one the listener dialled at accept, which already has
// the ClientHello. REALITY forwards the hello it reads again; those bytes
// are dropped, so the target sees the hello once, as from REALITY's own
// listener. What the target sent before REALITY reads is read first.
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
