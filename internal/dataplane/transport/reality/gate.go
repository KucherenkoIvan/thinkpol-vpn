package reality

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// maxMirrors bounds the connections one listener is deciding at once
	// (from before the target is dialled until the hello is decided, at
	// most the router's deadline behind a shared listener); more are
	// closed, as an overloaded site would close them.
	maxMirrors = 1024
	// maxSplices bounds the connections one listener keeps spliced to its
	// target at once, each for as long as both ends keep it going (a
	// write stalled past spliceWriteTimeout, or one side idle past
	// spliceLinger once the other ended, closes it); more are closed.
	// Apart from maxMirrors, so strangers holding splices open never stop
	// a member's hello being decided.
	maxSplices = 1024
)

// gateBounds are the bounds a listener opened now gets: maxMirrors and
// maxSplices, smaller in tests.
var gateBounds = struct{ mirrors, splices int }{maxMirrors, maxSplices}

// liveSet is what a listener holds that isn't a link (connections being
// decided, spliced to the target or in REALITY's handshake) and the
// goroutines it started for them: closing it closes those connections,
// cancels ctx (the dials to the target) and waits for those goroutines.
type liveSet struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	closed bool
	conns  map[io.Closer]struct{}
}

func newLiveSet() *liveSet {
	ctx, cancel := context.WithCancel(context.Background())
	return &liveSet{ctx: ctx, cancel: cancel, conns: map[io.Closer]struct{}{}}
}

// track has close close cs; it reports false, and leaves cs to the
// caller, once the set is closed.
func (s *liveSet) track(cs ...io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	for _, c := range cs {
		s.conns[c] = struct{}{}
	}
	return true
}

func (s *liveSet) untrack(cs ...io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cs {
		delete(s.conns, c)
	}
}

// spawn runs f on a goroutine close waits for; it reports false, and
// doesn't run f, once the set is closed.
func (s *liveSet) spawn(f func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		f()
	}()
	return true
}

func (s *liveSet) close() {
	s.cancel()
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	clear(s.conns)
	s.mu.Unlock()
	s.wg.Wait()
}

// gate is what a reality listener does with a connection before its hello
// is decided, the same for a standalone listener and a supervisor's public
// one, and where whatever it turns away is spliced to the target. Its
// slots bound the connections being decided (mirrors) and spliced
// (splices) apart; each costs two descriptors.
type gate struct {
	t            *Transport
	target       netip.AddrPort
	linger       time.Duration
	writeTimeout time.Duration
	helloTimeout time.Duration
	mirrors      chan struct{}
	splices      chan struct{}
	live         *liveSet
}

func newGate(t *Transport, target netip.AddrPort) *gate {
	return &gate{
		t: t, target: target, linger: spliceLinger, writeTimeout: spliceWriteTimeout, helloTimeout: helloTimeout,
		mirrors: make(chan struct{}, gateBounds.mirrors), splices: make(chan struct{}, gateBounds.splices), live: newLiveSet(),
	}
}

func take(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *gate) dialTarget() (net.Conn, error) {
	d := net.Dialer{Control: g.t.control, Timeout: targetDialTimeout}
	return d.DialContext(g.live.ctx, "tcp", g.target.String())
}

// passed is a hello the gate let through: the whole record, the target
// connection dialled for it, which has all of it but the held-back tail,
// and what the target sent after the decision, not yet passed on.
type passed struct {
	record []byte
	target net.Conn
	held   []byte
}

// decision is what the gate did with a connection.
type decision uint8

const (
	turnedAway  decision = iota // spliced to the target, or closed with it unreachable
	passedOn                    // auth let it through
	boundClosed                 // closed past the gate's bounds
)

// decide dials the target for conn and mirrors conn's hello to it, as
// REALITY's own server does, calling waiting (if set) once the mirror is
// up, and asks auth once the hello is whole. What auth lets through comes
// back with conn and its target still tracked, for the caller to untrack
// once it hands them on or is done with them. Anything else is spliced
// to the target, raw and whole, on a goroutine of the gate's; with the
// target unreachable conn is closed; past the gate's bounds too, and
// decide says so.
func (g *gate) decide(conn net.Conn, auth func(record []byte) bool, waiting func()) (passed, decision) {
	if !take(g.mirrors) {
		_ = conn.Close()
		return passed{}, boundClosed
	}
	defer func() { <-g.mirrors }()
	if !g.live.track(conn) {
		_ = conn.Close()
		return passed{}, turnedAway
	}
	target, err := g.dialTarget()
	if err != nil {
		g.live.untrack(conn)
		_ = conn.Close()
		return passed{}, turnedAway
	}
	if !g.live.track(target) {
		_ = target.Close()
		return passed{}, turnedAway // close closed conn
	}
	m := newMirror(conn, target, g.linger, g.writeTimeout)
	if waiting != nil {
		waiting()
	}
	record, ok, rerr := m.gather(auth)
	if ok {
		raw, held := m.stop()
		return passed{record: record, target: raw, held: held}, passedOn
	}
	_ = conn.SetReadDeadline(time.Time{})
	if !g.keepSpliced(conn, target, func() { m.splice(rerr) }, m.closeBoth) {
		return passed{}, boundClosed
	}
	return passed{}, turnedAway
}

// turnAway splices conn to a target dialled now, consumed sent to it
// first: a public listener's camouflage.
func (g *gate) turnAway(conn net.Conn, consumed []byte) {
	if !take(g.splices) {
		_ = conn.Close()
		return
	}
	if !g.live.track(conn) {
		<-g.splices
		_ = conn.Close()
		return
	}
	if !g.live.spawn(func() {
		defer func() { <-g.splices }()
		target, err := g.dialTarget()
		if err != nil {
			g.live.untrack(conn)
			_ = conn.Close()
			return
		}
		if !g.live.track(target) {
			_ = target.Close()
			return // close closed conn
		}
		defer g.live.untrack(conn, target)
		spliceJoined(conn, target, g.linger, g.writeTimeout, consumed, nil)
	}) {
		<-g.splices
		_ = conn.Close()
	}
}

// splice joins conn to target, a connection to the target that already
// has what conn sent but toTarget, toTarget sent to the target and
// toClient to conn first: a hello a worker refuses after the router let
// it through.
func (g *gate) splice(conn, target net.Conn, toTarget, toClient []byte) {
	if !g.live.track(conn, target) {
		_ = conn.Close()
		_ = target.Close()
		return
	}
	g.keepSpliced(conn, target, func() { spliceJoined(conn, target, g.linger, g.writeTimeout, toTarget, toClient) }, func() {
		_ = conn.Close()
		_ = target.Close()
	})
}

// keepSpliced runs splice, which returns once conn and target (both
// tracked) are closed, on a goroutine of the gate's under a splice slot;
// without a free slot, or once the gate is closed, it runs drop instead.
// It reports false when it found no free slot.
func (g *gate) keepSpliced(conn, target net.Conn, splice, drop func()) bool {
	if !take(g.splices) {
		drop()
		g.live.untrack(conn, target)
		return false
	}
	if !g.live.spawn(func() {
		defer func() { <-g.splices }()
		defer g.live.untrack(conn, target)
		splice()
	}) {
		<-g.splices
		drop()
		g.live.untrack(conn, target)
	}
	return true
}

// close closes everything the gate holds and waits for its splices.
func (g *gate) close() { g.live.close() }
