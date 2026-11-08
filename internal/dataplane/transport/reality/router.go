package reality

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

var _ transport.StreamRoutable = (*Transport)(nil)

// ListenStream implements transport.StreamRoutable: the public listener a
// server node's supervisor accepts on. It checks the target as Listen
// does (its certificate, then REALITY's detection of its post-handshake
// records) and keeps what REALITY learned for the workers' handoff
// settings: a worker's sandbox can neither verify the target nor, in a
// guest space, reach it.
func (t *Transport) ListenStream(ctx context.Context, cfg transport.ListenConfig) (transport.StreamListener, error) {
	ln, ls, err := t.openListener(ctx, cfg)
	if err != nil {
		return nil, err
	}
	records, err := learnedRecords(upstreamRecords{}, ls.target.String(), ls.names)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	handoff, err := json.Marshal(handoffSettings{Address: ln.Addr().String(), Listener: cfg.Settings, Records: records})
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("reality: handoff settings: %w", err)
	}
	return &publicListener{Listener: ln, t: t, settings: ls, handoff: handoff, linger: spliceLinger, live: map[io.Closer]struct{}{}}, nil
}

// handoffSettings is what a worker's Handoff gets from the supervisor's
// public listener: its address, its settings and what REALITY learned of
// the target's post-handshake records, by REALITY's key. It never leaves
// the node: the supervisor and its workers are one binary (the IPC
// version says so), so the encoding is plain JSON.
type handoffSettings struct {
	Address  string           `json:"address"`
	Listener []byte           `json:"listener"`
	Records  map[string][]int `json:"records"`
}

// learnedRecords reads what REALITY learned of dest's post-handshake
// records for every server name and ALPN; detect must have succeeded.
func learnedRecords(store recordsStore, dest string, names map[string]bool) (map[string][]int, error) {
	out := map[string][]int{}
	for name := range names {
		for alpn := range detectedALPNs {
			key := recordsKey(dest, name, alpn)
			v, _ := store.load(key)
			lens, ok := v.([]int)
			if !ok {
				return nil, fmt.Errorf("reality: target %s: no records learned under %q", dest, key)
			}
			out[key] = lens
		}
	}
	return out, nil
}

// publicListener is a supervisor's public reality listener: the settings
// the router opens hellos with, and the connections it still holds (being
// routed, or spliced to the target), which Close closes.
type publicListener struct {
	net.Listener
	t        *Transport
	settings listenSettings
	handoff  []byte
	linger   time.Duration

	mu     sync.Mutex
	closed bool
	live   map[io.Closer]struct{}
}

var _ transport.StreamListener = (*publicListener)(nil)

func (pl *publicListener) HandoffSettings() []byte { return pl.handoff }

// Camouflage is reality's own: a connection turned away is spliced to the
// target, what was read of it sent first.
func (pl *publicListener) Camouflage() transport.Camouflage { return targetSplice{pl} }

func (pl *publicListener) Close() error {
	err := pl.Listener.Close()
	pl.mu.Lock()
	pl.closed = true
	for c := range pl.live {
		_ = c.Close()
	}
	clear(pl.live)
	pl.mu.Unlock()
	return err
}

// track has Close close c; it reports false, and leaves c to the caller,
// once the listener is closed.
func (pl *publicListener) track(cs ...io.Closer) bool {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	if pl.closed {
		return false
	}
	for _, c := range cs {
		pl.live[c] = struct{}{}
	}
	return true
}

func (pl *publicListener) untrack(cs ...io.Closer) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for _, c := range cs {
		delete(pl.live, c)
	}
}

func (pl *publicListener) dialTarget() (net.Conn, error) {
	d := net.Dialer{Control: pl.t.control, Timeout: targetDialTimeout}
	return d.Dial("tcp", pl.settings.target.String())
}

// targetSplice is a public listener's own camouflage: the connection is
// spliced to the target, raw and whole, on a goroutine of its own.
type targetSplice struct{ pl *publicListener }

func (targetSplice) Datagram([]byte, net.Addr) {}

func (c targetSplice) Stream(conn net.Conn, consumed []byte) {
	if !c.pl.track(conn) {
		_ = conn.Close()
		return
	}
	go func() {
		defer c.pl.untrack(conn)
		target, err := c.pl.dialTarget()
		if err != nil {
			_ = conn.Close()
			return
		}
		if !c.pl.track(target) {
			_ = target.Close()
			return
		}
		defer c.pl.untrack(target)
		splicePair(conn, target, c.pl.linger, consumed, nil)
	}()
}

// splicePair joins client and target both ways, toTarget sent to the
// target and toClient to the client first, and returns once both
// directions ended and both connections are closed. Each side's FIN is
// passed on as a half-close, as in an established mirror's splice.
func splicePair(client, target net.Conn, linger time.Duration, toTarget, toClient []byte) {
	m := &mirror{client: &idleConn{Conn: client}, target: &idleConn{Conn: target}, linger: linger, fromTarget: make(chan struct{}), state: spliced}
	if _, err := target.Write(toTarget); err != nil {
		m.closeBoth()
		return
	}
	if _, err := client.Write(toClient); err != nil {
		m.closeBoth()
		return
	}
	go func() {
		defer close(m.fromTarget)
		_, err := io.Copy(m.client, m.target)
		m.endDirection(m.client, err)
	}()
	m.splice(nil)
}

// StreamRouter implements transport.StreamRoutable: one router serves
// every reality listener of a supervisor, so the replay cache is per
// credential, not per listener, and outlives a listener's reopening.
func (t *Transport) StreamRouter(peers transport.Peers) transport.StreamRouter {
	return &router{t: t, peers: peers, replay: newReplayCache(transport.MaxClockSkew)}
}

// router is the supervisor's half of reality behind a shared listener: it
// opens each hello's seal with the listener's key, finds the short id in
// the merged table and admits the hello once, before anything is
// answered or any TLS terminated.
type router struct {
	t      *Transport
	peers  transport.Peers
	replay *replayCache // remembered for MaxClockSkew, the widest window

	mu      sync.Mutex
	tab     table
	changed <-chan struct{} // nil until the table was first read
}

func (r *router) Rejected() []transport.PeerError {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	return r.tab.rejected
}

// refresh rebuilds the table if the peers changed since it was read; r.mu
// held.
func (r *router) refresh() {
	if r.changed != nil {
		select {
		case <-r.changed:
		default:
			return
		}
	}
	var links []transport.PeerLink
	links, r.changed = r.peers.Snapshot()
	r.tab = newTable(r.t, links)
}

func (r *router) lookup(id shortID) (transport.PeerLink, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	pl, ok := r.tab.links[id]
	return pl, ok
}

// authenticate decides one whole hello on ln: its seal opens under ln's
// key and names a short id of the table whose space serves, it was sealed
// within ln's window and wasn't seen before.
func (r *router) authenticate(ln *publicListener, record []byte, serves func(transport.Identity) bool) (transport.Identity, bool) {
	h, sh, ok := ln.settings.openHello(record)
	if !ok {
		return transport.Identity{}, false
	}
	pl, ok := r.lookup(sh.shortID)
	if !ok || !serves(pl.Peer) {
		return transport.Identity{}, false
	}
	now := r.t.now()
	if !transport.FreshWithin(sh.sent, now, ln.settings.window) || !r.replay.admit(sh.shortID, h.sessionID, sh.sent, now) {
		return transport.Identity{}, false
	}
	return pl.Peer, true
}

// RouteStream implements transport.StreamRouter. Without a camouflage it
// does what a standalone listener does up to the decision: the target is
// dialled at accept and gets the hello as it arrives, all of it but the
// last byte until the router decided; what fails is spliced to the target
// on a goroutine of the listener's. What authenticates is handed over
// with that target connection. A read deadline on conn (the supervisor's
// bound) passing before the hello was whole leaves the connection spliced
// to the target, which can then end it as the site would.
func (r *router) RouteStream(ln transport.StreamListener, conn net.Conn, serves func(transport.Identity) bool, camo transport.Camouflage) (transport.StreamHandoff, bool) {
	pl, ok := ln.(*publicListener)
	if !ok {
		_ = conn.SetReadDeadline(time.Time{})
		transport.OrDrop(camo).Stream(conn, nil)
		return transport.StreamHandoff{}, false
	}
	if camo != nil {
		return r.routeCamouflaged(pl, conn, serves, camo)
	}
	if !pl.track(conn) {
		_ = conn.Close()
		return transport.StreamHandoff{}, false
	}
	target, err := pl.dialTarget()
	if err != nil {
		pl.untrack(conn)
		_ = conn.Close()
		return transport.StreamHandoff{}, false
	}
	if !pl.track(target) {
		_ = target.Close()
		return transport.StreamHandoff{}, false // Close closed conn
	}
	m := newMirror(conn, target, pl.linger)
	var peer transport.Identity
	record, authenticated, rerr := m.gather(func(record []byte) bool {
		var ok bool
		peer, ok = r.authenticate(pl, record, serves)
		return ok
	})
	if !authenticated {
		_ = conn.SetReadDeadline(time.Time{})
		go func() {
			defer pl.untrack(conn, target)
			m.splice(rerr)
		}()
		return transport.StreamHandoff{}, false
	}
	raw, held := m.stop()
	pl.untrack(conn, target)
	return transport.StreamHandoff{Peer: peer, Conn: conn, Consumed: record, Target: raw, TargetRead: held}, true
}

// routeCamouflaged is RouteStream with a camouflage of the supervisor's:
// the hello is read whole (within conn's deadline) before anything is
// dialled, and what fails goes to camo. The target an authenticated hello
// is handed over with is dialled then and given the hello but its last
// byte, as from the mirror.
func (r *router) routeCamouflaged(pl *publicListener, conn net.Conn, serves func(transport.Identity) bool, camo transport.Camouflage) (transport.StreamHandoff, bool) {
	record, err := readRecord(conn)
	var peer transport.Identity
	ok := false
	if err == nil {
		peer, ok = r.authenticate(pl, record, serves)
	}
	if !ok {
		_ = conn.SetReadDeadline(time.Time{})
		camo.Stream(conn, record)
		return transport.StreamHandoff{}, false
	}
	target, err := pl.dialTarget()
	if err == nil {
		if _, err = target.Write(record[:len(record)-heldBack]); err != nil {
			_ = target.Close()
		}
	}
	if err != nil {
		_ = conn.Close()
		return transport.StreamHandoff{}, false
	}
	return transport.StreamHandoff{Peer: peer, Conn: conn, Consumed: record, Target: target}, true
}

// Handoff implements transport.StreamRoutable: a worker's listener for the
// connections the supervisor's router handed over from one public
// listener, settings being its HandoffSettings. It puts what REALITY
// learned of the target's records into this process's store, where
// REALITY's server reads them, and serves each connection as a
// standalone listener serves one that authenticated: REALITY's handshake
// on the target connection the router dialled. It checks the seal and
// the short id against its own table again, not the replay cache (the
// router admitted the hello once); what it refuses is spliced to the
// target.
func (t *Transport) Handoff(settings []byte, admission transport.Admission) (transport.HandoffListener, error) {
	var hs handoffSettings
	if err := json.Unmarshal(settings, &hs); err != nil {
		return nil, invalid("handoff settings: %v", err)
	}
	ls, err := parseListen(hs.Listener)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddrPort(hs.Address)
	if err != nil {
		return nil, invalid("handoff address %q: %v", hs.Address, err)
	}
	dest := ls.target.String()
	records := map[string][]int{}
	for name := range ls.names {
		for alpn := range detectedALPNs {
			key := recordsKey(dest, name, alpn)
			lens, ok := hs.Records[key]
			if !ok {
				return nil, invalid("handoff settings: no records for %q", key)
			}
			records[key] = append([]int{}, lens...)
		}
	}
	for key, lens := range records {
		xreality.GlobalPostHandshakeRecordsLens.Store(key, lens)
	}
	l := newListener(t, nil, net.TCPAddrFromAddrPort(addr), ls, admission, nil)
	return l, nil
}

// ServeStream implements transport.HandoffListener: the connection is
// served on a goroutine of its own.
func (l *listener) ServeStream(h transport.StreamHandoff) { go l.serveHandoff(h) }

func (l *listener) serveHandoff(h transport.StreamHandoff) {
	if h.Target == nil || !l.track(h.Conn) {
		h.Close()
		return
	}
	if !l.track(h.Target) {
		_ = h.Target.Close()
		return // Close closed the connection
	}
	defer l.untrack(h.Conn, h.Target)
	record := h.Consumed
	id, peer, ok := l.authenticate(record)
	if !ok {
		var tail []byte
		if len(record) >= heldBack {
			tail = record[len(record)-heldBack:]
		}
		splicePair(h.Conn, h.Target, l.linger, tail, h.TargetRead)
		return
	}
	ht := &handedTarget{Conn: h.Target, held: h.TargetRead, skip: len(record) - heldBack}
	l.handshake(h.Conn, record, id, peer, func(context.Context, string, string) (net.Conn, error) { return ht, nil })
}
