package reality

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// helloTimeout bounds reading the ClientHello. What doesn't arrive in
	// time goes to the camouflage with whatever did.
	helloTimeout = 10 * time.Second
	// detectWait bounds how long Listen waits for REALITY to learn the
	// target's post-handshake records.
	detectWait = 10 * time.Second
)

// Listen implements transport.Transport. Whatever fails authentication
// goes to the admission's camouflage; without one, it is spliced to the
// listener's target, raw and whole, which is reality's disguise.
func (t *Transport) Listen(ctx context.Context, cfg transport.ListenConfig, admission transport.Admission) (transport.Listener, error) {
	addr, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || !addr.Addr().IsValid() {
		return nil, invalid("listen address %q: an IP literal and port", cfg.Address)
	}
	ls, err := parseListen(cfg.Settings)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: t.control}
	ln, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	camo := admission.Camouflage
	if camo == nil {
		camo = &splice{t: t, target: ls.target}
	}
	l := &listener{
		t:        t,
		ln:       ln,
		settings: ls,
		peers:    admission.Peers,
		camo:     camo,
		replay:   newReplayCache(ls.window),
		accepted: make(chan accepted),
		closed:   make(chan struct{}),
		links:    map[shortID]*link{},
		pending:  map[net.Conn]struct{}{},
	}
	links, changed := l.peers.Snapshot()
	l.apply(links)
	t.detect(ctx, ls)
	go l.watch(changed)
	go l.acceptLoop()
	return l, nil
}

type listener struct {
	t        *Transport
	ln       net.Listener
	settings listenSettings
	peers    transport.Peers
	camo     transport.Camouflage
	replay   *replayCache

	accepted  chan accepted
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	table    map[shortID]transport.PeerLink
	refused  map[shortID]error // credentials in the table whose entry reality refuses
	rejected []transport.PeerError
	links    map[shortID]*link
	pending  map[net.Conn]struct{} // connections not yet a link
}

type accepted struct {
	link *link
	peer transport.Identity
}

func (l *listener) Accept(ctx context.Context) (transport.Link, transport.Identity, error) {
	select {
	case a := <-l.accepted:
		return a.link, a.peer, nil
	case <-l.closed:
		return nil, transport.Identity{}, net.ErrClosed
	case <-ctx.Done():
		return nil, transport.Identity{}, ctx.Err()
	}
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }

func (l *listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.ln.Close()
		l.mu.Lock()
		links := make([]*link, 0, len(l.links))
		for _, lk := range l.links {
			links = append(links, lk)
		}
		for c := range l.pending {
			_ = c.Close()
		}
		l.mu.Unlock()
		for _, lk := range links {
			lk.close(nil)
		}
	})
	return err
}

// Rejected lists the peer links of the table the listener can't use: ones
// reality refuses, and every one sharing a short id with another (both
// are dropped, not one guessed).
func (l *listener) Rejected() []transport.PeerError {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rejected
}

func (l *listener) watch(changed <-chan struct{}) {
	for {
		select {
		case <-changed:
		case <-l.closed:
			return
		}
		var links []transport.PeerLink
		links, changed = l.peers.Snapshot()
		l.apply(links)
	}
}

// apply takes a new table: links whose credential left it close
// (ErrRevoked), links whose entry is now refused close
// (ErrSettingsRefused), the rest pick up their new shaping.
func (l *listener) apply(links []transport.PeerLink) {
	table := make(map[shortID]transport.PeerLink, len(links))
	refused := map[shortID]error{}
	shared := map[shortID]bool{}
	var rejected []transport.PeerError
	for _, pl := range links {
		id, err := parseShortID(pl.Verifier)
		if err == nil {
			err = l.t.CheckInbound(pl)
		}
		errShared := invalid("a short id another peer link has too")
		if err != nil {
			if len(pl.Verifier) == ShortIDSize {
				refused[id] = err
			}
			rejected = append(rejected, transport.PeerError{Peer: pl.Peer, Err: err})
			continue
		}
		if first, ok := table[id]; ok {
			shared[id] = true
			delete(table, id)
			rejected = append(rejected, transport.PeerError{Peer: first.Peer, Err: errShared})
		}
		if shared[id] {
			rejected = append(rejected, transport.PeerError{Peer: pl.Peer, Err: errShared})
			continue
		}
		table[id] = pl
	}

	type closing struct {
		link  *link
		cause error
	}
	var toClose []closing
	l.mu.Lock()
	l.table, l.refused, l.rejected = table, refused, rejected
	for id, lk := range l.links {
		pl, ok := table[id]
		switch {
		case refused[id] != nil:
			toClose = append(toClose, closing{lk, fmt.Errorf("%w: %w", transport.ErrSettingsRefused, refused[id])})
		case !ok || pl.Peer != lk.peer:
			toClose = append(toClose, closing{lk, transport.ErrRevoked})
		default:
			lk.setShaping(pl.Shaping)
		}
	}
	l.mu.Unlock()
	for _, c := range toClose {
		c.link.close(c.cause)
	}
}

func (l *listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			select {
			case <-l.closed:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond) // out of descriptors, say: don't spin
			continue
		}
		if !l.track(conn) {
			_ = conn.Close()
			return
		}
		go l.serve(conn)
	}
}

func (l *listener) track(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	l.pending[conn] = struct{}{}
	return true
}

func (l *listener) untrack(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pending, conn)
}

// serve authenticates one connection: its ClientHello, read before
// anything is answered, must carry a sealed short id in the table, fresh
// and not seen before. Anything else goes to the camouflage, raw and
// whole. An authenticated connection's TLS handshake is REALITY's, which
// imitates the target's.
func (l *listener) serve(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))
	record, err := readRecord(conn)
	_ = conn.SetReadDeadline(time.Time{})
	var (
		id   shortID
		peer transport.Identity
		ok   bool
	)
	if err == nil {
		id, peer, ok = l.authenticate(record)
	}
	if !ok {
		l.untrack(conn)
		l.camo.Stream(conn, record)
		return
	}
	tlsConn, err := xreality.Server(context.Background(), &replayConn{Conn: conn, prefix: record}, l.realityConfig(id))
	l.untrack(conn)
	if err != nil {
		return // REALITY spliced the connection to the target or closed it
	}
	l.admit(tlsConn, conn, id, peer)
}

func (l *listener) authenticate(record []byte) (shortID, transport.Identity, bool) {
	h, err := parseHello(record)
	if err != nil || !l.settings.names[h.serverName] {
		return shortID{}, transport.Identity{}, false
	}
	s, err := open(l.settings.key, h)
	if err != nil {
		return shortID{}, transport.Identity{}, false
	}
	l.mu.Lock()
	pl, ok := l.table[s.shortID]
	l.mu.Unlock()
	if !ok || !l.replay.admit(h.sessionID, s.sent, l.t.now()) {
		return shortID{}, transport.Identity{}, false
	}
	return s.shortID, pl.Peer, true
}

// admit makes an established connection a link: it replaces the
// credential's link, if any, and waits for Accept.
func (l *listener) admit(tlsConn, tcp net.Conn, id shortID, peer transport.Identity) {
	l.mu.Lock()
	pl, ok := l.table[id]
	select {
	case <-l.closed:
		ok = false
	default:
	}
	if !ok || pl.Peer != peer {
		l.mu.Unlock()
		_ = tlsConn.Close()
		return
	}
	lk := newLink(tlsConn, tcp, pl.Shaping, l.t.sent, func(lk *link) { l.forget(id, lk) })
	lk.peer = peer
	old := l.links[id]
	l.links[id] = lk
	l.mu.Unlock()
	if old != nil {
		old.close(transport.ErrSuperseded)
	}
	select {
	case l.accepted <- accepted{lk, peer}:
	case <-l.closed:
		lk.close(nil)
	}
}

func (l *listener) forget(id shortID, lk *link) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.links[id] == lk {
		delete(l.links, id)
	}
}

func (l *listener) realityConfig(id shortID) *xreality.Config {
	d := &net.Dialer{Control: l.t.control, Timeout: helloTimeout}
	return &xreality.Config{
		DialContext:                 d.DialContext,
		Type:                        "tcp",
		Dest:                        l.settings.target.String(),
		ServerNames:                 l.settings.names,
		PrivateKey:                  l.settings.key.Bytes(),
		MaxTimeDiff:                 l.settings.window,
		ShortIds:                    map[[ShortIDSize]byte]bool{id: true},
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true, // one write, one record: shaping sizes records
	}
}

// detect has REALITY learn the target's post-handshake records, which its
// handshake imitates, and waits for it: until it knows, REALITY holds
// every authenticated handshake in 5-second sleeps.
func (t *Transport) detect(ctx context.Context, ls listenSettings) {
	cfg := &xreality.Config{Type: "tcp", Dest: ls.target.String(), ServerNames: ls.names}
	xreality.DetectPostHandshakeRecordsLens(cfg)
	deadline := time.Now().Add(detectWait)
	for name := range ls.names {
		for alpn := range 3 {
			key := fmt.Sprintf("%s %s %d", cfg.Dest, name, alpn)
			for {
				v, _ := xreality.GlobalPostHandshakeRecordsLens.Load(key)
				if _, done := v.([]int); done || time.Now().After(deadline) || ctx.Err() != nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// readRecord reads one TLS record of at most maxHelloRecord bytes; on
// error it returns what it consumed.
func readRecord(conn net.Conn) ([]byte, error) {
	buf := make([]byte, recordHeaderSize, recordHeaderSize+maxHelloRecord)
	if n, err := io.ReadFull(conn, buf); err != nil {
		return buf[:n], err
	}
	size := int(buf[3])<<8 | int(buf[4])
	if buf[0] != recordTypeHandshake || size > maxHelloRecord {
		return buf, errHello
	}
	buf = buf[:recordHeaderSize+size]
	n, err := io.ReadFull(conn, buf[recordHeaderSize:])
	return buf[:recordHeaderSize+n], err
}

// replayConn hands REALITY a connection whose first bytes, the ClientHello
// the listener already read, are read again. REALITY splices through
// CloseWrite, so it has one.
type replayConn struct {
	net.Conn
	prefix []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
