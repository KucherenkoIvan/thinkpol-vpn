package reality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// targetDialTimeout bounds the dial to the target at accept. A target
	// that can't be reached closes the connection.
	targetDialTimeout = 10 * time.Second
	// handshakeTimeout bounds REALITY's handshake, which has no deadline
	// of its own, once the ClientHello authenticated: a dialer holding a
	// credential that stalls there would hold the connection for good.
	handshakeTimeout = 15 * time.Second
	// detectWait bounds Listen's check of the target's certificate, and
	// how long it waits for REALITY to learn the target's post-handshake
	// records.
	detectWait = 10 * time.Second
)

// helloTimeout bounds reading the ClientHello, from accept: what doesn't
// arrive in time stays spliced to the target, whose own timeouts end it
// (no timer of the listener's shows), and frees its slot among the
// connections being decided; with an Admission.Camouflage it goes there
// with whatever did arrive. A listener reads it at Listen.
var helloTimeout = 10 * time.Second

// Listen implements transport.Transport. Whatever fails authentication
// goes to the admission's camouflage; without one, the connection is
// mirrored to the listener's target from accept and spliced to it, raw and
// whole, which is reality's disguise. Listen fails unless the target's
// certificate verifies for every server name and REALITY learned the
// target's post-handshake records first.
func (t *Transport) Listen(ctx context.Context, cfg transport.ListenConfig, admission transport.Admission) (transport.Listener, error) {
	ln, ls, err := t.openListener(ctx, cfg)
	if err != nil {
		return nil, err
	}
	l := newListener(t, ln, ln.Addr(), ls, admission, helloCheck{t: t, replay: newReplays(ls.window), start: transport.StartedAt(t.now(), t.elapsed)})
	go l.acceptLoop()
	return l, nil
}

// openListener checks a listener of the map and its target (the target's
// certificate, then REALITY's detection of its records), then listens.
func (t *Transport) openListener(ctx context.Context, cfg transport.ListenConfig) (net.Listener, listenSettings, error) {
	addr, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || !addr.Addr().IsValid() {
		return nil, listenSettings{}, invalid("listen address %q: an IP literal and port", cfg.Address)
	}
	ls, err := parseListen(cfg.Settings)
	if err != nil {
		return nil, ls, err
	}
	if err := verifyTarget(ctx, ls.target.String(), ls.names, t.targetRoots, detectWait, t.control); err != nil {
		return nil, ls, err
	}
	if err := detect(ctx, upstreamRecords{}, ls.target.String(), ls.names, detectWait); err != nil {
		return nil, ls, err
	}
	lc := net.ListenConfig{Control: t.control}
	ln, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return nil, ls, fmt.Errorf("reality: %w", err)
	}
	return ln, ls, nil
}

// newListener is a listener on ln (nil for a worker's Handoff, which is
// handed its connections) at addr, deciding hellos with check.
func newListener(t *Transport, ln net.Listener, addr net.Addr, ls listenSettings, admission transport.Admission, check helloCheck) *listener {
	l := &listener{
		t:        t,
		ln:       ln,
		addr:     addr,
		settings: ls,
		peers:    admission.Peers,
		camo:     admission.Camouflage,
		check:    check,
		gate:     newGate(t, ls.target),
		accepted: make(chan accepted),
		closed:   make(chan struct{}),
		links:    map[shortID]*link{},
	}
	links, changed := l.peers.Snapshot()
	l.apply(links)
	go l.watch(changed)
	return l
}

type listener struct {
	t        *Transport
	ln       net.Listener // nil behind a shared listener
	addr     net.Addr
	settings listenSettings
	peers    transport.Peers
	camo     transport.Camouflage // nil: the mirror and splice to the target
	check    helloCheck
	gate     *gate // what isn't a link yet, and the splices

	accepted  chan accepted
	closed    chan struct{}
	closeOnce sync.Once

	mu    sync.Mutex
	table table
	links map[shortID]*link
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

func (l *listener) Addr() net.Addr { return l.addr }

func (l *listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		if l.ln != nil {
			err = l.ln.Close()
		}
		l.gate.close()
		l.mu.Lock()
		links := make([]*link, 0, len(l.links))
		for _, lk := range l.links {
			links = append(links, lk)
		}
		l.mu.Unlock()
		for _, lk := range links {
			lk.close(nil)
		}
	})
	return err
}

// Rejected lists the peer links of the table the listener can't use: ones
// reality refuses, and those sharing a short id with another (newTable).
func (l *listener) Rejected() []transport.PeerError {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.table.rejected
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
	l.mu.Lock()
	prev := l.table.links
	l.mu.Unlock()
	tab := newTable(l.t, links, prev)
	type closing struct {
		link  *link
		cause error
	}
	var toClose []closing
	l.mu.Lock()
	l.table = tab
	for id, lk := range l.links {
		pl, ok := tab.links[id]
		switch {
		case tab.refused[id] != nil:
			toClose = append(toClose, closing{lk, fmt.Errorf("%w: %w", transport.ErrSettingsRefused, tab.refused[id])})
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
		go l.serve(conn)
	}
}

// serve authenticates one connection: its ClientHello, read before
// anything is answered, must carry a sealed short id in the table, fresh
// and not seen before. An authenticated connection's TLS handshake is
// REALITY's, which imitates the target's.
func (l *listener) serve(conn net.Conn) {
	if l.camo != nil {
		l.serveCamouflaged(conn)
		return
	}
	var id shortID
	var peer transport.Identity
	_ = conn.SetReadDeadline(time.Now().Add(l.gate.helloTimeout))
	p, d := l.gate.decide(conn, func(record []byte) bool {
		var ok bool
		id, peer, ok = l.authenticate(record)
		return ok
	}, nil)
	if d != passedOn {
		return
	}
	defer l.gate.live.untrack(conn, p.target)
	ht := &handedTarget{Conn: p.target, held: p.held, skip: len(p.record) - heldBack}
	l.handshake(conn, p.record, id, peer, func(context.Context, string, string) (net.Conn, error) { return ht, nil })
}

// serveCamouflaged is serve with an Admission.Camouflage: the hello is
// read whole, or for helloTimeout, before anything is dialled, and what
// fails goes to the camouflage. It counts against the gate's bound on
// connections being decided.
func (l *listener) serveCamouflaged(conn net.Conn) {
	if !take(l.gate.mirrors) {
		_ = conn.Close()
		return
	}
	decided := sync.OnceFunc(func() { <-l.gate.mirrors })
	defer decided()
	if !l.gate.live.track(conn) {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(l.gate.helloTimeout))
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
	decided()
	if !ok {
		l.gate.live.untrack(conn)
		l.camo.Stream(conn, record)
		return
	}
	defer l.gate.live.untrack(conn)
	d := &net.Dialer{Control: l.t.control, Timeout: targetDialTimeout}
	l.handshake(conn, record, id, peer, d.DialContext)
}

// handshake runs REALITY's server on conn, whose ClientHello, record,
// authenticated, with dial giving it the target, and admits the result.
func (l *listener) handshake(conn net.Conn, record []byte, id shortID, peer transport.Identity, dial func(ctx context.Context, network, address string) (net.Conn, error)) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	tlsConn, err := xreality.Server(context.Background(), &replayConn{Conn: conn, prefix: record}, l.realityConfig(id, dial))
	if err != nil {
		return // REALITY spliced the connection to the target or closed it
	}
	_ = conn.SetDeadline(time.Time{})
	l.admit(tlsConn, conn, id, peer)
}

// authenticate checks a whole hello against the listener's own table
// (helloCheck.check).
func (l *listener) authenticate(record []byte) (shortID, transport.Identity, bool) {
	id, peer, v := l.check.check(l.settings, record, l.lookup, nil)
	return id, peer, v == transport.StreamRouted
}

func (l *listener) lookup(id shortID) (transport.PeerLink, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	pl, ok := l.table.links[id]
	return pl, ok
}

// openHello opens a whole hello's seal: one ClientHello for one of the
// server names, whose seal opens under the listener's key.
func (ls listenSettings) openHello(record []byte) (*clientHello, sealedHello, bool) {
	h, err := parseHello(record)
	if err != nil || !ls.names[h.serverName] {
		return nil, sealedHello{}, false
	}
	s, err := open(ls.key, h)
	if err != nil {
		return nil, sealedHello{}, false
	}
	return h, s, true
}

// admit makes an established connection a link: it replaces the
// credential's link, if any, and waits for Accept.
func (l *listener) admit(tlsConn, tcp net.Conn, id shortID, peer transport.Identity) {
	l.mu.Lock()
	pl, ok := l.table.links[id]
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

func (l *listener) realityConfig(id shortID, dial func(ctx context.Context, network, address string) (net.Conn, error)) *xreality.Config {
	return &xreality.Config{
		DialContext:                 dial,
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

// verifyTarget completes a TLS 1.3 handshake with the target for each
// server name, through control, within wait, and fails unless its
// certificate verifies against roots (nil: the system roots). REALITY's
// own detection stores the same empty result for a target whose
// certificate doesn't verify as for one that can't be reached, and the
// target would then be imitated without its post-handshake records; and
// REALITY imitates only a target's TLS 1.3 ServerHello, so with a target
// that doesn't speak TLS 1.3 every authenticated handshake would fail.
func verifyTarget(ctx context.Context, dest string, names map[string]bool, roots *x509.CertPool, wait time.Duration, control func(network, address string, c syscall.RawConn) error) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for name := range names {
		d := tls.Dialer{
			NetDialer: &net.Dialer{Control: control},
			Config:    &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13},
		}
		c, err := d.DialContext(ctx, "tcp", dest)
		// crypto/tls has no typed error for a version mismatch; both its
		// own and the target's (an alert) say "protocol version".
		if err != nil && strings.Contains(err.Error(), "protocol version") {
			return fmt.Errorf("reality: target %s for %q doesn't speak TLS 1.3: %w", dest, name, err)
		}
		if err != nil {
			return fmt.Errorf("reality: target %s for %q: %w", dest, name, err)
		}
		_ = c.Close()
	}
	return nil
}

// detect has REALITY learn the target's post-handshake records, which its
// handshake imitates, and waits up to wait for it. REALITY keeps what it
// learned per process; detect fails unless REALITY's detection ended for
// every server name and ALPN: left pending (the target stalled), REALITY
// would hold every authenticated handshake in 5-second sleeps for good.
//
// REALITY's detection runs on with no deadline of its own once detect
// gave up, and stores an empty result when it ends if its key still holds
// a pending one, so it would overwrite a later detection's pending key.
// Detections of a target are serialized, and a key detect gave up on is
// left pending and marked stale: a later detect waits for that earlier
// detection to end (failing while it runs), then forgets its result and
// detects again.
//
// A result on a stale key isn't yet the detection's last write: one that
// read the target's records stores them, then closes its connection and
// only then checks for a pending key, and that check, run on a fresh
// detection's pending key, would store an empty result over it. So a
// stale key's result is forgotten only once it has stood for staleGrace;
// only detect deletes keys, so a result seen twice that far apart is the
// same one.
func detect(ctx context.Context, store recordsStore, dest string, names map[string]bool, wait time.Duration) error {
	dd := detectionOf(dest)
	dd.mu.Lock()
	defer dd.mu.Unlock()
	var keys []string
	for name := range names {
		for alpn := range detectedALPNs {
			keys = append(keys, recordsKey(dest, name, alpn))
		}
	}
	cfg := &xreality.Config{Type: "tcp", Dest: dest, ServerNames: names}
	store.detect(cfg)
	deadline := time.Now().Add(wait)
	for {
		var pending []string
		redetect := false
		now := time.Now()
		for _, key := range keys {
			v, ok := store.load(key)
			if !ok {
				// Only detect deletes keys, holding dd.mu, and
				// store.detect ran since.
				return fmt.Errorf("%w: nothing under %q", errRecordsKeyFormat, key)
			}
			_, done := v.([]int)
			stale, wasStale := dd.stale[key]
			switch {
			case done && wasStale && stale.IsZero():
				dd.stale[key] = now
				pending = append(pending, key)
			case done && wasStale && now.Sub(stale) < staleGrace:
				pending = append(pending, key)
			case done && wasStale:
				store.delete(key)
				delete(dd.stale, key)
				redetect = true
				pending = append(pending, key)
			case !done:
				pending = append(pending, key)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if redetect {
			store.detect(cfg)
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			earlier := false
			for _, key := range pending {
				if _, wasStale := dd.stale[key]; wasStale {
					earlier = true
				} else {
					dd.stale[key] = time.Time{}
				}
			}
			if earlier {
				return fmt.Errorf("reality: target %s: a detection of its records from an earlier Listen hasn't finished", dest)
			}
			return fmt.Errorf("reality: target %s didn't complete a TLS handshake for every server name in %v", dest, wait)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// staleGrace is how long a result on a stale key stands before detect
// forgets it: far longer than REALITY's detection takes from storing its
// result to its last check of the key.
const staleGrace = time.Second

// recordsStore is where REALITY's detection keeps a target's records:
// upstreamRecords, or a fake in tests.
type recordsStore interface {
	detect(cfg *xreality.Config)
	load(key string) (any, bool)
	delete(key string)
}

// upstreamRecords is REALITY's own detection and its per-process store.
type upstreamRecords struct{}

func (upstreamRecords) detect(cfg *xreality.Config) { xreality.DetectPostHandshakeRecordsLens(cfg) }

func (upstreamRecords) load(key string) (any, bool) {
	return xreality.GlobalPostHandshakeRecordsLens.Load(key)
}

func (upstreamRecords) delete(key string) { xreality.GlobalPostHandshakeRecordsLens.Delete(key) }

// errRecordsKeyFormat is detect finding nothing where REALITY keeps a
// target's records: the pinned module's key format changed.
var errRecordsKeyFormat = errors.New("reality: REALITY's records key format changed")

// targetDetection serializes detect for one target and keeps the keys
// whose detection detect gave up on, each with when a result was first
// seen on it (zero: not yet).
type targetDetection struct {
	mu    sync.Mutex
	stale map[string]time.Time
}

var detections = struct {
	mu     sync.Mutex
	byDest map[string]*targetDetection
}{byDest: map[string]*targetDetection{}}

func detectionOf(dest string) *targetDetection {
	detections.mu.Lock()
	defer detections.mu.Unlock()
	dd := detections.byDest[dest]
	if dd == nil {
		dd = &targetDetection{stale: map[string]time.Time{}}
		detections.byDest[dest] = dd
	}
	return dd
}

// detectedALPNs is how many ALPN cases REALITY detects per server name: no
// ALPN, http/1.1, h2.
const detectedALPNs = 3

// recordsKey is REALITY's key for a target's records in
// GlobalPostHandshakeRecordsLens, as record_detect.go builds it at the
// pinned commit; TestRecordsKeyIsREALITYs fails if it changes.
func recordsKey(dest, serverName string, alpn int) string {
	return fmt.Sprintf("%s %s %d", dest, serverName, alpn)
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
	return c.Close()
}
