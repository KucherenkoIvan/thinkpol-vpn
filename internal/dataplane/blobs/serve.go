package blobs

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// listener is one served address.
type listener struct {
	l      net.Listener
	iface  string
	closed atomic.Bool // by listenLoop
	done   chan struct{}
}

// listenLoop keeps a listener on each of the plan's addresses, reopening
// those that fail to open or stop on their own after ListenRetry, and
// serves what they accept, until ctx ends.
func (s *Service) listenLoop(ctx context.Context) {
	var conns sync.WaitGroup
	active := &activeConns{m: map[net.Conn]struct{}{}}
	open := map[netip.AddrPort]*listener{}
	retryAt := map[netip.AddrPort]time.Time{}
	ended := make(chan struct{}, 1)
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	closeListener := func(l *listener) {
		l.closed.Store(true)
		_ = l.l.Close()
		<-l.done
	}
	defer func() {
		retry.Stop()
		for _, l := range open {
			closeListener(l)
		}
		active.closeAll()
		conns.Wait()
	}()
	for {
		p := s.snapshot()
		now := time.Now()
		want := map[netip.AddrPort]bool{}
		for _, a := range p.Listen {
			want[netip.AddrPortFrom(a, Port)] = true
		}
		for addr, l := range open {
			switch {
			case !want[addr] || l.iface != p.Interface:
				closeListener(l)
				delete(open, addr)
			case isDone(l.done):
				delete(open, addr)
				retryAt[addr] = now.Add(s.limits.ListenRetry)
			}
		}
		var next time.Time
		for addr := range retryAt {
			if !want[addr] {
				delete(retryAt, addr)
			}
		}
		for addr := range want {
			if open[addr] != nil {
				continue
			}
			if at, ok := retryAt[addr]; ok && now.Before(at) {
				if next.IsZero() || at.Before(next) {
					next = at
				}
				continue
			}
			ln, err := s.openListener(addr, p.Interface)
			if err != nil {
				at := now.Add(s.limits.ListenRetry)
				retryAt[addr] = at
				if next.IsZero() || at.Before(next) {
					next = at
				}
				s.log.Warn("blob service: listening failed, retrying", "address", addr, "in", s.limits.ListenRetry, "err", err)
				continue
			}
			delete(retryAt, addr)
			l := &listener{l: ln, iface: p.Interface, done: make(chan struct{})}
			open[addr] = l
			go s.accept(ctx, l, &conns, active, ended)
		}
		if !next.IsZero() {
			retry.Reset(time.Until(next))
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wakeListen:
		case <-retry.C:
		case <-ended:
		}
	}
}

func isDone(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// openListener opens the listener for addr: the test's overlay, or the
// node's real one, bound to the overlay's TUN (iface).
func (s *Service) openListener(addr netip.AddrPort, iface string) (net.Listener, error) {
	if s.listen != nil {
		return s.listen(addr)
	}
	lc := net.ListenConfig{Control: bindTo(iface)}
	return lc.Listen(context.Background(), "tcp", addr.String())
}

type activeConns struct {
	mu     sync.Mutex
	m      map[net.Conn]struct{}
	closed bool
}

func (a *activeConns) add(c net.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	a.m[c] = struct{}{}
	return true
}

func (a *activeConns) remove(c net.Conn) {
	a.mu.Lock()
	delete(a.m, c)
	a.mu.Unlock()
}

func (a *activeConns) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for c := range a.m {
		_ = c.Close()
	}
}

// accept serves l's connections until it closes.
func (s *Service) accept(ctx context.Context, l *listener, conns *sync.WaitGroup, active *activeConns, ended chan struct{}) {
	for {
		c, err := l.l.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Closed before done, so a retry can bind the address again.
			_ = l.l.Close()
			close(l.done)
			if !l.closed.Load() {
				s.log.Warn("blob service: a listener stopped, reopening", "address", l.l.Addr(), "in", s.limits.ListenRetry, "err", err)
				signal(ended)
			}
			return
		}
		if !active.add(c) {
			_ = c.Close()
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer active.remove(c)
			defer func() { _ = c.Close() }()
			s.serveConn(ctx, c)
		}()
	}
}

// remoteAddr is a connection's peer address: inside the tunnel, the
// overlay address WireGuard authenticated.
func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// peerOfLocked is the current plan's peer with that overlay address (a
// peer has several): who a connection counts against. The plan is the
// access control, and this is the one place it is asked: when a
// connection is admitted and before each chunk it is sent. That covers a
// transfer within one map transition, for an address the new map drops
// or reassigns to another peer in the same map: it gets no chunk after
// the new plan is in, and its connection is reset (abort), so nothing
// already buffered reaches it either.
func (s *Service) peerOfLocked(remote netip.Addr) (string, bool) {
	key, ok := s.peerOf[remote]
	return key, ok
}

// stillPeer reports whether remote still is key's under the current plan.
func (s *Service) stillPeer(remote netip.Addr, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.peerOfLocked(remote)
	return ok && k == key
}

// errNotPeer is a connection from no peer of the plan.
var errNotPeer = errors.New("blobs: not a peer")

// admit takes a connection slot for remote's peer, or says the service is
// busy, or that remote is no peer: through the tunnel every source is a
// peer's overlay address (WireGuard's allowed IPs), so anything else came
// from elsewhere (a process on the node itself) and gets nothing.
func (s *Service) admit(remote netip.Addr) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.peerOfLocked(remote)
	if !ok {
		s.st.NotPeer++
		return "", errNotPeer
	}
	if s.nconns >= s.limits.MaxConns || s.conns[key] >= s.limits.MaxConnsPerPeer {
		s.st.Busy++
		return "", errBusy
	}
	s.nconns++
	s.conns[key]++
	return key, nil
}

func (s *Service) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nconns--
	if s.conns[key]--; s.conns[key] <= 0 {
		delete(s.conns, key)
	}
}

// serveConn answers one request.
func (s *Service) serveConn(ctx context.Context, c net.Conn) {
	remote := remoteAddr(c)
	idle := func() { _ = c.SetDeadline(time.Now().Add(s.limits.IdleTimeout)) }
	idle()
	key, err := s.admit(remote)
	switch {
	case errors.Is(err, errNotPeer):
		return // closed without a word
	case err != nil:
		_, _ = c.Write([]byte{byte(statusBusy)})
		return
	}
	defer s.release(key)

	var b [requestSize]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return
	}
	req, err := decodeRequest(b)
	if err != nil {
		_, _ = c.Write([]byte{byte(statusBadRequest)})
		return
	}
	s.mu.Lock()
	data, ok := s.data[req.sha256]
	if !ok {
		s.st.NotHere++
	}
	s.mu.Unlock()
	switch {
	case !ok:
		_, _ = c.Write([]byte{byte(statusNotHere)})
		return
	case req.offset > uint64(len(data)):
		_, _ = c.Write([]byte{byte(statusBadRequest)})
		return
	}
	rest := data[req.offset:]
	// A peer that reads slowly holds its slot no longer than a transfer
	// at the minimum rate (or its share of the serving rate) takes.
	rate := min(s.limits.MinRate, max(1, s.limits.ServeRate/int64(s.limits.MaxConns)))
	tctx, cancel := context.WithTimeout(ctx, s.limits.transferTimeout(uint64(len(rest)), rate))
	defer cancel()
	ctx = tctx
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	var head [responseHeaderSize]byte
	head[0] = byte(statusOK)
	binary.BigEndian.PutUint64(head[1:], uint64(len(rest)))
	if _, err := c.Write(head[:]); err != nil {
		return
	}
	const chunk = 16 << 10
	for len(rest) > 0 {
		n := min(chunk, len(rest))
		if err := s.rate.wait(ctx, n); err != nil {
			return
		}
		if !s.stillPeer(remote, key) {
			abort(c)
			return
		}
		idle()
		if _, err := c.Write(rest[:n]); err != nil {
			return
		}
		rest = rest[n:]
		s.count(func(st *Status) { st.ServedBytes += uint64(n) })
	}
	s.count(func(st *Status) { st.Served++ })
	s.log.Debug("blob served", "blob", hex.EncodeToString(req.sha256[:6]), "peer", remote)
}

// abort closes c with a reset where it can (no linger), so what is still
// buffered for the peer is dropped instead of delivered.
func abort(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(sec int) error }); ok {
		_ = l.SetLinger(0)
	}
	_ = c.Close()
}

// limiter is a token bucket shared by every transfer: rate bytes per
// second, bursts of one chunk.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newLimiter(rate int64, now func() time.Time) *limiter {
	burst := float64(min(rate, 64<<10))
	return &limiter{rate: float64(rate), burst: burst, tokens: burst, last: now(), now: now}
}

// wait takes n tokens, waiting until the bucket has them (it may go into
// debt, which later callers wait out).
func (l *limiter) wait(ctx context.Context, n int) error {
	l.mu.Lock()
	now := l.now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	l.tokens -= float64(n)
	debt := -l.tokens
	l.mu.Unlock()
	if debt <= 0 {
		return nil
	}
	t := time.NewTimer(time.Duration(debt / l.rate * float64(time.Second)))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
