package blobs

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// sources maps loopback connections to the overlay addresses they stand
// for, so a server sees a dialer's overlay address as the connection's
// remote end, as it would through the tunnel.
type sources struct {
	mu sync.Mutex
	m  map[string]netip.Addr // the dialer's loopback address → its overlay address
}

func (s *sources) note(c net.Conn, overlay netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]netip.Addr{}
	}
	s.m[c.LocalAddr().String()] = overlay
}

func (s *sources) lookup(real net.Addr) (netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[real.String()]
	return a, ok
}

// listener presents accepted connections with their dialers' overlay
// addresses.
type overlayListener struct {
	net.Listener
	src *sources
}

func (l overlayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &overlayConn{Conn: c, src: l.src}, nil
}

type overlayConn struct {
	net.Conn
	src *sources
}

// SetLinger reaches the TCP connection underneath, as on the overlay.
func (c *overlayConn) SetLinger(sec int) error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.SetLinger(sec)
	}
	return nil
}

// RemoteAddr waits briefly for the dialer to note its overlay address
// (the kernel completes the connection before Dial returns), and is the
// loopback address of a dialer that noted none.
func (c *overlayConn) RemoteAddr() net.Addr {
	for range 100 {
		if a, ok := c.src.lookup(c.Conn.RemoteAddr()); ok {
			return net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 1))
		}
		time.Sleep(time.Millisecond)
	}
	return c.Conn.RemoteAddr()
}
