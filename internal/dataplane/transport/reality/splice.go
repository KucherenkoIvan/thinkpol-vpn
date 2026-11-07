package reality

import (
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// splice is reality's camouflage: a connection that failed authentication
// is joined, raw and whole, to the target, starting with the bytes the
// listener already read. The prober completes a handshake with the real
// site and sees its certificate. A target that can't be reached closes the
// connection, as a relay whose upstream is down would.
type splice struct {
	t      *Transport
	target netip.AddrPort
}

var _ transport.Camouflage = (*splice)(nil)

func (s *splice) Datagram([]byte, net.Addr) {}

func (s *splice) Stream(conn net.Conn, consumed []byte) {
	go s.join(conn, consumed)
}

func (s *splice) join(conn net.Conn, consumed []byte) {
	d := net.Dialer{Control: s.t.control, Timeout: helloTimeout}
	up, err := d.Dial("tcp", s.target.String())
	if err != nil {
		_ = conn.Close()
		return
	}
	if _, err := up.Write(consumed); err != nil {
		_ = up.Close()
		_ = conn.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(up, conn) }()
	go func() { defer wg.Done(); pipe(conn, up) }()
	wg.Wait()
	_ = up.Close()
	_ = conn.Close()
}

// pipe copies until src ends, then half-closes dst, so each side's FIN
// reaches the other; an error closes both ways.
func pipe(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
		_ = cw.CloseWrite()
		return
	}
	_ = dst.Close()
	_ = src.Close()
}
