package routetable

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// Each socket is bound to its family's physical interface as it opens;
// one without a default route for its family never opens. Only socket
// options: nothing is sent, and the default route is a stand-in.
func TestSocketsAreBoundToThePhysicalInterface(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0:", err)
	}
	var asked []netcfg.Family
	physicalInterface = func(f netcfg.Family) (string, int, error) {
		asked = append(asked, f)
		if f == netcfg.IPv6 {
			return "", 0, netcfg.ErrNoDefaultRoute
		}
		return lo.Name, lo.Index, nil
	}
	t.Cleanup(func() { physicalInterface = netcfg.DefaultInterface })
	d := net.Dialer{Control: SocketControl()}
	c, err := d.DialContext(context.Background(), "udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := c.(syscall.Conn).SyscallConn()
	var bound int
	_ = raw.Control(func(fd uintptr) { bound, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) })
	_ = c.Close()
	if bound != lo.Index {
		t.Errorf("bound to %d, want %d", bound, lo.Index)
	}
	if c, err := d.DialContext(context.Background(), "udp6", "[::1]:9"); !errors.Is(err, netcfg.ErrNoDefaultRoute) {
		if c != nil {
			_ = c.Close()
		}
		t.Errorf("IPv6 without a default route: %v", err)
	}
	if len(asked) != 2 || asked[0] != netcfg.IPv4 || asked[1] != netcfg.IPv6 {
		t.Errorf("asked for %v", asked)
	}
}
