package ifbind

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A socket opened through Control carries IP_BOUND_IF (or IPV6_BOUND_IF)
// with the picked interface's index; only a socket option, nothing is
// sent.
func TestSocketsAreBoundToThePickedInterface(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0:", err)
	}
	for _, tc := range []struct {
		network, address string
		level, opt       int
	}{
		{"udp4", "127.0.0.1:9", unix.IPPROTO_IP, unix.IP_BOUND_IF},
		{"udp6", "[::1]:9", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF},
	} {
		var picked []bool
		d := net.Dialer{Control: Control(func(ipv6 bool) (Interface, error) {
			picked = append(picked, ipv6)
			return Interface{Name: "lo0"}, nil
		})}
		c, err := d.DialContext(context.Background(), tc.network, tc.address)
		if err != nil {
			t.Fatalf("%s: %v", tc.network, err)
		}
		raw, _ := c.(syscall.Conn).SyscallConn()
		var got int
		var gerr error
		_ = raw.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), tc.level, tc.opt) })
		_ = c.Close()
		if gerr != nil || got != lo.Index {
			t.Errorf("%s: bound to %d (%v), want lo0's %d", tc.network, got, gerr, lo.Index)
		}
		if len(picked) != 1 || picked[0] != (tc.network == "udp6") {
			t.Errorf("%s: picked with %v", tc.network, picked)
		}
	}
}

// A socket whose interface can't be picked never opens.
func TestASocketWithoutAnInterfaceFailsToOpen(t *testing.T) {
	refused := errors.New("no default route")
	d := net.Dialer{Control: Control(func(bool) (Interface, error) { return Interface{}, refused })}
	if c, err := d.DialContext(context.Background(), "udp4", "127.0.0.1:9"); !errors.Is(err, refused) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("dial: %v, want the pick's error", err)
	}
	d = net.Dialer{Control: ByName("no-such-interface0")}
	if c, err := d.DialContext(context.Background(), "udp4", "127.0.0.1:9"); err == nil {
		_ = c.Close()
		t.Fatal("dial bound to a missing interface succeeded")
	}
}
