package path

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// errHostUnreach stands for the kernel's error (the path layer names no
// syscall).
var errHostUnreach = errors.New("sendto: no route to host")

// Errors in logs say what failed, never where: a *net.OpError quotes both
// ends of a socket.
func TestRedactedErrorsQuoteNoAddress(t *testing.T) {
	for _, err := range []error{
		&net.OpError{Op: "write", Net: "udp", Source: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.0.113:50123")),
			Addr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.7:4500")), Err: errHostUnreach},
		&net.OpError{Op: "read", Net: "udp", Source: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[fe80::1%en0]:50123")),
			Addr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::7]:4500")), Err: errors.New("connection refused")},
		errors.New("dial udp 2001:db8::7: no route"),
	} {
		got := redact(err)
		for _, addr := range []string{"192.168.0.113", "203.0.113.7", "50123", "4500", "fe80::1", "2001:db8::7"} {
			if strings.Contains(got, addr) {
				t.Errorf("%q quotes %s", got, addr)
			}
		}
		if !strings.Contains(got, "<addr>") {
			t.Errorf("%q: nothing redacted", got)
		}
	}
	if got := redact(errHostUnreach); got != errHostUnreach.Error() {
		t.Errorf("an error without an address became %q", got)
	}
}

func TestRedactLeavesNoAddressDigits(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"peer ::ffff:192.0.2.1 timed out", "peer <addr> timed out"},
		{"dial [::ffff:192.0.2.1]:80: refused", "dial <addr>: refused"},
		{"send on fe80::1%en0 failed", "send on <addr> failed"},
		{"connect [2001:db8::1]:443: timeout", "connect <addr>: timeout"},
		{"route 192.0.2.1:443 unreachable", "route <addr> unreachable"},
		{"no path to 2001:db8::1", "no path to <addr>"},
	} {
		got := redact(errors.New(tc.in))
		if got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
		for _, digit := range []string{"192", "0.2", "2001", "db8", "fe80", "443", "80"} {
			if strings.Contains(got, digit) {
				t.Errorf("%q still quotes %s", got, digit)
			}
		}
	}
}

// fakeLink is a transport link whose far end can move.
type fakeLink struct {
	mu     sync.Mutex
	remote net.Addr
	done   chan struct{}
	once   sync.Once
}

func (f *fakeLink) ReadPacket([]byte) (int, error) { <-f.done; return 0, net.ErrClosed }
func (f *fakeLink) WritePacket([]byte) error       { return nil }
func (f *fakeLink) Close() error                   { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeLink) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.10:4500"))
}
func (f *fakeLink) RemoteAddr() net.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.remote
}

// A listener's link following its dialer to a new address (a NAT rebind)
// is logged at info level, the addresses by their tags only.
func TestARemoteThatMovesIsLoggedByItsTag(t *testing.T) {
	var out bytes.Buffer
	// The node's watcher stays out of the way: the test calls it itself.
	n, err := NewNode(NodeID{1}, Options{Log: slog.New(slog.NewTextHandler(&out, nil)), watchEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	before := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.20:61000"))
	after := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.20:61999"))
	tl := &fakeLink{remote: before, done: make(chan struct{})}
	l := n.addLink(NodeID{2}, tl, false, "udp", -1)
	l.watchRemote()
	if strings.Contains(out.String(), "moved") {
		t.Fatalf("logged a move that didn't happen:\n%s", out.String())
	}
	tl.mu.Lock()
	tl.remote = after
	tl.mu.Unlock()
	l.watchRemote()
	line := out.String()
	want := []string{`msg="link remote moved"`, "local_port=4500", "remote=" + remoteTag(after.String()), "previous=" + remoteTag(before.String())}
	for _, w := range want {
		if !strings.Contains(line, w) {
			t.Errorf("log lacks %s:\n%s", w, line)
		}
	}
	if strings.Contains(line, "198.51.100.20") || strings.Contains(line, "61999") {
		t.Errorf("log quotes the address:\n%s", line)
	}
}
