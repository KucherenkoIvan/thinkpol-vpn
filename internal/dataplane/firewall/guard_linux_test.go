//go:build linux && !android

package firewall_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// pair is a device namespace whose eth0 is a veth to a gateway namespace,
// which answers for the "sites" on its lo; the device also has a TUN-like
// dummy thinkpol0. No route table: what isn't guarded leaves by eth0.
type pair struct{ dev, gw string }

const (
	foreign6  = "2001:db8:ab::7" // a site only the tunnel may reach
	domestic6 = "2001:db8:d0::7" // a direct site
)

func newPair(t *testing.T) *pair {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	p := &pair{dev: "fw-" + hex.EncodeToString(b), gw: "fwgw-" + hex.EncodeToString(b)}
	for _, ns := range []string{p.dev, p.gw} {
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("ip netns add: %v: %s", err, out)
		}
		t.Cleanup(func() { _, _ = exec.Command("ip", "netns", "del", ns).CombinedOutput() })
	}
	p.ip(t, p.dev, "link", "add", "eth0", "type", "veth", "peer", "name", "gw0", "netns", p.gw)
	for _, args := range [][]string{
		{"link", "add", "thinkpol0", "type", "dummy"},
		{"link", "set", "lo", "up"},
		{"link", "set", "eth0", "up"},
		{"link", "set", "thinkpol0", "up"},
		{"addr", "add", "192.0.2.2/24", "dev", "eth0"},
		{"addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad"},
		{"route", "add", "default", "via", "192.0.2.1"},
		{"-6", "route", "add", "default", "via", "2001:db8:1::1"},
	} {
		p.ip(t, p.dev, args...)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "gw0", "up"},
		{"addr", "add", "192.0.2.1/24", "dev", "gw0"},
		{"addr", "add", "2001:db8:1::1/64", "dev", "gw0", "nodad"},
		{"addr", "add", foreign6 + "/128", "dev", "lo"},
		{"addr", "add", domestic6 + "/128", "dev", "lo"},
		{"addr", "add", "2a00:2::1/128", "dev", "lo"},
		{"addr", "add", "2a00:1::1/128", "dev", "lo"},
	} {
		p.ip(t, p.gw, args...)
	}
	return p
}

func (p *pair) ip(t *testing.T, ns string, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"-n", ns}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip -n %s %s: %v: %s", ns, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (p *pair) guard(t *testing.T) *firewall.IPv6Guard {
	t.Helper()
	g, err := firewall.NewIPv6GuardInNamespace("/run/netns/" + p.dev)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// ping says whether one ping from the device, with ping's own extra
// arguments (-I eth0, -m mark), is answered.
func (p *pair) ping(t *testing.T, dst string, args ...string) bool {
	t.Helper()
	cmd := append([]string{"netns", "exec", p.dev, "ping", "-6", "-c", "1", "-W", "2"}, args...)
	out, err := exec.Command("ip", append(cmd, dst)...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "100% packet loss") && !strings.Contains(string(out), "not permitted") {
		t.Logf("ping %s %s: %v: %s", strings.Join(args, " "), dst, err, out)
	}
	return err == nil
}

func (p *pair) table(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("ip", "netns", "exec", p.dev, "nft", "list", "tables").CombinedOutput()
	return string(out)
}

// inNamespace runs f on a thread in the device's namespace (sockets it
// opens stay there).
func (p *pair) inNamespace(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		ns, err := netns.GetFromName(p.dev)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = ns.Close() }()
		if err := netns.Set(ns); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

// dialBound connects a TCP socket bound to eth0 (SO_BINDTODEVICE) to
// dst:80 from the device's namespace.
func (p *pair) dialBound(t *testing.T, dst string) error {
	t.Helper()
	var err error
	p.inNamespace(t, func() {
		var fd int
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err = unix.BindToDevice(fd, "eth0"); err != nil {
			return
		}
		tv := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
		err = unix.Connect(fd, &unix.SockaddrInet6{Port: 80, Addr: netip.MustParseAddr(dst).As16()})
	})
	return err
}

// The guard refuses IPv6 out of a physical interface, bound or not, but
// to direct destinations and endpoints, from the links' marked sockets,
// and on the link itself; IPv4 isn't its business; a removed table comes
// back with the next Apply; Close removes it.
func TestIPv6GuardRefusesWhatRoutingCantConfine(t *testing.T) {
	p := newPair(t)
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("the gateway doesn't answer without a guard: the test proves nothing")
	}
	g := p.guard(t)
	e := firewall.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: set(t, "2001:db8:d0::/48", "198.51.100.0/24")}
	ctx := context.Background()
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect := func(when string) {
		t.Helper()
		for _, c := range []struct {
			dst  string
			args []string
			want bool
		}{
			{foreign6, []string{"-I", "eth0"}, false},        // bound to the physical interface
			{foreign6, nil, false},                           // unbound, by main's routes (no route table here)
			{domestic6, []string{"-I", "eth0"}, true},        // direct
			{foreign6, []string{"-m", "29808"}, true},        // a link's marked socket
			{"ff02::1", []string{"-I", "eth0"}, true},        // the link itself (the gateway answers)
			{"2001:db8:1::1", []string{"-I", "eth0"}, false}, // the gateway's global address: not on-link trust
		} {
			if got := p.ping(t, c.dst, c.args...); got != c.want {
				t.Errorf("%s: ping %s %v answered %v, want %v", when, c.dst, c.args, got, c.want)
			}
		}
		// TCP is refused with a reset, at once.
		start := time.Now()
		if err := p.dialBound(t, foreign6); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 2*time.Second {
			t.Errorf("%s: a TCP connect bound to eth0: %v after %v, want refused at once", when, err, time.Since(start))
		}
		out, err := exec.Command("ip", "netns", "exec", p.dev, "ping", "-4", "-c", "1", "-W", "2", "-I", "eth0", "192.0.2.1").CombinedOutput()
		if err != nil {
			t.Errorf("%s: IPv4 (the kill switch's, TP-048) refused: %v: %s", when, err, out)
		}
	}
	expect("applied")

	// The same again checks the table and leaves it; someone deleting it
	// gets it back with the next Apply.
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "netns", "exec", p.dev, "nft", "delete", "table", "inet", firewall.GuardTable).CombinedOutput(); err != nil {
		t.Fatalf("nft delete table: %v: %s", err, out)
	}
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("still refused with the table deleted")
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect("re-applied after a deletion")

	// A successor (a restart after a crash) takes the table over.
	g2 := p.guard(t)
	if err := g2.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.table(t), firewall.GuardTable) {
		t.Errorf("a successor's Close left the table:\n%s", p.table(t))
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.table(t), firewall.GuardTable) {
		t.Errorf("Close left the table:\n%s", p.table(t))
	}
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Error("refused after Close")
	}
	if err := g.Apply(ctx, e); err == nil {
		t.Error("Apply after Close succeeded")
	}
}

// A country-sized direct set (RU's IPv6: ~10k prefixes) goes into one
// transaction quickly, and the interval set matches by range.
func TestIPv6GuardTakesACountrySizedSet(t *testing.T) {
	p := newPair(t)
	var b lists.Builder
	for i := range 10088 {
		n := uint32(0x2a000000) + uint32(i)*2 // every other /32 from 2a00::
		_ = b.AddPrefix(netip.PrefixFrom(netip.AddrFrom16([16]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), 32))
	}
	_ = b.AddPrefix(netip.MustParsePrefix("ff00::/8")) // up to the last address: an interval with no end
	direct, _ := b.Build()
	g := p.guard(t)
	start := time.Now()
	if err := g.Apply(context.Background(), firewall.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: direct}); err != nil {
		t.Fatal(err)
	}
	t.Logf("applied %d ranges in %v", len(firewall.Exempt{Direct: direct}.Ranges6()), time.Since(start).Round(time.Millisecond))
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("took %v", took)
	}
	if !p.ping(t, "2a00:2::1", "-I", "eth0") {
		t.Error("a destination inside a direct /32 refused")
	}
	if p.ping(t, "2a00:1::1", "-I", "eth0") {
		t.Error("a destination between direct /32s answered")
	}
	if p.ping(t, foreign6, "-I", "eth0") {
		t.Error("a foreign destination answered")
	}
}
