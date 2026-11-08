//go:build linux && !android

package firewall_test

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

const (
	foreign4 = "203.0.113.7"  // a site only the tunnel may reach
	entry4   = "203.0.113.50" // an entry's endpoint
	entry6   = "2001:db8:e::50"
	lan4     = "10.9.0.1" // a private address beyond the gateway
)

// ksPair is newPair with IPv4 sites, an entry of each family and a
// private address on the gateway's lo.
func ksPair(t *testing.T) *pair {
	t.Helper()
	p := newPair(t)
	for _, a := range []string{foreign4 + "/32", entry4 + "/32", lan4 + "/32"} {
		p.ip(t, p.gw, "addr", "add", a, "dev", "lo")
	}
	p.ip(t, p.gw, "addr", "add", entry6+"/128", "dev", "lo")
	return p
}

func (p *pair) killSwitch(t *testing.T) *firewall.KillSwitch {
	t.Helper()
	k, err := firewall.NewKillSwitchInNamespace("/run/netns/" + p.dev)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k
}

// ping4 says whether one IPv4 ping from the device is answered.
func (p *pair) ping4(t *testing.T, dst string, args ...string) bool {
	t.Helper()
	cmd := append([]string{"netns", "exec", p.dev, "ping", "-4", "-c", "1", "-W", "2"}, args...)
	return exec.Command("ip", append(cmd, dst)...).Run() == nil
}

// inNS runs f on a thread in namespace name.
func inNS(t *testing.T, name string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		ns, err := netns.GetFromName(name)
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

// dial4 connects TCP from the device to dst:80, bound to dev if set, and
// returns the error (nil: connected) within 3 s.
func (p *pair) dial4(t *testing.T, dst, dev string) error {
	t.Helper()
	var err error
	inNS(t, p.dev, func() {
		var fd int
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if dev != "" {
			if err = unix.BindToDevice(fd, dev); err != nil {
				return
			}
		}
		tv := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: 80, Addr: netip.MustParseAddr(dst).As4()})
	})
	return err
}

// dhcp4 says whether a UDP datagram from the device's port 68 reaches
// the gateway's port 67.
func (p *pair) dhcp4(t *testing.T) bool {
	t.Helper()
	var rfd int
	var err error
	inNS(t, p.gw, func() {
		if rfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		tv := unix.NsecToTimeval((2 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(rfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		err = unix.Bind(rfd, &unix.SockaddrInet4{Port: 67})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rfd) }()
	inNS(t, p.dev, func() {
		var fd int
		if fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err = unix.Bind(fd, &unix.SockaddrInet4{Port: 68}); err != nil {
			return
		}
		err = unix.Sendto(fd, []byte("discover"), 0, &unix.SockaddrInet4{Port: 67, Addr: [4]byte{192, 0, 2, 1}})
	})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := unix.Recvfrom(rfd, buf, 0)
	return err == nil && string(buf[:n]) == "discover"
}

// ksHandles are the kill switch chain's rule handles, in order.
func (p *pair) ksHandles(t *testing.T) string {
	t.Helper()
	out := p.nft(t, "-a", "list", "chain", "inet", firewall.KillSwitchTable, "output")
	var hs []string
	for _, m := range regexp.MustCompile(`# handle (\d+)`).FindAllStringSubmatch(out, -1) {
		hs = append(hs, m[1])
	}
	return strings.Join(hs, " ")
}

// With the tunnel down, the kill switch lets out only the entries, the
// links' marked sockets, DHCP and the link's own ND, both families, bound
// sockets or not; with allow-LAN the LAN too. Refused TCP gets a reset at
// once. Connected, the TUN and the direct destinations pass too.
func TestKillSwitchLetsOutOnlyEntriesWhileDown(t *testing.T) {
	p := ksPair(t)
	if !p.ping4(t, foreign4) || !p.ping(t, foreign6) {
		t.Fatal("the gateway doesn't answer without a kill switch: the test proves nothing")
	}
	k := p.killSwitch(t)
	ctx := context.Background()
	down := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128")}
	if err := k.Apply(ctx, down); err != nil {
		t.Fatal(err)
	}
	type probe struct {
		name string
		ok   func() bool
		want bool
	}
	check := func(when string, ps []probe) {
		t.Helper()
		for _, c := range ps {
			if got := c.ok(); got != c.want {
				t.Errorf("%s: %s answered %v, want %v", when, c.name, got, c.want)
			}
		}
	}
	downProbes := func(lan bool) []probe {
		return []probe{
			{"ping foreign4", func() bool { return p.ping4(t, foreign4) }, false},
			{"ping foreign4 bound to eth0", func() bool { return p.ping4(t, foreign4, "-I", "eth0") }, false},
			{"ping foreign6", func() bool { return p.ping(t, foreign6) }, false},
			{"ping foreign6 bound to eth0", func() bool { return p.ping(t, foreign6, "-I", "eth0") }, false},
			{"ping the entry4", func() bool { return p.ping4(t, entry4) }, true},
			{"ping the entry6 bound to eth0", func() bool { return p.ping(t, entry6, "-I", "eth0") }, true},
			{"ping foreign4 from a marked socket", func() bool { return p.ping4(t, foreign4, "-m", "29808") }, true},
			{"ping foreign6 from a marked socket", func() bool { return p.ping(t, foreign6, "-m", "29808") }, true},
			{"DHCPv4 to the gateway", func() bool { return p.dhcp4(t) }, true},
			{"ping lan4", func() bool { return p.ping4(t, lan4) }, lan},
			{"ping ff02::1 on eth0", func() bool { return p.ping(t, "ff02::1", "-I", "eth0") }, lan},
		}
	}
	check("down", downProbes(false))
	start := time.Now()
	if err := p.dial4(t, foreign4, "eth0"); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 2*time.Second {
		t.Errorf("down: a TCP connect bound to eth0: %v after %v, want refused at once", err, time.Since(start))
	}

	lan := down
	lan.Allow = set(t, append([]string{entry4 + "/32", entry6 + "/128"}, prefixStrings(firewall.LAN)...)...)
	if err := k.Apply(ctx, lan); err != nil {
		t.Fatal(err)
	}
	check("down, allow-LAN", downProbes(true))

	// Connected: the TUN and the direct destinations too.
	up := firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128", domestic6+"/128")}
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	check("connected", []probe{
		{"ping domestic6", func() bool { return p.ping(t, domestic6) }, true},
		{"ping foreign6", func() bool { return p.ping(t, foreign6) }, false},
		{"ping foreign4", func() bool { return p.ping4(t, foreign4) }, false},
	})
	// A connect bound to the TUN (a dummy that drops) isn't refused: it
	// times out, where one bound to eth0 is reset.
	if err := p.dial4(t, foreign4, "thinkpol0"); errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("connected: a TCP connect bound to the TUN was refused")
	}

	// The same again leaves the table as it is; deleted, the next Apply
	// puts it back.
	before := p.ksHandles(t)
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	if after := p.ksHandles(t); after != before {
		t.Errorf("applying the same rules rebuilt the chain: handles %s, then %s", before, after)
	}
	p.nft(t, "delete", "element", "inet", firewall.KillSwitchTable, "allow6", "{", domestic6, "}")
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	if !p.ping(t, domestic6) {
		t.Error("an element deleted from outside isn't put back by the next Apply")
	}
	p.nft(t, "delete", "table", "inet", firewall.KillSwitchTable)
	if !p.ping4(t, foreign4) {
		t.Fatal("still refused with the table deleted")
	}
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	if p.ping4(t, foreign4) {
		t.Error("the deleted table isn't put back by the next Apply")
	}

	// A fresh kill switch's Close removes what another left (a crashed
	// run's), and Close is final.
	fresh := p.killSwitch(t)
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.table(t), firewall.KillSwitchTable) {
		t.Errorf("the table is still there after Close:\n%s", p.table(t))
	}
	if !p.ping4(t, foreign4) {
		t.Error("still refused after Close")
	}
	if err := fresh.Apply(ctx, up); err == nil {
		t.Error("Apply after Close succeeded")
	}
}

// The kill switch and the guard are two tables: IPv6 must pass both, and
// removing one leaves the other.
func TestKillSwitchAndGuardAreSeparateOwners(t *testing.T) {
	p := ksPair(t)
	k, g := p.killSwitch(t), p.guard(t)
	ctx := context.Background()
	// The guard exempts domestic6; the kill switch only the entry.
	if err := g.Apply(ctx, routetable.Exempt{TUN: "thinkpol0", Mark: routetable.Mark, Direct: set(t, domestic6+"/128", entry6+"/128")}); err != nil {
		t.Fatal(err)
	}
	if err := k.Apply(ctx, firewall.KillSwitchRules{Mark: routetable.Mark, Allow: set(t, entry6+"/128")}); err != nil {
		t.Fatal(err)
	}
	if p.ping(t, domestic6) {
		t.Error("the guard's exemption let IPv6 past the kill switch")
	}
	if !p.ping(t, entry6) {
		t.Error("an address both exempt is refused")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if p.ping(t, foreign6) || !strings.Contains(p.table(t), firewall.KillSwitchTable) {
		t.Error("closing the guard took the kill switch with it")
	}
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
