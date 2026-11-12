//go:build linux && !android

package firewall_test

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	lan6     = "fd09::1"
	spoof4   = "198.51.100.9" // an allowed source no one has
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
	p.ip(t, p.gw, "addr", "add", lan6+"/128", "dev", "lo")
	return p
}

// sockaddr is addr:port as a socket address, with its family; a
// link-local address names its interface after a %.
func sockaddr(t *testing.T, addr string, port int) (unix.Sockaddr, int) {
	t.Helper()
	a, err := netip.ParseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if a.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: a.As4()}, unix.AF_INET
	}
	sa := &unix.SockaddrInet6{Port: port, Addr: a.As16()}
	if a.Zone() != "" {
		ifc, err := net.InterfaceByName(a.Zone())
		if err != nil {
			t.Fatal(err)
		}
		sa.ZoneId = uint32(ifc.Index)
	}
	return sa, unix.AF_INET6
}

// udpArrives says whether a UDP datagram sent from namespace from (from
// src, if set) reaches dst:port in namespace to.
func udpArrives(t *testing.T, from, src, to, dst string, port int) bool {
	t.Helper()
	var rfd int
	var err error
	inNS(t, to, func() {
		sa, family := sockaddr(t, dst, port)
		if rfd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		tv := unix.NsecToTimeval((2 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(rfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		err = unix.Bind(rfd, sa)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rfd) }()
	inNS(t, from, func() {
		sa, family := sockaddr(t, dst, port)
		var fd int
		if fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if src != "" {
			bind, _ := sockaddr(t, src, 0)
			if err = unix.Bind(fd, bind); err != nil {
				return
			}
		}
		// A refusal at output can show as an error on the send.
		_ = unix.Sendto(fd, []byte("probe"), 0, sa)
	})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := unix.Recvfrom(rfd, buf, 0)
	return err == nil && string(buf[:n]) == "probe"
}

// listenTCP listens on addr:port in namespace ns until the test ends.
func listenTCP(t *testing.T, ns, addr string, port int) {
	t.Helper()
	var fd int
	var err error
	inNS(t, ns, func() {
		sa, family := sockaddr(t, addr, port)
		if fd, err = unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		if err = unix.Bind(fd, sa); err == nil {
			err = unix.Listen(fd, 16)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
}

// dialTCP connects TCP from namespace ns to dst:port and returns the
// error (nil: connected) within 3 s.
func dialTCP(t *testing.T, ns, dst string, port int) error {
	t.Helper()
	var err error
	inNS(t, ns, func() {
		sa, family := sockaddr(t, dst, port)
		var fd int
		if fd, err = unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		tv := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
		err = unix.Connect(fd, sa)
	})
	return err
}

// sysctl sets keys in namespace ns.
func sysctl(t *testing.T, ns string, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if out, err := exec.Command("ip", "netns", "exec", ns, "sysctl", "-qw", key).CombinedOutput(); err != nil {
			t.Fatalf("sysctl %s: %v: %s", key, err, out)
		}
	}
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

// dhcp6 says whether a UDP datagram from the device's port 546 to dst's
// port 547, out of eth0, reaches the gateway (listening on gw0, joined to
// ff02::1:2, with the link-local address fe80::1).
func (p *pair) dhcp6(t *testing.T, dst string) bool {
	t.Helper()
	var rfd int
	var err error
	inNS(t, p.gw, func() {
		var ifc *net.Interface
		if ifc, err = net.InterfaceByName("gw0"); err != nil {
			return
		}
		if rfd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		tv := unix.NsecToTimeval((2 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(rfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		if err = unix.Bind(rfd, &unix.SockaddrInet6{Port: 547}); err != nil {
			return
		}
		mreq := &unix.IPv6Mreq{Multiaddr: netip.MustParseAddr("ff02::1:2").As16(), Interface: uint32(ifc.Index)}
		err = unix.SetsockoptIPv6Mreq(rfd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rfd) }()
	inNS(t, p.dev, func() {
		var ifc *net.Interface
		if ifc, err = net.InterfaceByName("eth0"); err != nil {
			return
		}
		var fd int
		if fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err = unix.Bind(fd, &unix.SockaddrInet6{Port: 546}); err != nil {
			return
		}
		to := &unix.SockaddrInet6{Port: 547, Addr: netip.MustParseAddr(dst).As16()}
		if a := netip.MustParseAddr(dst); a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			to.ZoneId = uint32(ifc.Index)
		}
		err = unix.Sendto(fd, []byte("solicit"), 0, to)
	})
	if err != nil {
		// A refusal by the kill switch shows as EPERM on the send.
		return false
	}
	buf := make([]byte, 64)
	n, _, err := unix.Recvfrom(rfd, buf, 0)
	return err == nil && string(buf[:n]) == "solicit"
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
	p.ip(t, p.gw, "addr", "add", "fe80::1/64", "dev", "gw0", "nodad")
	if !p.ping4(t, foreign4) || !p.ping(t, foreign6) || !p.dhcp6(t, "2001:db8:1::1") || !p.dhcp6(t, "fe80::1") || !p.dhcp6(t, "ff02::1:2") {
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
			{"DHCPv6 to ff02::1:2", func() bool { return p.dhcp6(t, "ff02::1:2") }, true},
			{"DHCPv6 to the gateway's link-local address", func() bool { return p.dhcp6(t, "fe80::1") }, true},
			{"DHCPv6 to the gateway's global address", func() bool { return p.dhcp6(t, "2001:db8:1::1") }, false},
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
	lan.NoDNS = set(t, prefixStrings(firewall.LAN)...)
	if err := k.Apply(ctx, lan); err != nil {
		t.Fatal(err)
	}
	check("down, allow-LAN", downProbes(true))
	// DNS to the LAN is refused while down, allow-LAN or not (the OS's
	// own resolvers forward in the clear); the rest of the LAN passes.
	for _, port := range []int{53, 853, 8080} {
		listenTCP(t, p.gw, lan4, port)
		listenTCP(t, p.gw, lan6, port)
	}
	for _, dst := range []string{lan4, lan6} {
		for _, port := range []int{53, 853} {
			if err := dialTCP(t, p.dev, dst, port); !errors.Is(err, syscall.ECONNREFUSED) {
				t.Errorf("down, allow-LAN: TCP to %s port %d: %v, want refused", dst, port, err)
			}
		}
		if err := dialTCP(t, p.dev, dst, 8080); err != nil {
			t.Errorf("down, allow-LAN: TCP to %s port 8080: %v, want connected", dst, err)
		}
		if udpArrives(t, p.dev, "", p.gw, dst, 53) {
			t.Errorf("down, allow-LAN: UDP to %s port 53 arrived", dst)
		}
		if !udpArrives(t, p.dev, "", p.gw, dst, 5353) {
			t.Errorf("down, allow-LAN: UDP to %s port 5353 didn't arrive", dst)
		}
	}

	// Connected: the TUN and the direct destinations too.
	up := firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128"), Direct: set(t, domestic6+"/128")}
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
	p.nft(t, "delete", "element", "inet", firewall.KillSwitchTable, "direct6", "{", domestic6, "}")
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

// The direct destinations expire DirectTimeout after the last Apply: a
// dead agent's kill switch lets out only the entries; an Apply in time
// renews them.
func TestKillSwitchDirectDestinationsExpireWithoutTheAgent(t *testing.T) {
	p := ksPair(t)
	k := p.killSwitch(t)
	ctx := context.Background()
	up := firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: set(t, entry6+"/128"), Direct: set(t, domestic6+"/128")}
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	// Renewed halfway: still there past the first deadline.
	time.Sleep(firewall.DirectTimeout / 2)
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	time.Sleep(firewall.DirectTimeout/2 + 5*time.Second)
	if !p.ping(t, domestic6) {
		t.Fatal("a renewed direct destination expired")
	}
	// No Apply since (the agent died): gone within DirectTimeout.
	deadline := time.Now().Add(firewall.DirectTimeout)
	for p.ping(t, domestic6) {
		if time.Now().After(deadline) {
			t.Fatal("the direct destination didn't expire")
		}
		time.Sleep(time.Second)
	}
	if !p.ping(t, entry6) || !strings.Contains(p.table(t), firewall.KillSwitchTable) {
		t.Error("the entry went with the direct destinations")
	}
}

// behind adds a client namespace the device forwards for (a container,
// a VM, a hotspot's client): its eth0 is a veth to the device's ctr0, its
// default routes go through the device, and the gateway routes its
// networks back. It returns the client's namespace.
func (p *pair) behind(t *testing.T) string {
	t.Helper()
	client := p.dev + "-c"
	if out, err := exec.Command("ip", "netns", "add", client).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _, _ = exec.Command("ip", "netns", "del", client).CombinedOutput() })
	p.ip(t, p.dev, "link", "add", "ctr0", "type", "veth", "peer", "name", "eth0", "netns", client)
	for _, args := range [][]string{
		{"link", "set", "ctr0", "up"},
		{"addr", "add", "10.77.0.1/24", "dev", "ctr0"},
		{"addr", "add", "2001:db8:77::1/64", "dev", "ctr0", "nodad"},
	} {
		p.ip(t, p.dev, args...)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "eth0", "up"},
		{"addr", "add", "10.77.0.2/24", "dev", "eth0"},
		{"addr", "add", "2001:db8:77::2/64", "dev", "eth0", "nodad"},
		{"route", "add", "default", "via", "10.77.0.1"},
		{"-6", "route", "add", "default", "via", "2001:db8:77::1"},
	} {
		p.ip(t, client, args...)
	}
	p.ip(t, p.gw, "route", "add", "10.77.0.0/24", "via", "192.0.2.2")
	p.ip(t, p.gw, "-6", "route", "add", "2001:db8:77::/64", "via", "2001:db8:1::2")
	for _, key := range []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"} {
		if out, err := exec.Command("ip", "netns", "exec", p.dev, "sysctl", "-qw", key).CombinedOutput(); err != nil {
			t.Fatalf("sysctl %s: %v: %s", key, err, out)
		}
	}
	return client
}

// tunnel replaces the device's dummy thinkpol0 with a veth to the
// gateway (tun0 there) that carries foreign4 and foreign6 both ways:
// the device routes them into it, and the gateway sends their replies
// back by it (policy routing by source).
func tunnel(t *testing.T, p *pair) {
	t.Helper()
	p.ip(t, p.dev, "link", "del", "thinkpol0")
	p.ip(t, p.dev, "link", "add", "thinkpol0", "type", "veth", "peer", "name", "tun0", "netns", p.gw)
	for _, args := range [][]string{
		{"link", "set", "thinkpol0", "up"},
		{"addr", "add", "10.88.0.1/30", "dev", "thinkpol0"},
		{"addr", "add", "2001:db8:88::1/64", "dev", "thinkpol0", "nodad"},
		{"route", "add", foreign4 + "/32", "via", "10.88.0.2"},
		{"-6", "route", "add", foreign6 + "/128", "via", "2001:db8:88::2"},
	} {
		p.ip(t, p.dev, args...)
	}
	for _, args := range [][]string{
		{"link", "set", "tun0", "up"},
		{"addr", "add", "10.88.0.2/30", "dev", "tun0"},
		{"addr", "add", "2001:db8:88::2/64", "dev", "tun0", "nodad"},
		{"route", "add", "default", "via", "10.88.0.1", "table", "88"},
		{"-6", "route", "add", "default", "via", "2001:db8:88::1", "table", "88"},
		{"rule", "add", "from", foreign4, "lookup", "88"},
		{"-6", "rule", "add", "from", foreign6, "lookup", "88"},
	} {
		p.ip(t, p.gw, args...)
	}
	// Neighbour discovery on the link waits for the link-local
	// addresses' DAD.
	deadline := time.Now().Add(10 * time.Second)
	for p.ip(t, p.dev, "-6", "addr", "show", "dev", "thinkpol0", "tentative") != "" ||
		p.ip(t, p.gw, "-6", "addr", "show", "dev", "tun0", "tentative") != "" {
		if time.Now().After(deadline) {
			t.Fatal("the TUN's link-local addresses are still tentative")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// pingFrom says whether one ping from namespace ns is answered.
func pingFrom(ns, dst string) bool {
	family := "-4"
	if netip.MustParseAddr(dst).Is6() {
		family = "-6"
	}
	return exec.Command("ip", "netns", "exec", ns, "ping", family, "-c", "1", "-W", "2", dst).Run() == nil
}

// clientDial4 connects TCP from namespace ns to dst:80 and returns the
// error (nil: connected) within 3 s.
func clientDial4(t *testing.T, ns, dst string) error {
	t.Helper()
	var err error
	inNS(t, ns, func() {
		var fd int
		if fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		tv := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: 80, Addr: netip.MustParseAddr(dst).As4()})
	})
	return err
}

// What the device forwards (a container, a VM, a hotspot's client) never
// meets the output chain: the kill switch's forward chain lets it reach
// only the entries (their replies coming back) while the tunnel is down,
// with allow-LAN the LAN but its DNS, and connected the direct
// destinations and whatever goes by the TUN (its replies coming in by
// it) too, both families. A new flow from an allowed source isn't a
// reply.
func TestKillSwitchConfinesForwardedTraffic(t *testing.T) {
	p := ksPair(t)
	client := p.behind(t)
	// IPv6 may need a few seconds after the namespaces came up (the
	// link-local addresses' DAD).
	for _, dst := range []string{foreign4, foreign6, entry4, entry6} {
		deadline := time.Now().Add(10 * time.Second)
		for !pingFrom(client, dst) {
			if time.Now().After(deadline) {
				t.Fatalf("the client doesn't reach %s without a kill switch: the test proves nothing", dst)
			}
		}
	}
	k := p.killSwitch(t)
	ctx := context.Background()
	check := func(when string, want map[string]bool) {
		t.Helper()
		for dst, w := range want {
			if got := pingFrom(client, dst); got != w {
				t.Errorf("%s: the client's ping to %s answered %v, want %v", when, dst, got, w)
			}
		}
	}
	down := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128")}
	if err := k.Apply(ctx, down); err != nil {
		t.Fatal(err)
	}
	check("down", map[string]bool{foreign4: false, foreign6: false, domestic6: false, entry4: true, entry6: true})
	// The refusal goes back to the client by output, where the client's
	// address is allowed only with allow-LAN: then it is refused at once.
	if err := clientDial4(t, client, foreign4); err == nil {
		t.Error("down: the client's TCP connect succeeded")
	}
	lan := down
	lan.Allow = set(t, append([]string{entry4 + "/32", entry6 + "/128"}, prefixStrings(firewall.LAN)...)...)
	if err := k.Apply(ctx, lan); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := clientDial4(t, client, foreign4); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 2*time.Second {
		t.Errorf("down, allow-LAN: the client's TCP connect: %v after %v, want refused at once", err, time.Since(start))
	}
	check("down, allow-LAN", map[string]bool{foreign4: false, foreign6: false, entry4: true})

	// Forwarded DNS to the LAN is refused while down, as the device's own.
	lan.NoDNS = set(t, prefixStrings(firewall.LAN)...)
	if err := k.Apply(ctx, lan); err != nil {
		t.Fatal(err)
	}
	if udpArrives(t, client, "", p.gw, lan4, 53) {
		t.Error("down, allow-LAN: the client's UDP to lan4 port 53 arrived")
	}
	if !udpArrives(t, client, "", p.gw, lan4, 5353) {
		t.Error("down, allow-LAN: the client's UDP to lan4 port 5353 didn't arrive")
	}

	// Connected: the TUN is a veth to the gateway, which sends foreign's
	// replies back by it, so the client's tunnelled flows go out by the
	// TUN and their replies come in by it.
	tunnel(t, p)
	up := firewall.KillSwitchRules{TUN: "thinkpol0", Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128"), Direct: set(t, domestic6+"/128")}
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	check("connected", map[string]bool{foreign4: true, foreign6: true, domestic6: true, entry6: true, lan4: false})
	// A new flow in the reply direction from an allowed source (spoofed)
	// isn't a reply: refused.
	spoofed := up
	spoofed.Allow = set(t, entry4+"/32", entry6+"/128", spoof4+"/32")
	if err := k.Apply(ctx, spoofed); err != nil {
		t.Fatal(err)
	}
	p.ip(t, client, "addr", "add", spoof4+"/32", "dev", "lo")
	sysctl(t, p.dev, "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.ctr0.rp_filter=0")
	sysctl(t, p.gw, "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.gw0.rp_filter=0")
	if udpArrives(t, client, spoof4, p.gw, lan4, 9999) {
		t.Error("connected: a new flow from an allowed source to lan4 passed")
	}
	if !udpArrives(t, client, "", p.gw, foreign4, 9999) {
		t.Error("connected: the client's UDP to foreign4 by the TUN didn't arrive")
	}
	// Re-applied whole: the forward chain is part of what is compared.
	p.nft(t, "flush", "chain", "inet", firewall.KillSwitchTable, "forward")
	if !pingFrom(client, lan4) {
		t.Fatal("still refused with the forward chain flushed")
	}
	if !udpArrives(t, client, spoof4, p.gw, lan4, 9999) {
		t.Fatal("a datagram from the spoofed source doesn't arrive with the forward chain flushed: the spoofing check proves nothing")
	}
	if err := k.Apply(ctx, spoofed); err != nil {
		t.Fatal(err)
	}
	check("connected, re-applied", map[string]bool{lan4: false, foreign4: true, domestic6: true})
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

// bridged adds a bridge to the device with a client namespace on each of
// two ports, 10.<n>.0.2 and .3 (2001:db8:<n>::2 and ::3), routed by the
// device's 10.<n>.0.1, and returns the clients' namespaces.
func bridged(t *testing.T, p *pair, bridge string, n int) (string, string) {
	t.Helper()
	p.ip(t, p.dev, "link", "add", bridge, "type", "bridge")
	p.ip(t, p.dev, "link", "set", bridge, "up")
	p.ip(t, p.dev, "addr", "add", fmt.Sprintf("10.%d.0.1/24", n), "dev", bridge)
	var clients [2]string
	for i := range clients {
		ns := fmt.Sprintf("%s-%s-%d", p.dev, bridge, i)
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("ip netns add: %v: %s", err, out)
		}
		t.Cleanup(func() { _, _ = exec.Command("ip", "netns", "del", ns).CombinedOutput() })
		port := fmt.Sprintf("%sp%d", bridge, i)
		p.ip(t, p.dev, "link", "add", port, "type", "veth", "peer", "name", "eth0", "netns", ns)
		p.ip(t, p.dev, "link", "set", port, "master", bridge, "up")
		for _, args := range [][]string{
			{"link", "set", "lo", "up"},
			{"link", "set", "eth0", "up"},
			{"addr", "add", fmt.Sprintf("10.%d.0.%d/24", n, i+2), "dev", "eth0"},
			{"addr", "add", fmt.Sprintf("2001:db8:%d::%d/64", n, i+2), "dev", "eth0", "nodad"},
			{"route", "add", "default", "via", fmt.Sprintf("10.%d.0.1", n)},
		} {
			p.ip(t, ns, args...)
		}
		clients[i] = ns
	}
	return clients[0], clients[1]
}

// With br_netfilter (bridge-nf-call-iptables, as Docker up to 27 and
// Kubernetes set it) frames bridged between two ports of one bridge meet
// the forward hook: the kill switch lets them pass, container to
// container, and nothing routed. A bridge made after an Apply passes
// from the next one.
func TestKillSwitchPassesFramesBridgedWithinABridge(t *testing.T) {
	p := ksPair(t)
	if exec.Command("ip", "netns", "exec", p.dev, "test", "-d", "/proc/sys/net/bridge").Run() != nil {
		t.Skip("no br_netfilter in this kernel: bridged frames never meet the forward hook")
	}
	sysctl(t, p.dev, "net.bridge.bridge-nf-call-iptables=1", "net.bridge.bridge-nf-call-ip6tables=1", "net.ipv4.ip_forward=1")
	p.ip(t, p.gw, "route", "add", "10.78.0.0/24", "via", "192.0.2.2")
	c1, c2 := bridged(t, p, "br0", 78)
	for _, dst := range []string{"10.78.0.3", "2001:db8:78::3", foreign4} {
		if !pingFrom(c1, dst) {
			t.Fatalf("%s doesn't reach %s without a kill switch: the test proves nothing", c1, dst)
		}
	}
	k := p.killSwitch(t)
	ctx := context.Background()
	down := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128")}
	if err := k.Apply(ctx, down); err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{"10.78.0.3": true, "2001:db8:78::3": true, foreign4: false, entry4: true} {
		if got := pingFrom(c1, dst); got != want {
			t.Errorf("down: %s's ping to %s answered %v, want %v", c1, dst, got, want)
		}
	}
	listenTCP(t, c2, "10.78.0.3", 8080)
	if err := dialTCP(t, c1, "10.78.0.3", 8080); err != nil {
		t.Errorf("down: a TCP connect across the bridge: %v", err)
	}

	c3, _ := bridged(t, p, "br1", 79)
	if pingFrom(c3, "10.79.0.3") {
		t.Fatal("a bridge made after the Apply passes before the next: br_netfilter doesn't put bridged frames through the forward hook, so the test proves nothing")
	}
	if err := k.Apply(ctx, down); err != nil {
		t.Fatal(err)
	}
	if !pingFrom(c3, "10.79.0.3") {
		t.Error("a bridge made after the Apply is still refused after the next")
	}
	if !pingFrom(c1, "10.78.0.3") {
		t.Error("the first bridge is refused after the re-apply")
	}
}
