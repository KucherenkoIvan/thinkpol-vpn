//go:build linux && !android

package supervisor_test

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The test's internet: a namespace behind the uplink tp-up0, holding the
// destinations on its loopback, and a LAN namespace behind tp-lan0 whose
// forwarded traffic is no space's.
var (
	upRoot4, upRoot6 = netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:1::1")
	upFar4, upFar6   = netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8:1::2")
	internet4        = netip.MustParseAddr("198.51.100.1")
	internet6        = netip.MustParseAddr("2001:db8:2::1")
	lanHost          = netip.MustParseAddr("10.77.0.2")
)

const uplink = "tp-up0"

// labInternet builds the internet and the LAN; everything goes when the
// test ends. It adds routes to the internet's prefixes only, never a
// default route.
func labInternet(t *testing.T) (inet, lan string) {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid())
	inet, lan = "tp-inet-"+suffix, "tp-lan-"+suffix
	sh := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s\n%s", err, out, script)
		}
	}
	t.Cleanup(func() {
		for _, c := range [][]string{{"ip", "netns", "del", inet}, {"ip", "netns", "del", lan}, {"ip", "link", "del", uplink}, {"ip", "link", "del", "tp-lan0"}} {
			_ = exec.Command(c[0], c[1:]...).Run()
		}
	})
	sh(fmt.Sprintf(`
		ip netns add %[1]s
		ip link add %[3]s type veth peer name eth0 netns %[1]s
		ip addr add %[4]s/24 dev %[3]s
		ip addr add %[5]s/64 dev %[3]s nodad
		ip link set %[3]s up
		ip -n %[1]s link set lo up
		ip -n %[1]s link set eth0 up
		ip -n %[1]s addr add %[6]s/24 dev eth0
		ip -n %[1]s addr add %[7]s/64 dev eth0 nodad
		ip -n %[1]s addr add %[8]s/32 dev lo
		ip -n %[1]s addr add %[9]s/128 dev lo
		ip -n %[1]s route add default via %[4]s
		ip -n %[1]s -6 route add default via %[5]s
		ip route add %[8]s/32 via %[6]s dev %[3]s
		ip -6 route add %[9]s/128 via %[7]s dev %[3]s
		ip netns add %[2]s
		ip link add tp-lan0 type veth peer name eth0 netns %[2]s
		ip addr add 10.77.0.1/24 dev tp-lan0
		ip link set tp-lan0 up
		ip -n %[2]s link set eth0 up
		ip -n %[2]s addr add %[10]s/24 dev eth0
		ip -n %[2]s route add default via 10.77.0.1
	`, inet, lan, uplink, upRoot4, upRoot6, upFar4, upFar6, internet4, internet6, lanHost))
	return inet, lan
}

// inNamespace runs fn on a thread in the named network namespace; sockets
// fn opens stay there.
func inNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		ns, err := netns.GetFromName(name)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = ns.Close() }()
		if err := netns.Set(ns); err != nil {
			done <- err
			return
		}
		fn()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// arrivals is what a UDP port in the internet received: "<source> <payload>".
type arrivals struct {
	mu  sync.Mutex
	got []string
}

func (a *arrivals) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got)
}

func (a *arrivals) from(src netip.Addr, payload string) bool {
	return slices.Contains(a.list(), src.String()+" "+payload)
}

func (a *arrivals) count(payload string) int {
	n := 0
	for _, l := range a.list() {
		if strings.HasSuffix(l, " "+payload) {
			n++
		}
	}
	return n
}

func listenIn(t *testing.T, ns string, port int) *arrivals {
	t.Helper()
	var pc net.PacketConn
	var err error
	inNamespace(t, ns, func() { pc, err = net.ListenPacket("udp", fmt.Sprintf(":%d", port)) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	a := &arrivals{}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			a.mu.Lock()
			a.got = append(a.got, fmt.Sprintf("%s %s", from.(*net.UDPAddr).AddrPort().Addr().Unmap(), buf[:n]))
			a.mu.Unlock()
		}
	}()
	return a
}

// rootSysctls sets keys to value for the test and puts them back after.
func rootSysctls(t *testing.T, value string, keys ...string) {
	t.Helper()
	for _, key := range keys {
		was, err := os.ReadFile("/proc/sys/" + key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/proc/sys/"+key, []byte(value), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile("/proc/sys/"+key, was, 0) })
	}
}

// TestEgress: a space with egress reaches the internet by the uplink, over
// IPv4 and IPv6, masqueraded to the uplink's addresses, its overlay sources
// SNATed to its transit address first; a space without egress on the same
// node reaches only the endpoints its section dials, and nothing through
// the other space's egress; turning egress off closes it; forwarded
// traffic that isn't a space's is never masqueraded; the root namespace's
// forwarding is turned on for egress and put back by Close.
func TestEgress(t *testing.T) {
	needsLab(t)
	inet, lan := labInternet(t)
	const forward4, forward6 = "net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"
	rootSysctls(t, "0", forward4, forward6)
	probes, dialed := listenIn(t, inet, probePort), listenIn(t, inet, probePort+1)

	s, err := supervisor.New(options([]string{envProbe + "=1"}))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = s.Close()
		}
	})
	exit, other := netmap.NewSpaceID(), netmap.NewSpaceID()
	egress := supervisor.Egress{Uplink: uplink, IPv4: true, IPv6: true}
	dial := netip.AddrPortFrom(internet4, probePort+1)
	targets := []byte(strings.Join([]string{
		internet4.String() + "#v4",
		netip.AddrPortFrom(internet6, probePort).String() + "#v6",
		internet4.String() + "@100.64.0.5#overlay",
		dial.String() + "#dial",
	}, "\n"))
	spaces := func(e supervisor.Egress) []supervisor.Space {
		return []supervisor.Space{
			{ID: exit, Config: targets, Egress: e},
			{ID: other, Config: targets, Dials: []netip.AddrPort{dial}},
		}
	}
	if err := s.SetSpaces(spaces(egress)); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, exit, other)
	if readSysctl(forward4) != "1" || readSysctl(forward6) != "1" {
		t.Fatalf("forwarding not turned on: %s %s", readSysctl(forward4), readSysctl(forward6))
	}

	tagged := func(space netmap.SpaceID, tag string) string { return "space=" + space.String() + "#" + tag }
	eventually(t, 15*time.Second, "the exit space's traffic, masqueraded", func() error {
		for _, want := range []struct {
			at      *arrivals
			src     netip.Addr
			payload string
		}{
			{probes, upRoot4, tagged(exit, "v4")},
			{probes, upRoot6, tagged(exit, "v6")},
			{probes, upRoot4, tagged(exit, "overlay")},
			{dialed, upRoot4, tagged(exit, "dial")},
			{dialed, upRoot4, tagged(other, "dial")},
		} {
			if !want.at.from(want.src, want.payload) {
				return fmt.Errorf("no %q from %s; got %q", want.payload, want.src, append(probes.list(), dialed.list()...))
			}
		}
		return nil
	})
	time.Sleep(time.Second)
	for _, l := range append(probes.list(), dialed.list()...) {
		src, payload, _ := strings.Cut(l, " ")
		if src != upRoot4.String() && src != upRoot6.String() {
			t.Errorf("arrived unmasqueraded: %q", l)
		}
		if strings.Contains(payload, other.String()) && !strings.HasSuffix(payload, "#dial") {
			t.Errorf("the space without egress got out: %q", l)
		}
	}
	for _, w := range ws {
		if w.Space == exit && len(w.SpaceAddrs) != 2 {
			t.Fatalf("worker %+v", w)
		}
	}

	// Egress off: nothing of the exit space's gets out (its section dials
	// nothing), and the other space's dial goes on.
	if err := s.SetSpaces(spaces(supervisor.Egress{})); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	before := map[string]int{}
	for _, tag := range []string{"v4", "v6", "overlay"} {
		before[tag] = probes.count(tagged(exit, tag))
	}
	exitDials, otherDials := dialed.count(tagged(exit, "dial")), dialed.count(tagged(other, "dial"))
	time.Sleep(2 * time.Second)
	for tag, n := range before {
		if got := probes.count(tagged(exit, tag)); got != n {
			t.Errorf("%s: %d more arrived with egress off", tag, got-n)
		}
	}
	if got := dialed.count(tagged(exit, "dial")); got != exitDials {
		t.Errorf("%d more of the exit space's datagrams to another server's port with egress off", got-exitDials)
	}
	if dialed.count(tagged(other, "dial")) == otherDials {
		t.Error("the other space's dial stopped")
	}

	// Forwarded traffic of no space keeps its source.
	inNamespace(t, lan, func() {
		c, err := net.Dial("udp", netip.AddrPortFrom(internet4, probePort).String())
		if err == nil {
			for range 5 {
				_, _ = c.Write([]byte("lan"))
			}
			_ = c.Close()
		}
	})
	eventually(t, 5*time.Second, "the LAN's datagram", func() error {
		if !probes.from(lanHost, "lan") {
			return fmt.Errorf("got %q", probes.list())
		}
		return nil
	})

	closed = true
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if readSysctl(forward4) != "0" || readSysctl(forward6) != "0" {
		t.Fatalf("forwarding not restored: %s %s", readSysctl(forward4), readSysctl(forward6))
	}
}
