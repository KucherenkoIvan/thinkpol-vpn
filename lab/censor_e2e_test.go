//go:build lab

package lab_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// tcpProbePort is where server-1 listens for plain TCP through the censor.
const tcpProbePort = 18080

// TestCensorForwardsWhatNoModuleDecides runs censord with no module at all:
// everything crosses the router, through the queue. Plain TCP connects over
// IPv4 and IPv6 (TCP segments carry DF, which a fragment rule must not take
// for a fragment), a UDP datagram the sender's kernel fragments arrives
// whole over both families, and the verdict log shows the censor accepted
// each of those flows, the datagram's in one piece.
func TestCensorForwardsWhatNoModuleDecides(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	dev, server, router := l.Node(lab.DeviceA), l.Node(lab.Server1), l.Node(lab.Router)
	listenTCP(t, server)
	c := startCensor(t, l, []censor.ModuleConfig{})

	// The datagram must reach the router in fragments, or this checks
	// nothing about them.
	routerCap := router.Capture(t, captureFrom(dev))
	for _, dst := range serverAddrs(server) {
		if err := tcpCrosses(dev, dst, 20*time.Second); err != nil {
			t.Errorf("plain TCP with no module: %v", err)
		}
		if got := sendDatagram(t, dev, server, dst, 19100, fragmentedSize); got != fragmentedSize {
			t.Errorf("a %d-byte UDP datagram to %s arrived as %d bytes", fragmentedSize, dst, got)
		}
	}
	waitFragments(t, routerCap, dev)

	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		dst := serverAddrFor(server, src)
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Src == src && e.Key.Dst == dst &&
				e.Key.DstPort == tcpProbePort && e.Verdict == censor.Accept
		}) {
			t.Errorf("no accepted TCP flow %s -> %s in the verdict log: it did not cross the queue", src, dst)
		}
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoUDP && e.Key.Src == src && e.Key.Dst == dst &&
				e.Key.DstPort == 19100 && e.Verdict == censor.Accept && e.Bytes == fragmentedSize
		}) {
			t.Errorf("the verdict log has no whole %d-byte datagram %s -> %s: modules did not see it reassembled", fragmentedSize, src, dst)
		}
	}
}

// TestCensorFragmentedUDPBlocked blocks server-1 and sends it UDP datagrams
// the sender's kernel fragments: not one fragment, first or later, may
// reach server-1, over IPv4 or IPv6.
func TestCensorFragmentedUDPBlocked(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	dev, server, router := l.Node(lab.DeviceA), l.Node(lab.Server1), l.Node(lab.Router)
	c := startCensor(t, l, entryBlockSettings(t, l, "drop"))

	routerCap := router.Capture(t, captureFrom(dev))
	serverCap := server.Capture(t, captureFrom(dev))
	for _, dst := range serverAddrs(server) {
		if got := sendDatagram(t, dev, server, dst, 19200, fragmentedSize); got != 0 {
			t.Errorf("%d bytes of a blocked datagram reached %s", got, dst)
		}
	}
	waitFragments(t, routerCap, dev)
	if err := serverCap.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, p := range serverCap.Packets() {
		t.Errorf("server-1 got a packet from device-a through the censor: %s -> %s proto %d, %d bytes, fragment %v",
			p.Src, p.Dst, p.Proto, len(p.IP), ipFragment(p.IP))
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		dst := serverAddrFor(server, src)
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoUDP && e.Key.Src == src && e.Key.Dst == dst &&
				e.Verdict == censor.Drop && e.Module == "block-ip" && e.Bytes == fragmentedSize
		}) {
			t.Errorf("no block-ip drop of the whole datagram %s -> %s in the verdict log", src, dst)
		}
	}
}

// TestTCPResetReachesClient checks block-ip reset: device-a's connect is
// refused at once (an RST, not a timeout), the RST is on device-a's wire,
// coming from server-1's address, and server-1 sees nothing: neither the
// SYN nor an RST.
func TestTCPResetReachesClient(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	listenTCP(t, server)
	c := startCensor(t, l, entryBlockSettings(t, l, "reset"))

	filter := fmt.Sprintf("tcp port %d", tcpProbePort)
	devCap := dev.Capture(t, filter)
	serverCap := server.Capture(t, filter)
	for _, dst := range serverAddrs(server) {
		res, took, err := tcpConnect(dev, dst, 5)
		if err == nil {
			t.Errorf("tcp to %s connected through a reset censor", dst)
			continue
		}
		if !strings.Contains(res.Stderr, "refused") || took > 2*time.Second {
			t.Errorf("tcp to %s: want an immediate \"Connection refused\", got %q after %s", dst, strings.TrimSpace(res.Stderr), took.Round(time.Millisecond))
		}
		devCap.WaitFor(t, 5*time.Second, func(p lab.Packet) bool {
			flags, ok := tcpFlags(p)
			return ok && !p.Outgoing && p.Src == dst && p.SrcPort == tcpProbePort && flags&censor.Rst != 0
		})
	}
	if err := serverCap.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, p := range serverCap.Packets() {
		flags, _ := tcpFlags(p)
		t.Errorf("server-1 saw %s:%d -> %s:%d flags %#x: the censor must stop the SYN and answer it itself",
			p.Src, p.SrcPort, p.Dst, p.DstPort, flags)
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
	for _, dst := range serverAddrs(server) {
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Dst == dst && e.Verdict == censor.Reset && e.Module == "block-ip"
		}) {
			t.Errorf("no block-ip reset to %s in the verdict log", dst)
		}
	}
}

// TestTCPThroughCensorDrop checks block-ip drop on plain TCP: the connect
// times out over both families, server-1 never sees the SYN, and the
// verdict log has the drops.
func TestTCPThroughCensorDrop(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	listenTCP(t, server)
	c := startCensor(t, l, entryBlockSettings(t, l, "drop"))

	serverCap := server.Capture(t, fmt.Sprintf("tcp port %d", tcpProbePort))
	for _, dst := range serverAddrs(server) {
		if _, _, err := tcpConnect(dev, dst, 3); err == nil {
			t.Errorf("tcp to %s connected through a dropping censor", dst)
		}
	}
	if err := serverCap.Complete(); err != nil {
		t.Fatal(err)
	}
	if n := len(serverCap.Packets()); n > 0 {
		t.Errorf("server-1 saw %d packets of the dropped connections", n)
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
	for _, dst := range serverAddrs(server) {
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Dst == dst && e.Verdict == censor.Drop && e.Module == "block-ip"
		}) {
			t.Errorf("no block-ip drop to %s in the verdict log", dst)
		}
	}
}

// fragmentedSize is a UDP payload far above the lab's 1500-byte MTU: the
// sender's kernel sends it as three fragments.
const fragmentedSize = 3000

func entryBlockSettings(t *testing.T, l *lab.Lab, verdict string) []censor.ModuleConfig {
	t.Helper()
	b, err := json.Marshal(struct {
		Destinations []string `json:"destinations"`
		Verdict      string   `json:"verdict"`
	}{Destinations: []string{
		l.Node(lab.Server1).IPv4(lab.NetServers).String(),
		l.Node(lab.Server1).IPv6(lab.NetServers).String(),
	}, Verdict: verdict})
	if err != nil {
		t.Fatal(err)
	}
	return []censor.ModuleConfig{{Name: "block-ip", Settings: b}}
}

func serverAddrs(server *lab.Node) []netip.Addr {
	return []netip.Addr{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}
}

// serverAddrFor is server-1's address in src's family.
func serverAddrFor(server *lab.Node, src netip.Addr) netip.Addr {
	if src.Is4() {
		return server.IPv4(lab.NetServers)
	}
	return server.IPv6(lab.NetServers)
}

func captureFrom(dev *lab.Node) string {
	return fmt.Sprintf("src host %s or src host %s", dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices))
}

// listenTCP keeps a plain TCP listener on server-1 for each family; -k keeps
// it listening after a connection.
func listenTCP(t *testing.T, server *lab.Node) {
	t.Helper()
	for _, a := range serverAddrs(server) {
		family := "-4"
		if a.Is6() {
			family = "-6"
		}
		server.Start(t, "nc", family, "-k", "-l", "-s", a.String(), "-p", fmt.Sprint(tcpProbePort))
	}
	lab.Eventually(t, 30*time.Second, func() error {
		out := server.MustExec(t, "ss", "-H", "-lnt", fmt.Sprintf("sport = :%d", tcpProbePort))
		if n := len(strings.Split(strings.TrimSpace(out), "\n")); strings.TrimSpace(out) == "" || n < 2 {
			return fmt.Errorf("listeners: %q", out)
		}
		return nil
	})
}

// tcpConnect opens and closes one TCP connection from dev, waiting at most
// wait seconds, and says how long it took.
func tcpConnect(dev *lab.Node, dst netip.Addr, wait int) (lab.Result, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(wait+10)*time.Second)
	defer cancel()
	start := time.Now()
	res, err := dev.Exec(ctx, "nc", "-v", "-z", "-w", fmt.Sprint(wait), dst.String(), fmt.Sprint(tcpProbePort))
	return res, time.Since(start), err
}

// tcpCrosses retries a TCP connect until one succeeds or within runs out.
func tcpCrosses(dev *lab.Node, dst netip.Addr, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		_, _, err := tcpConnect(dev, dst, 2)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tcp to %s: %w", dst, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// sendDatagram sends one size-byte UDP datagram from dev to dst:port and
// returns how many bytes a listener on server-1 received within a few
// seconds.
func sendDatagram(t *testing.T, dev, server *lab.Node, dst netip.Addr, port, size int) int {
	t.Helper()
	family := "-4"
	if dst.Is6() {
		family = "-6"
	}
	out := fmt.Sprintf("/tmp/udp-%s-%d", strings.ReplaceAll(dst.String(), ":", "_"), port)
	server.Start(t, "sh", "-c", fmt.Sprintf("exec nc -u %s -l -s %s -p %d > %s", family, dst, port, out))
	lab.Eventually(t, 30*time.Second, func() error {
		if strings.TrimSpace(server.MustExec(t, "ss", "-H", "-lnu", fmt.Sprintf("sport = :%d", port))) == "" {
			return fmt.Errorf("no UDP listener on %d yet", port)
		}
		return nil
	})
	// One write of size bytes, one datagram: nc sends what each read of
	// the pipe returns, and a pipe write this small is atomic.
	dev.MustExec(t, "sh", "-c", fmt.Sprintf("head -c %d /dev/zero | nc -u %s -w 1 %s %d", size, family, dst, port))
	got := 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n := strings.TrimSpace(server.MustExec(t, "sh", "-c", "wc -c < "+out))
		_, _ = fmt.Sscan(n, &got)
		if got >= size {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return got
}

// waitFragments requires device-a's datagrams to have reached the router
// as fragments, later ones included, over both families.
func waitFragments(t *testing.T, routerCap *lab.Capture, dev *lab.Node) {
	t.Helper()
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		routerCap.WaitFor(t, 5*time.Second, func(p lab.Packet) bool {
			return !p.Outgoing && p.Src == src && ipFragment(p.IP) == "later"
		})
	}
}

// ipFragment says whether an IP packet is a fragment: "" for none, "first"
// or "later".
func ipFragment(ip []byte) string {
	if len(ip) >= 20 && ip[0]>>4 == 4 {
		switch f := binary.BigEndian.Uint16(ip[6:]); {
		case f&0x1fff != 0:
			return "later"
		case f&0x2000 != 0:
			return "first"
		}
		return ""
	}
	if len(ip) >= 48 && ip[0]>>4 == 6 && ip[6] == 44 {
		if binary.BigEndian.Uint16(ip[42:])&0xfff8 != 0 {
			return "later"
		}
		return "first"
	}
	return ""
}

// tcpFlags reads a captured TCP segment's flags.
func tcpFlags(p lab.Packet) (uint8, bool) {
	if p.Proto != lab.ProtoTCP {
		return 0, false
	}
	off := 40
	if p.Src.Is4() {
		off = int(p.IP[0]&0x0f) * 4
	}
	if len(p.IP) < off+14 {
		return 0, false
	}
	return p.IP[off+13], true
}
