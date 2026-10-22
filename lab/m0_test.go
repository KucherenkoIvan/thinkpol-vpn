//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestM0 is M0's "done when" (docs/design/milestones.md, Milestones; lab/M0.md): with
// `thinkpol up` on server-1, device-a and device-b and a map made by
// `thinkpol dev`, devices ping server-1 directly and each other through
// server-1 as relay, over overlay IPv4 and IPv6; server-1 runs the space in
// a worker of its own; the relayed traffic goes through server-1 and never
// straight from device to device; and nothing on the wire at the router
// looks like WireGuard (C1). It runs once with server-1 reachable over
// IPv4 (m0.yaml as is: its IPv4 endpoint comes first) and once over IPv6
// only (m0.yaml without the IPv4 endpoint).
func TestM0(t *testing.T) {
	t.Parallel()
	for _, underlay := range []string{"ipv4", "ipv6"} {
		t.Run("underlay="+underlay, func(t *testing.T) {
			t.Parallel()
			testM0(t, underlay == "ipv6")
		})
	}
}

// burstSize is the payload of the pings whose datagrams are counted: far
// above anything the data plane sends on its own (keepalives, probes).
const burstSize, burstCount = 1200, 20

func testM0(t *testing.T, ipv6 bool) {
	l := lab.StartOwnSlot(t, lab.Standard())
	server, devA, devB, router := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB), l.Node(lab.Router)
	space := newM0Space(t, l.Node(lab.Internet), server)
	underlay := func(n *lab.Node, network string) netip.Addr {
		if ipv6 {
			return n.IPv6(network)
		}
		return n.IPv4(network)
	}
	serverU, devAU, devBU := underlay(server, lab.NetServers), underlay(devA, lab.NetDevices), underlay(devB, lab.NetDevices)
	if ipv6 {
		space.builder.MustExec(t, "sh", "-ec", `grep -vF 'udp://${SERVER_1_IPV4}:' /src/lab/maps/m0.yaml > /tmp/m0/m0-ipv6.yaml`)
		space.spec = "/tmp/m0/m0-ipv6.yaml"
	}
	envelope, version := space.build(t)
	checkM0Map(t, space, server, ipv6)

	nodes := map[string]*lab.Node{"server-1": server, "device-a": devA, "device-b": devB}
	for name, n := range nodes {
		space.install(t, n, name, envelope)
	}
	// Everything from before the first handshake on.
	routerCap := router.Capture(t, "")
	devACap, devBCap := devA.Capture(t, ""), devB.Capture(t, "")

	up := map[string]*lab.Process{}
	for name, n := range nodes {
		up[name] = n.Start(t, "thinkpol", "up")
	}
	waitLog(t, up["server-1"], `worker space=\S+ .*`+applied(version))
	waitLog(t, up["device-a"], applied(version))
	waitLog(t, up["device-b"], applied(version))

	s4, s6 := space.overlay(1)
	a4, a6 := space.overlay(2)
	b4, b6 := space.overlay(3)

	var worker string
	t.Run("server-1 runs the space in its own worker", func(t *testing.T) {
		worker = checkWorker(t, server, s4, s6)
	})

	t.Run("direct: devices and server-1", func(t *testing.T) {
		for _, to := range []netip.Addr{s4, s6} {
			ping(t, devA, to)
			ping(t, devB, to)
		}
		if worker != "" {
			for _, to := range []netip.Addr{a4, a6, b4, b6} {
				pingFromNetns(t, server, worker, to)
			}
		}
		// One hop: device-a's datagrams end at server-1, which sends
		// nothing on to device-b.
		for _, to := range []netip.Addr{s4, s6} {
			c := burst(t, server, devA, to, serverU, map[string]netip.Addr{"device-a": devAU, "device-b": devBU})
			if c.in["device-a"] < c.received || c.out["device-a"] < c.received {
				t.Errorf("ping %s: server-1 got %d and sent %d datagrams of the burst with device-a, want at least %d each way (the replies device-a got)", to, c.in["device-a"], c.out["device-a"], c.received)
			}
			if c.in["device-b"] != 0 || c.out["device-b"] != 0 {
				t.Errorf("ping %s: server-1 exchanged %d/%d datagrams of the burst with device-b", to, c.in["device-b"], c.out["device-b"])
			}
			t.Logf("ping %s from device-a, at server-1: %s", to, c)
		}
	})

	t.Run("relayed: device to device through server-1", func(t *testing.T) {
		for _, to := range []netip.Addr{b4, b6} {
			ping(t, devA, to)
		}
		for _, to := range []netip.Addr{a4, a6} {
			ping(t, devB, to)
		}
		// Every packet of the burst arrives at server-1 from device-a and
		// leaves toward device-b, and every reply the other way.
		for _, to := range []netip.Addr{b4, b6} {
			c := burst(t, server, devA, to, serverU, map[string]netip.Addr{"device-a": devAU, "device-b": devBU})
			for _, n := range []string{"device-a", "device-b"} {
				if c.in[n] < c.received || c.out[n] < c.received {
					t.Errorf("ping %s: server-1 got %d and sent %d datagrams of the burst with %s, want at least %d each way (the replies device-a got)", to, c.in[n], c.out[n], n, c.received)
				}
			}
			t.Logf("ping %s from device-a, at server-1: %s", to, c)
		}
	})

	// The devices share a network: had anything gone straight from one to
	// the other, it would show in their own captures, not at the router.
	t.Run("no traffic between the devices but through server-1", func(t *testing.T) {
		checkNoDirect(t, complete(t, devACap), devA, devB, serverU)
		checkNoDirect(t, complete(t, devBCap), devB, devA, serverU)
	})

	t.Run("no WireGuard on the wire at the router (C1)", func(t *testing.T) {
		checkNoWireGuard(t, complete(t, routerCap), serverU)
	})
}

// checkM0Map checks, in device-a's opened section, what the test relies
// on: its only link is to server-1, at the underlay under test first, and
// device-b's only first hop is server-1.
func checkM0Map(t *testing.T, space *m0Space, server *lab.Node, ipv6 bool) {
	t.Helper()
	out := space.builder.MustExec(t, "sh", "-ec", "cd /tmp/m0 && thinkpol dev map inspect -keys keys -node-key keys/device-a.key map.bin")
	_, section, ok := strings.Cut(out, "\nsection for keys/device-a.key\n")
	if !ok {
		t.Fatalf("no section for device-a:\n%s", out)
	}
	links := regexp.MustCompile(`(?m)^links:\n((?:  .*\n)*)`).FindStringSubmatch(section)
	if links == nil {
		t.Fatalf("no links in device-a's section:\n%s", out)
	}
	if n := strings.Count(links[1], "- peer:"); n != 1 || !strings.Contains(links[1], "(server-1)") {
		t.Fatalf("device-a links to %d nodes, want server-1 only:\n%s", n, links[1])
	}
	v4 := fmt.Sprintf("udp://%s:4500", server.IPv4(lab.NetServers))
	v6 := fmt.Sprintf("udp://[%s]:4500", server.IPv6(lab.NetServers))
	first := regexp.MustCompile(`endpoints:\n\s+- (\S+),`).FindStringSubmatch(links[1])
	switch {
	case first == nil:
		t.Fatalf("no endpoints in device-a's link:\n%s", links[1])
	case !ipv6 && first[1] != v4:
		t.Fatalf("device-a dials %s first, want %s", first[1], v4)
	case ipv6 && (first[1] != v6 || strings.Contains(links[1], v4)):
		t.Fatalf("device-a's link isn't IPv6 only:\n%s", links[1])
	}
	if !regexp.MustCompile(`\(device-b\)\n\s+wireguard key: \S+\n\s+addresses: .*\n\s+first hops:\n\s+- \S+ \(server-1\)\n\s*(links|  - id)`).MatchString(section) {
		t.Fatalf("device-a doesn't reach device-b through server-1 only:\n%s", section)
	}
}

// checkWorker finds server-1's worker and checks it is isolated from the
// supervisor and holds the server's overlay addresses, which the root
// namespace doesn't. It returns the worker's pid.
func checkWorker(t *testing.T, server *lab.Node, overlay ...netip.Addr) string {
	t.Helper()
	pids := strings.Fields(server.MustExec(t, "pgrep", "-f", "^thinkpol worker"))
	if len(pids) != 1 {
		t.Fatalf("%d worker processes, want 1: %v", len(pids), pids)
	}
	worker := pids[0]
	supervisor := strings.TrimSpace(server.MustExec(t, "pgrep", "-f", "^thinkpol up"))
	if parent := strings.Fields(server.MustExec(t, "ps", "-o", "ppid=", "-p", worker)); len(parent) != 1 || parent[0] != supervisor {
		t.Errorf("the worker's parent is %v, want the supervisor %s", parent, supervisor)
	}
	for _, ns := range []string{"net", "user", "pid", "mnt"} {
		w := server.MustExec(t, "readlink", "/proc/"+worker+"/ns/"+ns)
		s := server.MustExec(t, "readlink", "/proc/"+supervisor+"/ns/"+ns)
		if w == s {
			t.Errorf("the worker shares the supervisor's %s namespace: %s", ns, strings.TrimSpace(w))
		}
	}
	status := server.MustExec(t, "cat", "/proc/"+worker+"/status")
	uid := regexp.MustCompile(`(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$`).FindStringSubmatch(status)
	if uid == nil {
		t.Fatalf("no Uid line in the worker's status:\n%s", status)
	}
	if slices.Contains(uid[1:], "0") {
		t.Errorf("the worker has root among its real, effective, saved and filesystem uids (in the node's namespace): %s", uid[0])
	}
	inWorker := server.MustExec(t, "nsenter", "--net=/proc/"+worker+"/ns/net", "ip", "-o", "addr", "show")
	inRoot := server.MustExec(t, "ip", "-o", "addr", "show")
	for _, a := range overlay {
		if !hasAddr(inWorker, a) {
			t.Errorf("%s isn't in the worker's namespace:\n%s", a, inWorker)
		}
		if hasAddr(inRoot, a) {
			t.Errorf("%s is in server-1's root namespace:\n%s", a, inRoot)
		}
	}
	t.Logf("worker %s (uid %s) under supervisor %s, own net/user/pid/mnt namespaces; overlay addresses only in its namespace:\n%s",
		worker, uid[1], supervisor, inWorker)
	return worker
}

func hasAddr(ipAddrOutput string, a netip.Addr) bool {
	return regexp.MustCompile(`\sinet6? ` + regexp.QuoteMeta(a.String()) + `/`).MatchString(ipAddrOutput)
}

func pingFromNetns(t *testing.T, n *lab.Node, pid string, to netip.Addr) {
	t.Helper()
	pingWith(t, n, to, "nsenter", "--net=/proc/"+pid+"/ns/net")
}

// pingWith is ping (up_test.go) behind a command prefix.
func pingWith(t *testing.T, n *lab.Node, to netip.Addr, prefix ...string) {
	t.Helper()
	args := append(slices.Clone(prefix), "ping", "-c", "1", "-W", "1", to.String())
	lab.Eventually(t, 60*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := n.Exec(ctx, args...)
		return err
	})
}

// datagramCounts are the large udp datagrams server-1 exchanged on its
// listener port with each node during a burst, and how many replies the
// burst got.
type datagramCounts struct {
	in, out  map[string]int
	received int
}

func (c datagramCounts) String() string {
	var names []string
	for _, m := range []map[string]int{c.in, c.out} {
		for n := range m {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	var parts []string
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s: %d in, %d out", n, c.in[n], c.out[n]))
	}
	return fmt.Sprintf("%d replies; %s", c.received, strings.Join(parts, "; "))
}

// burst pings to from a node burstCount times with burstSize payloads and
// counts the large datagrams captured at server-1. A burst that loses a
// reply is tried once more.
func burst(t *testing.T, server, from *lab.Node, to, serverU netip.Addr, nodes map[string]netip.Addr) datagramCounts {
	t.Helper()
	c := burstOnce(t, server, from, to, serverU, nodes)
	if c.received < burstCount {
		t.Logf("ping %s: %d of %d replies, once more", to, c.received, burstCount)
		c = burstOnce(t, server, from, to, serverU, nodes)
	}
	if c.received < burstCount {
		t.Errorf("ping %s: %d of %d replies", to, c.received, burstCount)
	}
	return c
}

func burstOnce(t *testing.T, server, from *lab.Node, to, serverU netip.Addr, nodes map[string]netip.Addr) datagramCounts {
	t.Helper()
	capture := server.Capture(t, "udp port 4500")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, _ := from.Exec(ctx, "ping", "-c", strconv.Itoa(burstCount), "-i", "0.2", "-W", "2", "-s", strconv.Itoa(burstSize), to.String())
	counts := datagramCounts{in: map[string]int{}, out: map[string]int{}}
	m := regexp.MustCompile(`(\d+) received`).FindStringSubmatch(res.Stdout)
	if m == nil {
		t.Fatalf("ping %s:\n%s%s", to, res.Stdout, res.Stderr)
	}
	counts.received, _ = strconv.Atoi(m[1])
	for _, p := range complete(t, capture) {
		if p.Network != lab.NetServers || len(p.Payload) < burstSize {
			continue
		}
		for name, addr := range nodes {
			switch {
			case !p.Outgoing && p.Src == addr && p.Dst == serverU && p.DstPort == 4500:
				counts.in[name]++
			case p.Outgoing && p.Dst == addr && p.Src == serverU && p.SrcPort == 4500:
				counts.out[name]++
			}
		}
	}
	return counts
}

// checkNoDirect checks a device's capture of the whole run: no unicast
// packet went between it and the other device, and every udp datagram it sent on the
// lab network went to server-1's listener.
func checkNoDirect(t *testing.T, pkts []lab.Packet, self, other *lab.Node, serverU netip.Addr) {
	t.Helper()
	otherAddrs := linkAddrs(t, other, lab.NetDevices)
	sent, direct := 0, 0
	for _, p := range pkts {
		// Multicast neighbour discovery, router solicitations and group
		// membership reach every node on the network: not traffic between
		// the two. Multicast of any other protocol is checked like the rest.
		if p.Network != lab.NetDevices || p.Dst.IsMulticast() && (p.Proto == lab.ProtoICMPv6 || p.Proto == lab.ProtoIGMP) {
			continue
		}
		if slices.Contains(otherAddrs, p.Src) || slices.Contains(otherAddrs, p.Dst) {
			direct++
			t.Errorf("%s: a packet between %s and %s (proto %d) didn't go through server-1", self.Name, p.Src, p.Dst, p.Proto)
		}
		if p.Outgoing && p.Proto == lab.ProtoUDP {
			if p.Dst != serverU || p.DstPort != 4500 {
				t.Errorf("%s sent a datagram to %s port %d", self.Name, p.Dst, p.DstPort)
				continue
			}
			sent++
		}
	}
	if sent < 2*burstCount {
		t.Errorf("%s sent only %d datagrams to server-1; the capture proves nothing", self.Name, sent)
	}
	t.Logf("%s: %d datagrams sent to server-1 at %s; %d packets to or from %s's addresses %v (multicast ICMPv6 and IGMP aside)", self.Name, sent, serverU, direct, other.Name, otherAddrs)
}

// linkAddrs are every address a node has on a lab network, link-local
// ones included.
func linkAddrs(t *testing.T, n *lab.Node, network string) []netip.Addr {
	t.Helper()
	var addrs []netip.Addr
	for _, m := range regexp.MustCompile(`\sinet6? (\S+)/`).FindAllStringSubmatch(n.MustExec(t, "ip", "-o", "addr", "show", "dev", n.Interface(network)), -1) {
		addrs = append(addrs, netip.MustParseAddr(m[1]))
	}
	if len(addrs) < 2 {
		t.Fatalf("%s has addresses %v on %s", n.Name, addrs, network)
	}
	return addrs
}

// checkNoWireGuard checks every udp payload that crossed the router during
// the whole run, the data plane's own and anything else, against the
// WireGuard signature: no WireGuard header at its start (lab.WireGuardHeader,
// the loosest part of the signature) and no whole WireGuard message behind
// some other header (lab.WireGuardOffset). TestCaptureFlagsRawWireGuard
// checks the classifier on raw WireGuard.
func checkNoWireGuard(t *testing.T, pkts []lab.Packet, serverU netip.Addr) {
	t.Helper()
	udp, ours, burstSized, flagged := 0, 0, 0, 0
	first := -1
	for i, p := range pkts {
		if p.Proto != lab.ProtoUDP {
			continue
		}
		udp++
		if at := lab.WireGuardOffset(p.Payload); lab.WireGuardHeader(p.Payload) || at >= 0 {
			flagged++
			t.Errorf("a datagram %s:%d → %s:%d looks like WireGuard (message at offset %d): %x", p.Src, p.SrcPort, p.Dst, p.DstPort, at, p.Payload[:min(len(p.Payload), 32)])
		}
		if serverU.Is6() && p.Src.Is4() {
			t.Errorf("a datagram %s:%d → %s:%d over IPv4 in the IPv6-only run", p.Src, p.SrcPort, p.Dst, p.DstPort)
		}
		if p.SrcPort != 4500 && p.DstPort != 4500 {
			continue
		}
		ours++
		if first < 0 {
			first = i
		}
		if p.Src.Is4() != serverU.Is4() {
			t.Errorf("a datagram of the data plane %s:%d → %s:%d isn't over %s", p.Src, p.SrcPort, p.Dst, p.DstPort, family(serverU))
		}
		if len(p.Payload) >= burstSize {
			burstSized++
		}
	}
	// The router sees each datagram twice. The bursts alone: 2 direct ones
	// (request and reply cross once each) and 2 relayed ones (twice each).
	if want := 2 * (2*2 + 2*4) * burstCount; burstSized < want {
		t.Fatalf("the router saw %d burst-sized datagrams of the data plane, want at least %d: the capture proves nothing", burstSized, want)
	}
	if pkts[first].Dst != serverU || pkts[first].Outgoing {
		t.Errorf("the first datagram the router saw goes %s → %s, not from a device dialing server-1: the capture missed the start", pkts[first].Src, pkts[first].Dst)
	}
	t.Logf("router: %d udp datagrams over the whole run (%d of the data plane, from the first handshake on, over %s; %d of them burst-sized), %d with a WireGuard header or message", udp, ours, family(serverU), burstSized, flagged)
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// TestCaptureFlagsRawWireGuard checks the classifier TestM0 relies on,
// through the same capture at the router: plain kernel WireGuard between
// device-a and server-1, every datagram of it flagged, handshakes and data
// alike.
func TestCaptureFlagsRawWireGuard(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	dev, server, router := l.Node(lab.DeviceA), l.Node(lab.Server1), l.Node(lab.Router)
	c := router.Capture(t, "udp port 51820")

	keys := map[*lab.Node]string{}
	for _, n := range []*lab.Node{dev, server} {
		n.MustExec(t, "sh", "-ec", "umask 077 && wg genkey > /tmp/wg.key")
		keys[n] = strings.TrimSpace(n.MustExec(t, "sh", "-ec", "wg pubkey < /tmp/wg.key"))
	}
	setup := func(n, peer *lab.Node, own, peerOverlay string, endpoint ...string) {
		n.MustExec(t, "ip", "link", "add", "wg0", "type", "wireguard")
		args := []string{"wg", "set", "wg0", "private-key", "/tmp/wg.key", "listen-port", "51820", "peer", keys[peer], "allowed-ips", peerOverlay + "/32"}
		n.MustExec(t, append(args, endpoint...)...)
		n.MustExec(t, "ip", "addr", "add", own+"/24", "dev", "wg0")
		n.MustExec(t, "ip", "link", "set", "wg0", "up")
	}
	setup(server, dev, "10.99.0.1", "10.99.0.2")
	setup(dev, server, "10.99.0.2", "10.99.0.1", "endpoint", server.IPv4(lab.NetServers).String()+":51820")
	dev.MustExec(t, "ping", "-c", "3", "-i", "0.2", "-W", "2", "-s", "1000", "10.99.0.1")

	types := map[byte]int{}
	n := 0
	for _, p := range complete(t, c) {
		if !p.Outgoing {
			continue // each datagram once, as it leaves the router
		}
		n++
		if !lab.LooksLikeWireGuard(p.Payload) || lab.WireGuardOffset(p.Payload) != 0 {
			t.Errorf("not flagged: %s:%d → %s:%d, %d bytes: %x", p.Src, p.SrcPort, p.Dst, p.DstPort, len(p.Payload), p.Payload[:min(len(p.Payload), 32)])
		}
		types[p.Payload[0]]++
	}
	for typ, name := range map[byte]string{1: "handshake initiation", 2: "handshake response", 4: "transport data"} {
		if types[typ] == 0 {
			t.Errorf("no WireGuard %s crossed the router; the check proves nothing", name)
		}
	}
	t.Logf("router: %d raw WireGuard datagrams (by type: %v), all flagged", n, types)
}

// complete stops a capture and fails the test unless it saw every packet.
func complete(t *testing.T, c *lab.Capture) []lab.Packet {
	t.Helper()
	if err := c.Complete(); err != nil {
		t.Fatal(err)
	}
	return c.Packets()
}
