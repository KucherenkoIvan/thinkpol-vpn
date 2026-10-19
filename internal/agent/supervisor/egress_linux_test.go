//go:build linux && !android

package supervisor_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread"
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
	// Also on the internet's loopback: a private address the supervisor
	// is told to allow, one it blocks, and the metadata services'.
	allowedPrivate, blockedPrivate = netip.MustParseAddr("10.9.9.9"), netip.MustParseAddr("10.9.8.9")
	metadata4, metadata6           = netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254")
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
		for a in %[11]s %[12]s %[13]s; do
			ip -n %[1]s addr add $a/32 dev lo
			ip route add $a/32 via %[6]s dev %[3]s
		done
		ip -n %[1]s addr add %[14]s/128 dev lo
		ip -6 route add %[14]s/128 via %[7]s dev %[3]s
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
	`, inet, lan, uplink, upRoot4, upRoot6, upFar4, upFar6, internet4, internet6, lanHost,
		allowedPrivate, blockedPrivate, metadata4, metadata6))
	return inet, lan
}

// inNamespace runs fn on a thread in the named network namespace (see
// inNetns).
func inNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	inNetns(t, "/run/netns/"+name, fn)
}

// inWorker runs fn on a thread in the network namespace of the worker pid
// (see inNetns).
func inWorker(t *testing.T, pid int, fn func()) {
	t.Helper()
	inNetns(t, fmt.Sprintf("/proc/%d/ns/net", pid), fn)
}

// inNetns runs fn on a thread in the network namespace at path, which
// nsthread moves back afterwards; sockets fn opens stay there.
func inNetns(t *testing.T, path string, fn func()) {
	t.Helper()
	err := nsthread.Do(func() error {
		ns, err := netns.GetFromPath(path)
		if err != nil {
			return err
		}
		defer func() { _ = ns.Close() }()
		if err := netns.Set(ns); err != nil {
			return err
		}
		fn()
		return nil
	})
	if err != nil {
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

// fixedUplink is the test's uplink, whatever the lab node's routes say.
func fixedUplink() (egress.Uplink, error) {
	return egress.Uplink{Name: uplink, IPv4: true, IPv6: true}, nil
}

// egressOptions are the probe workers' options with the test's uplink, the
// allowed private network and a runtime directory of the test's own.
func egressOptions(t *testing.T) supervisor.Options {
	o := options([]string{envProbe + "=1"})
	o.Uplink = fixedUplink
	o.EgressAllowed = []netip.Prefix{netip.PrefixFrom(allowedPrivate, 24).Masked()}
	o.RuntimeDir = t.TempDir()
	return o
}

// dropped is the sum of the counters in one of the supervisor's inet
// chains (only drops count).
func dropped(t *testing.T, chain string) uint64 {
	t.Helper()
	return nftDrops(t, "inet", supervisor.TableName, chain)
}

// nftDrops is the sum of the counters in a chain of an nftables table. It
// reads nft's listing: google/nftables can't read back a rule matching the
// original direction (it sends the direction as 4 bytes, the kernel answers
// with 1).
func nftDrops(t *testing.T, family, table, chain string) uint64 {
	t.Helper()
	out, err := exec.Command("nft", "list", "chain", family, table, chain).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list chain %s %s %s: %v: %s", family, table, chain, err, out)
	}
	var n uint64
	for _, m := range counterRE.FindAllStringSubmatch(string(out), -1) {
		v, _ := strconv.ParseUint(m[1], 10, 64)
		n += v
	}
	return n
}

var counterRE = regexp.MustCompile(`counter packets (\d+) bytes \d+`)

// awaitDrops waits until the supervisor's inet chain has dropped at least
// n more packets than before: proof that what a negative check waits for
// was sent and refused.
func awaitDrops(t *testing.T, chain string, before, n uint64) {
	t.Helper()
	awaitNftDrops(t, "inet", supervisor.TableName, chain, before, n)
}

// awaitNftDrops is awaitDrops for a chain of any table.
func awaitNftDrops(t *testing.T, family, table, chain string, before, n uint64) {
	t.Helper()
	eventually(t, 15*time.Second, fmt.Sprintf("%d drops in %s %s %s", n, family, table, chain), func() error {
		if got := nftDrops(t, family, table, chain); got < before+n {
			return fmt.Errorf("%d so far", got-before)
		}
		return nil
	})
}

// spaceTable is a worker's namespace's egress table, as nft lists it.
func spaceTable(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid), "nft", "list", "table", "inet", supervisor.SpaceTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("the space's table: %v: %s", err, out)
	}
	return string(out)
}

// TestEgress: a space with egress reaches the internet by the uplink, over
// IPv4 and IPv6, masqueraded to the uplink's addresses, its overlay sources
// SNATed to its transit address first, and an allowed private network; not
// the metadata services, a blocked private network, nor another space. A
// space without egress on the same node reaches only the endpoints its
// section dials, in their protocol, and nothing through the other space's
// egress. Turning egress off closes it and rewrites the space's own table.
// The root's forwarding is turned on for egress and put back by Close.
func TestEgress(t *testing.T) {
	needsLab(t)
	inet, _ := labInternet(t)
	const forward4, forward6 = "net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"
	rootSysctls(t, "0", forward4, forward6)
	probes, dialed, wrongProto := listenIn(t, inet, probePort), listenIn(t, inet, probePort+1), listenIn(t, inet, probePort+2)

	s, err := supervisor.New(egressOptions(t))
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
	dial := supervisor.Dial{Address: netip.AddrPortFrom(internet4, probePort+1), Network: "udp"}
	tcpDial := supervisor.Dial{Address: netip.AddrPortFrom(internet4, probePort+2), Network: "tcp"}
	targets := func(cross netip.Addr) []byte {
		return []byte(strings.Join([]string{
			internet4.String() + "#v4",
			netip.AddrPortFrom(internet6, probePort).String() + "#v6",
			internet4.String() + "@100.64.0.5#overlay",
			dial.Address.String() + "#dial",
			tcpDial.Address.String() + "#wrongproto", // a UDP datagram to a TCP dial
			allowedPrivate.String() + "#allowed",
			blockedPrivate.String() + "#private",
			metadata4.String() + "#metadata",
			netip.AddrPortFrom(metadata6, probePort).String() + "#metadata6",
			cross.String() + "#cross",
		}, "\n"))
	}
	if err := s.SetSpaces([]supervisor.Space{{ID: exit}, {ID: other}}); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, exit, other)
	spaces := func(e supervisor.EgressGrant) []supervisor.Space {
		return []supervisor.Space{
			{ID: exit, Config: targets(ws[1].SpaceAddrs[0].Addr()), Egress: e},
			{ID: other, Config: targets(ws[0].SpaceAddrs[0].Addr()), Dials: []supervisor.Dial{dial, tcpDial}},
		}
	}
	blockedBefore := dropped(t, "space_out")
	if err := s.SetSpaces(spaces(supervisor.EgressGrant{IPv4: true, IPv6: true})); err != nil {
		t.Fatal(err)
	}
	if readSysctl(forward4) != "1" || readSysctl(forward6) != "1" {
		t.Fatalf("forwarding not turned on: %s %s", readSysctl(forward4), readSysctl(forward6))
	}
	if e := s.Egress(); e != (supervisor.EgressInfo{Uplink: uplink, IPv4: true, IPv6: true, Forwarding4: true, Forwarding6: true}) {
		t.Fatalf("egress %+v", e)
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
			{probes, upRoot4, tagged(exit, "allowed")},
			{dialed, upRoot4, tagged(exit, "dial")},
			{dialed, upRoot4, tagged(other, "dial")},
		} {
			if !want.at.from(want.src, want.payload) {
				return fmt.Errorf("no %q from %s; got %q", want.payload, want.src, append(probes.list(), dialed.list()...))
			}
		}
		return nil
	})
	// Two spaces send to four blocked destinations every 100 ms.
	awaitDrops(t, "space_out", blockedBefore, 40)
	for _, l := range append(append(probes.list(), dialed.list()...), wrongProto.list()...) {
		src, payload, _ := strings.Cut(l, " ")
		if src != upRoot4.String() && src != upRoot6.String() {
			t.Errorf("arrived unmasqueraded: %q", l)
		}
		for _, tag := range []string{"#private", "#metadata", "#metadata6"} {
			if strings.HasSuffix(payload, tag) {
				t.Errorf("a blocked destination got %q", l)
			}
		}
		// The other space's UDP to its TCP dial included.
		if strings.Contains(payload, other.String()) && !strings.HasSuffix(payload, "#dial") {
			t.Errorf("the space without egress got out: %q", l)
		}
	}
	for i, id := range []netmap.SpaceID{exit, other} {
		for _, l := range probeLines(s, id) {
			if strings.HasPrefix(l, "got ") && strings.Contains(l, "#cross") {
				t.Errorf("space %d got another space's datagram: %q", i, l)
			}
		}
	}
	if table := spaceTable(t, ws[0].PID); !strings.Contains(table, "meta nfproto ipv4 accept") {
		t.Fatalf("the exit space's table forwards nothing:\n%s", table)
	}

	// Egress off: nothing of the exit space's gets out (its section dials
	// nothing), its own table forwards nothing, and the other space's dial
	// goes on.
	if err := s.SetSpaces(spaces(supervisor.EgressGrant{})); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the space's table follows", func() error {
		if table := spaceTable(t, ws[0].PID); strings.Contains(table, "meta nfproto ipv4 accept") {
			return fmt.Errorf("still forwards:\n%s", table)
		}
		return nil
	})
	refused := dropped(t, "space_accept")
	awaitDrops(t, "space_accept", refused, 10) // what was in flight is through
	exitBefore := map[string]int{}
	for _, tag := range []string{"v4", "v6", "overlay", "allowed"} {
		exitBefore[tag] = probes.count(tagged(exit, tag))
	}
	exitDials, otherDials := dialed.count(tagged(exit, "dial")), dialed.count(tagged(other, "dial"))
	awaitDrops(t, "space_accept", dropped(t, "space_accept"), 20)
	for tag, n := range exitBefore {
		if got := probes.count(tagged(exit, tag)); got != n {
			t.Errorf("%s: %d more arrived with egress off", tag, got-n)
		}
	}
	if got := dialed.count(tagged(exit, "dial")); got != exitDials {
		t.Errorf("%d more of the exit space's datagrams to another server's port with egress off", got-exitDials)
	}
	eventually(t, 5*time.Second, "the other space's dial goes on", func() error {
		if dialed.count(tagged(other, "dial")) == otherDials {
			return errors.New("no new datagram")
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

// Where the supervisor turned forwarding on itself, it forwards only the
// spaces' traffic: a LAN behind the node gets nothing through; where the
// node forwarded already, its own forwarding goes on as before, and isn't
// masqueraded. An RA-configured uplink keeps taking advertisements
// (accept_ra 2) while IPv6 forwarding is on, and is put back by Close.
func TestForwardingTurnedOnForwardsOnlyTheSpaces(t *testing.T) {
	needsLab(t)
	for _, tc := range []struct {
		name   string
		before string
	}{{"off before", "0"}, {"on before", "1"}} {
		t.Run(tc.name, func(t *testing.T) {
			inet, lan := labInternet(t)
			const forward4, forward6 = "net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"
			rootSysctls(t, tc.before, forward4, forward6)
			raKey := "net/ipv6/conf/" + uplink + "/accept_ra"
			rootSysctls(t, "1", raKey)
			probes := listenIn(t, inet, probePort)
			s, err := supervisor.New(egressOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = s.Close()
				}
			})
			if err := s.SetSpaces([]supervisor.Space{{ID: netmap.NewSpaceID(), Egress: supervisor.EgressGrant{IPv4: true, IPv6: true}}}); err != nil {
				t.Fatal(err)
			}
			wantRA := "1"
			if tc.before == "0" {
				wantRA = "2"
			}
			if got := readSysctl(raKey); got != wantRA {
				t.Errorf("accept_ra %s while serving, want %s", got, wantRA)
			}
			send := func() {
				inNamespace(t, lan, func() {
					if c, err := net.Dial("udp", netip.AddrPortFrom(internet4, probePort).String()); err == nil {
						_, _ = c.Write([]byte("lan"))
						_ = c.Close()
					}
				})
			}
			if tc.before == "1" {
				eventually(t, 5*time.Second, "the LAN's datagram, unmasqueraded", func() error {
					send()
					if !probes.from(lanHost, "lan") {
						return fmt.Errorf("got %q", probes.list())
					}
					return nil
				})
			} else {
				before := dropped(t, "forward")
				eventually(t, 5*time.Second, "the LAN's datagrams dropped", func() error {
					send()
					if dropped(t, "forward") < before+5 {
						return errors.New("not yet")
					}
					return nil
				})
				if got := probes.list(); len(got) > 0 {
					t.Errorf("the LAN got through forwarding the supervisor turned on: %q", got)
				}
			}
			closed = true
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if readSysctl(forward4) != tc.before || readSysctl(forward6) != tc.before || readSysctl(raKey) != "1" {
				t.Fatalf("after Close: forwarding %s/%s, accept_ra %s", readSysctl(forward4), readSysctl(forward6), readSysctl(raKey))
			}
		})
	}
}

// ICMP errors a worker forges, quoting a flow that isn't its own space's,
// go nowhere: conntrack takes them as related to that flow, but the
// accepts are bound to the flows a slot started. A "port unreachable" or
// "fragmentation needed" quoting a root socket's flow never reaches it (no
// socket error, no lowered path MTU), and one quoting another space's flow
// never leaves the node. The negative control accepts any established or
// related flow and lets them through.
func TestForgedICMPErrorsAreRefused(t *testing.T) {
	needsLab(t)
	for _, bound := range []bool{true, false} {
		t.Run(fmt.Sprintf("bound=%v", bound), func(t *testing.T) {
			inet, _ := labInternet(t)
			rootSysctls(t, "1", "net/ipv4/ip_forward")
			listenIn(t, inet, probePort)
			icmps := icmpListenIn(t, inet)

			// The root's socket whose flow the forged errors quote. An
			// unreplied UDP flow expires (nf_conntrack_udp_timeout), so
			// it is opened just before the errors are sent.
			root, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(internet4, probePort)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			rootPort := root.LocalAddr().(*net.UDPAddr).AddrPort().Port()

			opts := egressOptions(t)
			if !bound {
				opts = supervisor.WithUnboundAccepts(opts)
			}
			s, err := supervisor.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			victim, forger := netmap.NewSpaceID(), netmap.NewSpaceID()
			grant := supervisor.EgressGrant{IPv4: true}
			if err := s.SetSpaces([]supervisor.Space{{ID: victim, Egress: grant}, {ID: forger, Egress: grant}}); err != nil {
				t.Fatal(err)
			}
			ws := waitReady(t, s, victim, forger)
			victimAddr := ws[0].SpaceAddrs[0].Addr()
			quoteRoot := func(code byte, mtu uint16) string {
				return (&icmpError{dst: upRoot4, typ: 3, code: code, mtu: mtu,
					innerSrc: netip.AddrPortFrom(upRoot4, rootPort), innerDst: netip.AddrPortFrom(internet4, probePort)}).String()
			}
			forged := []string{
				quoteRoot(3, 0),   // port unreachable
				quoteRoot(4, 576), // fragmentation needed
				// The victim's flow (its probe sends from :7000), as if
				// the forger answered a packet of it.
				(&icmpError{dst: internet4, typ: 3, code: 3,
					innerSrc: netip.AddrPortFrom(internet4, probePort), innerDst: netip.AddrPortFrom(victimAddr, probePort)}).String(),
			}
			inputDrops, acceptDrops := dropped(t, "input"), dropped(t, "space_accept")
			if _, err := root.Write([]byte("root")); err != nil {
				t.Fatal(err)
			}
			if err := s.SetSpaces([]supervisor.Space{
				{ID: victim, Egress: grant, Config: []byte(internet4.String() + "#flow")},
				{ID: forger, Egress: grant, Config: []byte(strings.Join(forged, "\n"))},
			}); err != nil {
				t.Fatal(err)
			}

			// errorReached reports whether a socket error reached the
			// root's socket. The forger sends a port unreachable and a
			// fragmentation needed on the same flow, and the second
			// usually overwrites the first in sk_err (EMSGSIZE over
			// ECONNREFUSED), so whichever error surfaces counts; a read
			// timeout is not one.
			errorReached := func() bool {
				if _, err := root.Write([]byte("root")); err != nil {
					return true
				}
				_ = root.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, err := root.Read(make([]byte, 64))
				if err == nil {
					return false
				}
				var ne net.Error
				return !errors.As(err, &ne) || !ne.Timeout()
			}
			// rootFlowTracked reports whether conntrack has the root's
			// flow, matched as its original direction's tuple. Only
			// while it does are the forged errors related to it, so
			// only then do the drops test the binding.
			rootFlowTracked := func() bool {
				out, err := os.ReadFile("/proc/thread-self/net/nf_conntrack")
				if err != nil {
					t.Fatalf("conntrack entries: %v: the kernel needs CONFIG_NF_CONNTRACK_PROCFS", err)
				}
				// The trailing space keeps 4000 from matching 40001.
				tuple := fmt.Sprintf("src=%s dst=%s sport=%d dport=%d ", upRoot4, internet4, rootPort, probePort)
				return slices.ContainsFunc(strings.Split(string(out), "\n"), func(l string) bool {
					f := strings.Fields(l)
					return len(f) > 2 && f[2] == "udp" && strings.Contains(l, tuple)
				})
			}
			if !bound {
				eventually(t, 15*time.Second, "the forged errors get through without the binding", func() error {
					if !errorReached() {
						return fmt.Errorf("no socket error, sent on %d", icmps.count())
					}
					return nil
				})
				return
			}
			awaitDrops(t, "input", inputDrops, 20)
			awaitDrops(t, "space_accept", acceptDrops, 10)
			if !rootFlowTracked() {
				t.Fatal("the root's conntrack flow expired before the forged errors were counted: the test proves nothing")
			}
			for range 5 {
				if errorReached() {
					t.Fatal("a forged ICMP error reached the root's socket")
				}
			}
			if lowered() {
				t.Error("a forged fragmentation needed lowered the root's path MTU")
			}
			if n := icmps.count(); n > 0 {
				t.Errorf("%d forged errors quoting another space's flow left the node", n)
			}
		})
	}
}

// lowered reports whether the root's route to the internet carries a path
// MTU a forged fragmentation needed could have set.
func lowered() bool {
	out, _ := exec.Command("ip", "route", "get", internet4.String()).CombinedOutput()
	return strings.Contains(string(out), "mtu 576")
}

// icmpCounter counts ICMP destination-unreachable messages from the node
// arriving in the internet's namespace.
type icmpCounter struct {
	mu sync.Mutex
	n  int
}

func (c *icmpCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func icmpListenIn(t *testing.T, ns string) *icmpCounter {
	t.Helper()
	var fd int
	var err error
	inNamespace(t, ns, func() { fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP) })
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "icmp")
	t.Cleanup(func() { _ = f.Close() })
	c := &icmpCounter{}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			// IPv4 header, then ICMP: type 3 from the node's uplink address.
			if n > 20 && buf[20] == 3 && netip.AddrFrom4([4]byte(buf[12:16])) == upRoot4 {
				c.mu.Lock()
				c.n++
				c.mu.Unlock()
			}
		}
	}()
	return c
}
