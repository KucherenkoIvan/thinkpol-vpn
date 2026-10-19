//go:build lab

package lab_test

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// The harness itself: a device reaches the internet target through the
// router over IPv4 and IPv6, the router sees it, and nothing else routes.
func TestSmoke(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	device, router, internet := l.Node(lab.DeviceA), l.Node(lab.Router), l.Node(lab.Internet)

	for _, family := range []struct {
		name string
		addr func(*lab.Node, string) netip.Addr
	}{
		{"ipv4", (*lab.Node).IPv4},
		{"ipv6", (*lab.Node).IPv6},
	} {
		t.Run(family.name, func(t *testing.T) {
			src, dst := family.addr(device, lab.NetDevices), family.addr(internet, lab.NetServers)
			if !src.IsValid() || !dst.IsValid() {
				t.Fatalf("no %s addresses: %v → %v", family.name, src, dst)
			}

			capture := router.Capture(t, "udp port 9999")
			// bash's /dev/udp sends one datagram without needing a client tool.
			device.MustExec(t, "bash", "-c", `echo "hello lab" > /dev/udp/`+dst.String()+`/9999`)
			in := capture.WaitFor(t, 10*time.Second, func(p lab.Packet) bool {
				return p.Network == lab.NetDevices && !p.Outgoing
			})
			out := capture.WaitFor(t, 10*time.Second, func(p lab.Packet) bool {
				return p.Network == lab.NetServers && p.Outgoing
			})
			for _, p := range []lab.Packet{in, out} {
				if p.Src != src || p.Dst != dst || p.Proto != lab.ProtoUDP || p.DstPort != 9999 {
					t.Errorf("unexpected packet at the router: %+v", p)
				}
				if !bytes.Equal(p.Payload, []byte("hello lab\n")) {
					t.Errorf("payload %q", p.Payload)
				}
			}

			ping := router.Capture(t, "icmp or icmp6")
			device.MustExec(t, "ping", "-c", "2", "-W", "2", dst.String())
			var requests, replies int
			for _, p := range ping.Stop() {
				switch {
				case p.Src == src && p.Dst == dst:
					requests++
				case p.Src == dst && p.Dst == src:
					replies++
				}
			}
			// each one crosses the router: seen arriving and leaving
			if requests < 4 || replies < 4 {
				t.Errorf("router saw %d requests and %d replies, want 4 each", requests, replies)
			}
		})
	}

	t.Run("hermetic", func(t *testing.T) {
		for _, n := range []*lab.Node{router, device, internet} {
			for _, family := range []string{"-4", "-6"} {
				if out := n.MustExec(t, "ip", family, "route", "show", "default"); n == router && out != "" {
					t.Errorf("router has a default route: %s", out)
				}
			}
		}
		noPing(t, device, "-c", "2", "-W", "1", "192.0.2.1") // outside the lab
		type gateway struct {
			net  string
			addr netip.Addr
		}
		var gateways []gateway
		for _, net := range []string{lab.NetDevices, lab.NetServers} {
			gws := l.DockerGateways(net)
			if len(gws) != 2 {
				t.Fatalf("network %s: Docker gateways %v, want IPv4 and IPv6", net, gws)
			}
			for _, gw := range gws {
				gateways = append(gateways, gateway{net, gw})
			}
		}
		pingOnce := func(dst string) []string {
			if strings.Contains(dst, ":") {
				return []string{"-6", "-c", "1", "-W", "1", dst}
			}
			return []string{"-c", "1", "-W", "1", dst}
		}
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			problems []string
		)
		problem := func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			problems = append(problems, fmt.Sprintf(format, args...))
		}
		// A gateway on one of n's networks is blackholed on n (the
		// sealing): ping's "no" is the blackhole's. Another network's
		// goes to n's gateway, whose own blackhole drops it: no reply.
		// Both measured; anything else fails.
		for _, n := range []*lab.Node{router, device, internet} {
			for _, gw := range gateways {
				no := pingNoReply
				if n.Interface(gw.net) != "" {
					no = pingBlackholed
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if answered, out, err := pingAnswers(n, no, pingOnce(gw.addr.String())...); err != nil {
						problem("%s to Docker's gateway %s: %v", n.Name, gw.addr, err)
					} else if answered {
						problem("%s reached Docker's gateway %s:\n%s", n.Name, gw.addr, out)
					}
				}()
			}
		}
		// Docker's bridge also has a link-local address, which no route
		// covers; frames to and from its MAC are dropped: a ping gets no
		// reply, a TCP connect times out ("Connection refused" would mean
		// the bridge answered), and no neighbour entry holds its MAC.
		for _, net := range []string{lab.NetDevices, lab.NetServers} {
			b := l.DockerBridge(net)
			if !b.LinkLocal.IsValid() || b.MAC == "" {
				t.Fatalf("network %s: bridge %+v", net, b)
			}
			for _, n := range []*lab.Node{router, device, internet} {
				ifname := n.Interface(net)
				if ifname == "" {
					continue
				}
				ll := b.LinkLocal.WithZone(ifname)
				wg.Add(1)
				go func() {
					defer wg.Done()
					if answered, out, err := pingAnswers(n, pingNoReply, pingOnce(ll.String())...); err != nil {
						problem("%s pinging Docker's bridge %s: %v", n.Name, ll, err)
					} else if answered {
						problem("%s reached Docker's bridge %s:\n%s", n.Name, ll, out)
					}
					if res, _, err := tcpConnect(n, ll, 12345, 2); err == nil {
						problem("%s connected to Docker's bridge %s", n.Name, ll)
					} else if res.ExitCode != 1 || !strings.Contains(res.Stderr, "timed out") {
						problem("%s connecting to Docker's bridge %s: %v\n%s", n.Name, ll, err, res.Stderr)
					}
					if out, err := execRead(n, execTimeout, "ip", "-6", "neigh", "show", b.LinkLocal.String(), "dev", ifname); err != nil {
						problem("%s reading its neighbours: %v", n.Name, err)
					} else if strings.Contains(out, "lladdr") {
						problem("%s has Docker's bridge as a neighbour: %s", n.Name, out)
					}
				}()
			}
		}
		wg.Wait()
		for _, p := range problems {
			t.Error(p)
		}

		// Names: lab nodes resolve through /etc/hosts, nothing else does,
		// not even through Docker's own resolver at 127.0.0.11, which would
		// forward the lookup out of the lab.
		if out := device.MustExec(t, "getent", "ahostsv4", lab.Internet); !strings.HasPrefix(out, internet.IPv4(lab.NetServers).String()) {
			t.Errorf("internet resolves to %q", out)
		}
		wantNoLookup(t, device, "an outside name on a device", "getent", "hosts", "example.com")
		// Asked directly, Docker's resolver answers a lab name (the
		// control) and can only fail to forward an outside one: SERVFAIL,
		// once its own forwarding times out (about 4s, measured), so the
		// client waits longer. A timeout or any other rcode is no proof.
		dockerDNS := func(name string) string {
			t.Helper()
			out, err := execRead(device, execTimeout, "labdns", "-server", "127.0.0.11:53", "-timeout", "20s", "-query", name)
			if err != nil {
				t.Fatalf("asking Docker's resolver for %s: %v", name, err)
			}
			return strings.TrimSpace(out)
		}
		if got := dockerDNS(lab.Router); got != "NOERROR" {
			t.Fatalf("Docker's resolver answers %s for a lab name, so the next check proves nothing", got)
		}
		if got := dockerDNS("example.com"); got != "SERVFAIL" {
			t.Errorf("Docker's resolver answered an outside name with %s, want SERVFAIL (forwarding failed)", got)
		}
	})

	t.Run("processes", func(t *testing.T) {
		p := internet.Start(t, "sh", "-c", "echo started; sleep 600")
		lab.Eventually(t, 10*time.Second, func() error {
			if p.Output() != "started\n" {
				return fmt.Errorf("output so far: %q", p.Output())
			}
			return nil
		})
		_ = p.Stop()
		select {
		case <-p.Done():
		default:
			t.Error("process still running after Stop")
		}
		internet.WriteFile(t, "/tmp/lab/file", []byte("written"))
		if got := internet.MustExec(t, "cat", "/tmp/lab/file"); got != "written" {
			t.Errorf("file holds %q", got)
		}
	})

	t.Run("gotest", func(t *testing.T) {
		device.RunGoTests(t, "./lab", "-test.run", "TestInsideLab")
	})
}

// Two labs started side by side share nothing: separate containers and
// networks, no route between them, and tearing one down leaves the other.
func TestLabsAreIsolated(t *testing.T) {
	t.Parallel()
	topo := lab.Topology{
		Networks: []lab.Network{{Name: "net"}},
		Nodes:    []lab.NodeSpec{{Name: "node", Networks: []string{"net"}}},
	}
	first, second := lab.Start(t, topo), lab.Start(t, topo)
	a, b := first.Node("node"), second.Node("node")
	if first.Project == second.Project || a.Container == b.Container {
		t.Fatalf("labs share a project or container: %s, %s", first.Project, second.Project)
	}
	if a.IPv4("net") == b.IPv4("net") || a.IPv6("net") == b.IPv6("net") {
		t.Fatalf("labs share addresses: %+v, %+v", a.Addr("net"), b.Addr("net"))
	}
	noPing(t, a, "-c", "1", "-W", "1", b.IPv4("net").String()) // the other lab
	if err := first.Down(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := b.MustExec(t, "echo", "alive"); got != "alive\n" {
		t.Errorf("second lab after the first went down: %q", got)
	}
}

// An IPv4Only network gives its nodes no IPv6 address and no IPv6 route.
func TestIPv4OnlyNetwork(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Topology{
		Networks: []lab.Network{{Name: "v4", IPv4Only: true}},
		Nodes:    []lab.NodeSpec{{Name: "gw", Networks: []string{"v4"}, Forward: true}, {Name: "node", Networks: []string{"v4"}, Gateway: "gw"}},
	})
	n := l.Node("node")
	if n.IPv6("v4").IsValid() || !n.IPv4("v4").IsValid() {
		t.Fatalf("addresses %+v", n.Addr("v4"))
	}
	if out := n.MustExec(t, "ip", "-6", "addr", "show", "scope", "global"); out != "" {
		t.Errorf("global IPv6 address on an IPv4-only network: %s", out)
	}
	if got, want := n.MustExec(t, "ip", "-4", "route", "show", "default"), "default via "+l.Node("gw").IPv4("v4").String(); !strings.HasPrefix(got, want) {
		t.Errorf("default route %q, want %q", got, want)
	}
}

// A node's own Command starts only once the node is sealed into the lab.
func TestCommandStartsSealed(t *testing.T) {
	t.Parallel()
	// Written aside and renamed, so the poll below never reads a partial file.
	record := `{ cat /etc/resolv.conf; ip -4 route show default; nft list tables; } > /tmp/at-start.tmp && mv /tmp/at-start.tmp /tmp/at-start; sleep infinity`
	l := lab.Start(t, lab.Topology{
		Networks: []lab.Network{{Name: "net"}},
		Nodes: []lab.NodeSpec{
			{Name: "gw", Networks: []string{"net"}},
			{Name: "node", Networks: []string{"net"}, Gateway: "gw", Command: []string{"sh", "-c", record}},
		},
	})
	n := l.Node("node")
	var atStart string
	lab.Eventually(t, 30*time.Second, func() error {
		out, err := execRead(n, pollTimeout, "cat", "/tmp/at-start")
		atStart = out
		return err
	})
	for _, want := range []string{"nameserver 127.0.0.1", "default via " + l.Node("gw").IPv4("net").String(), "table netdev tplab_"} {
		if !strings.Contains(atStart, want) {
			t.Errorf("at start the node had no %q:\n%s", want, atStart)
		}
	}
}
