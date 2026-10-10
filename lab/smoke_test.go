//go:build lab

package lab_test

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
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
		if _, err := device.Exec(t.Context(), "ping", "-c", "1", "-W", "1", "192.0.2.1"); err == nil {
			t.Error("a device reached an address outside the lab")
		}
		var gateways []string
		for _, net := range []string{lab.NetDevices, lab.NetServers} {
			gws := l.DockerGateways(net)
			if len(gws) != 2 {
				t.Fatalf("network %s: Docker gateways %v, want IPv4 and IPv6", net, gws)
			}
			for _, gw := range gws {
				gateways = append(gateways, gw.String())
			}
		}
		pingAll := `for gw; do (ping -c 1 -W 1 "$gw" >/dev/null 2>&1 && echo "reached $gw") & done; wait`
		for _, n := range []*lab.Node{router, device, internet} {
			if out := n.MustExec(t, append([]string{"sh", "-c", pingAll, "sh"}, gateways...)...); out != "" {
				t.Errorf("%s reached Docker's gateways:\n%s", n.Name, out)
			}
		}
		// Names: lab nodes resolve through /etc/hosts, nothing else does,
		// not even through Docker's own resolver at 127.0.0.11, which would
		// forward the lookup out of the lab.
		if out := device.MustExec(t, "getent", "ahostsv4", lab.Internet); !strings.HasPrefix(out, internet.IPv4(lab.NetServers).String()) {
			t.Errorf("internet resolves to %q", out)
		}
		if _, err := device.Exec(t.Context(), "getent", "hosts", "example.com"); err == nil {
			t.Error("a device resolved an outside name")
		}
		viaDocker := `printf 'nameserver 127.0.0.11\noptions timeout:2 attempts:1\n' > /tmp/docker-dns && ` +
			`exec unshare -m sh -c 'mount --bind /tmp/docker-dns /etc/resolv.conf && getent hosts "$0"' `
		if _, err := device.Exec(t.Context(), "sh", "-c", viaDocker+lab.Router); err != nil {
			t.Fatalf("Docker's resolver doesn't answer for lab names, so the next check proves nothing: %v", err)
		}
		if _, err := device.Exec(t.Context(), "sh", "-c", viaDocker+"example.com"); err == nil {
			t.Error("Docker's resolver forwarded an outside name")
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
	if _, err := a.Exec(t.Context(), "ping", "-c", "1", "-W", "1", b.IPv4("net").String()); err == nil {
		t.Error("one lab reached the other")
	}
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
