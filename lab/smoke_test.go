//go:build lab

package lab_test

import (
	"bytes"
	"fmt"
	"net/netip"
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
		if out := router.MustExec(t, "ip", "route", "show", "default"); out != "" {
			t.Errorf("router has a default route: %s", out)
		}
		if _, err := device.Exec(t.Context(), "ping", "-c", "1", "-W", "1", "192.0.2.1"); err == nil {
			t.Error("a device reached an address outside the lab")
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
