//go:build lab

package lab_test

import (
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Two labs started side by side share nothing: separate containers and
// networks, no route between them, and tearing one down leaves the other.
func TestHarnessLabsAreIsolated(t *testing.T) {
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
func TestHarnessIPv4OnlyNetwork(t *testing.T) {
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
func TestHarnessCommandStartsSealed(t *testing.T) {
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
