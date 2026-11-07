//go:build lab

package lab_test

import (
	"fmt"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestHealthWithNoLinkUp: a device whose only server never answers says so
// in `thinkpol status` (TP-140), whether the server drops every packet or
// every dial fails (no route to it), and health is ok again once the link
// comes up.
func TestHealthWithNoLinkUp(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	srv := server.Start(t, "thinkpol", "up")
	waitLog(t, srv, `worker space=\S+ .*msg="map applied"`)
	s4, s6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)

	noLinkUp := regexp.MustCompile(`(?m)^health: +down: .*no_link_up`)
	healthOK := regexp.MustCompile(`(?m)^health: +ok$`)
	status := func() (string, error) { return execRead(dev, pollTimeout, "thinkpol", "status") }
	waitStatus := func(t *testing.T, re *regexp.Regexp) {
		t.Helper()
		lab.Eventually(t, 60*time.Second, func() error {
			out, err := status()
			if err != nil {
				return err
			}
			if !re.MatchString(out) {
				return fmt.Errorf("no %q in\n%s", re, out)
			}
			return nil
		})
	}

	t.Run("the server drops every packet", func(t *testing.T) {
		server.MustExec(t, "nft", "-f", "-", "--", `table inet tp140 {
			chain input { type filter hook input priority -10; policy accept; udp dport 4500 drop; }
		}`)
		up := dev.Start(t, "thinkpol", "up")
		waitLog(t, up, "mode=device")
		waitStatus(t, noLinkUp)
		server.MustExec(t, "nft", "delete", "table", "inet", "tp140")
		waitStatus(t, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("every dial fails", func(t *testing.T) {
		dev.MustExec(t, "ip", "route", "add", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "add", "unreachable", s6.String()+"/128")
		up := dev.Start(t, "thinkpol", "up")
		waitLog(t, up, `msg="dial failed"`)
		waitStatus(t, noLinkUp)
		dev.MustExec(t, "ip", "route", "del", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "del", "unreachable", s6.String()+"/128")
		waitStatus(t, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})
}

// TestHealthWithAnExitThatNeverHandshakes runs lab/maps/egress.yaml:
// device-a's chain ends at server-2, relayed by server-1. server-2 drops
// every WireGuard handshake initiation that reaches it while its links
// stay up, so device-a's first hop is up and its exit never answers:
// `thinkpol status` says exit_no_handshake (TP-195), not no_link_up, and
// health is ok again once the exit answers.
func TestHealthWithAnExitThatNeverHandshakes(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	s1, s2, devA, inet := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inet4, exit4 := inet.IPv4(lab.NetServers), s2.IPv4(lab.NetServers)
	space := &m0Space{builder: inet, spec: "/src/lab/maps/egress.yaml", flags: []string{"-insecure-secrets-seed", "egress-lab"}, env: []string{
		"SERVER_1_IPV4=" + s1.IPv4(lab.NetServers).String(), "SERVER_2_IPV4=" + exit4.String(),
		"SERVER_2_EGRESS=true", "EXIT=server-2",
	}}
	space.builder.MustExec(t, "sh", "-ec", `mkdir -p /tmp/m0 && cd /tmp/m0
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 server-2 server-3 device-a >/dev/null`)
	envelope, version := space.build(t)

	// A relayed initiation reaches server-2 as one unpadded udp datagram:
	// the path header and WireGuard's 148 bytes inside. Probes and
	// WireGuard data (32 bytes and up, in 16-byte steps) never have that
	// length, so the links stay up.
	initiation := 8 + udp.Overhead + path.HeaderSize + device.MessageInitiationSize
	s2.MustExec(t, "nft", "-f", "-", "--", fmt.Sprintf(`table inet tp195 {
		chain input { type filter hook input priority -10; policy accept; udp dport 4500 udp length %d drop; }
	}`, initiation))

	nodes := map[string]*lab.Node{"server-1": s1, "server-2": s2, "device-a": devA}
	up := map[string]*lab.Process{}
	servers := netip.PrefixFrom(inet4, 24).Masked().String()
	for name, n := range nodes {
		space.install(t, n, name, envelope)
		up[name] = n.Start(t, "thinkpol", "up", "-egress-allowed", servers)
	}
	waitLog(t, up["device-a"], applied(version))

	// Each poll sends the exit traffic, so WireGuard keeps initiating.
	status := func(re *regexp.Regexp) error {
		_, _ = execRead(devA, pollTimeout, "ping", "-c", "1", "-W", "1", inet4.String())
		out, err := execRead(devA, pollTimeout, "thinkpol", "status")
		if err != nil {
			return err
		}
		if !re.MatchString(out) {
			return fmt.Errorf("no %q in\n%s", re, out)
		}
		return nil
	}
	lab.Eventually(t, 90*time.Second, func() error {
		return status(regexp.MustCompile(`(?m)^health: +down: (?:.*, )?exit_no_handshake(?:,|$)`))
	})
	if err := status(regexp.MustCompile(`(?m)^health: .*(?:no_link_up|neighbor_down)`)); err == nil {
		t.Fatal("the first hop is up, but health says a neighbor is down")
	}

	s2.MustExec(t, "nft", "delete", "table", "inet", "tp195")
	lab.Eventually(t, 60*time.Second, func() error { return status(regexp.MustCompile(`(?m)^health: +ok$`)) })
	for _, p := range up {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	}
}
