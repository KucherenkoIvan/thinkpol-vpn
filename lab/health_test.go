//go:build lab

package lab_test

import (
	"fmt"
	"net/netip"
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
	l := tunnelPool.Acquire(t)
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	space := newM0Space(t, l.Node(lab.Router), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	srv := startUp(t, server)
	waitLog(t, srv, workerApplied(""))
	s4, s6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)

	noLinkUp, healthOK := health("down", "no_link_up"), health("ok")

	t.Run("the server drops every packet", func(t *testing.T) {
		server.MustExec(t, "nft", "-f", "-", "--", `table inet tp140 {
			chain input { type filter hook input priority -10; policy accept; udp dport 4500 drop; }
		}`)
		up := startUp(t, dev)
		waitStatus(t, dev, noLinkUp)
		server.MustExec(t, "nft", "delete", "table", "inet", "tp140")
		waitStatus(t, dev, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("every dial fails", func(t *testing.T) {
		dev.MustExec(t, "ip", "route", "add", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "add", "unreachable", s6.String()+"/128")
		up := startUp(t, dev)
		waitLog(t, up, `msg="dial failed"`)
		waitStatus(t, dev, noLinkUp)
		dev.MustExec(t, "ip", "route", "del", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "del", "unreachable", s6.String()+"/128")
		waitStatus(t, dev, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})
}

// TestHealthWithAnExitThatNeverHandshakes runs lab/maps/egress.yaml:
// device-a's chain ends at server-2, relayed by server-1. server-2 drops
// every WireGuard handshake initiation that reaches it while its links
// stay up, so device-a's first hop is up and its exit never answers:
// `thinkpol status` says exit_no_handshake (TP-195), not no_link_up,
// within exitNoHandshakeBound of the first hop coming up, and health is ok
// again once the exit answers.
func TestHealthWithAnExitThatNeverHandshakes(t *testing.T) {
	t.Parallel()
	l := standardPool.Acquire(t)
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
	// length, so the links stay up. A link writes V1 frames, without seq
	// and ack, until it learns that the far end reads acks
	// (docs/design/path-liveness.md, "Older nodes"): server-1's new link
	// to server-2 can carry the first initiation that way, 8 bytes
	// shorter.
	initiation := 8 + udp.Overhead + path.HeaderSize + device.MessageInitiationSize
	s2.MustExec(t, "nft", "-f", "-", "--", fmt.Sprintf(`table inet tp195 {
		chain input { type filter hook input priority -10; policy accept; udp dport 4500 udp length { %d, %d } drop; }
	}`, initiation, initiation-seqAckSize))

	nodes := map[string]*lab.Node{"server-1": s1, "server-2": s2, "device-a": devA}
	up := map[string]*lab.Process{}
	servers := netip.PrefixFrom(inet4, 24).Masked().String()
	for name, n := range nodes {
		space.install(t, n, name, envelope)
		up[name] = startUp(t, n, "-egress-allowed", servers)
	}
	waitStatus(t, devA, mapApplied(version), linkUp)
	firstHopUp := time.Now()

	// Each poll sends the exit traffic, so WireGuard keeps initiating.
	status := func(checks ...statusCheck) error {
		_, _ = execRead(devA, pollTimeout, "ping", "-c", "1", "-W", "1", inet4.String())
		st, err := readStatus(devA, pollTimeout)
		if err != nil {
			return err
		}
		return st.check(checks...)
	}
	lab.Eventually(t, exitNoHandshakeBound(), func() error { return status(health("down", "exit_no_handshake")) })
	t.Logf("exit_no_handshake %v after device-a's first hop was seen up, want within %v", time.Since(firstHopUp).Round(time.Millisecond), exitNoHandshakeBound())
	if err := status(noProblem("no_link_up"), noProblem("neighbor_down")); err != nil {
		t.Fatalf("the first hop is up: %v", err)
	}

	s2.MustExec(t, "nft", "delete", "table", "inet", "tp195")
	lab.Eventually(t, 60*time.Second, func() error { return status(health("ok")) })
	for _, p := range up {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	}
}

// seqAckSize is what a frame's seq and ack add to the path header
// (docs/design/path-liveness.md, "Acks in the frames").
const seqAckSize = 8

// exitNoHandshakeBound is how soon after its first hop comes up a device
// whose exit never answers says exit_no_handshake while it has traffic for
// the exit: the health rules' 15 s, three REKEY_TIMEOUTs, counted from the
// first initiation since the first hop's link came up (RR48; the health
// row of docs/design/api-overview.md), which comes within one more
// REKEY_TIMEOUT, all at the lab's timer scale (20 s at real time, 2 s at
// the default ÷10), plus healthSlack. Written out, not
// dataplane.ExitHandshakeDeadline, so a change to that constant fails here.
func exitNoHandshakeBound() time.Duration {
	return (device.RekeyTimeout+3*device.RekeyTimeout)/time.Duration(wgTimerScale) + healthSlack
}

// healthSlack is what the polls (a ping of up to 1 s and a status read
// each) and a loaded lab machine may add to the health rules' timers.
const healthSlack = 10 * time.Second
