//go:build lab

package lab_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestIngressOffAdmitsOnlyServers turns server-2's ingress off under a
// running space (lab/maps/ingress.yaml). device-b keeps its old map, so it
// still has server-2's address and a credential, and is refused; device-a
// still reaches server-2 through server-1, which server-2 admits as a
// server. No device's section of the new map has server-2's address, and a
// spec asking a device to dial server-2 with ingress off doesn't build.
func TestIngressOffAdmitsOnlyServers(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	s1, s2, devA, devB := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA), l.Node(lab.DeviceB)
	s1Addr, s2Addr := s1.IPv4(lab.NetServers).String(), s2.IPv4(lab.NetServers).String()
	space := &m0Space{builder: l.Node(lab.Internet), spec: "/src/lab/maps/ingress.yaml"}
	settings := func(ingress, deviceBDials string) {
		space.env = []string{
			"SERVER_1_IPV4=" + s1Addr, "SERVER_2_IPV4=" + s2Addr,
			"SERVER_2_INGRESS=" + ingress, "DEVICE_B_DIALS=" + deviceBDials,
		}
	}
	space.builder.MustExec(t, "sh", "-ec", `mkdir -p /tmp/m0 && cd /tmp/m0
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 server-2 device-a device-b >/dev/null`)

	settings("false", "server-2")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refused, err := space.builder.Exec(ctx, append(append([]string{"env"}, space.env...),
		"sh", "-ec", "cd /tmp/m0 && thinkpol dev map build -keys keys -out map.bin "+space.spec)...)
	if err == nil || !strings.Contains(refused.Stderr, "server-2 has ingress off, so device-b can't connect to it") {
		t.Fatalf("a spec giving device-b server-2's address with ingress off: %v\n%s%s", err, refused.Stdout, refused.Stderr)
	}

	settings("true", "server-2")
	v1, version1 := space.build(t)
	nodes := map[string]*lab.Node{"server-1": s1, "server-2": s2, "device-a": devA, "device-b": devB}
	for name, n := range nodes {
		space.install(t, n, name, v1)
	}
	up := map[string]*lab.Process{
		// server-1's worker dials server-2 out of its namespace, on the
		// lab's private network, which dials refuse unless allowed.
		"server-1": s1.Start(t, "thinkpol", "up", "-map-poll", "1s", "-egress-allowed", netip.PrefixFrom(s1.IPv4(lab.NetServers), 24).Masked().String()),
		"server-2": s2.Start(t, "thinkpol", "up", "-map-poll", "1s"),
		"device-a": devA.Start(t, "thinkpol", "up", "-map-poll", "1s"),
		"device-b": devB.Start(t, "thinkpol", "up", "-map-poll", "1s"),
	}
	waitLog(t, up["server-2"], `msg="map applied" .*version=`+version1+` .*ingress=on egress=off`)

	server2 := netip.AddrFrom4([4]byte{100, 64, 0, 2}) // overlay addresses go in spec order
	ping(t, devB, server2)                             // directly: device-b's credential works
	ping(t, devA, server2)                             // through server-1

	settings("false", "server-1")
	v2, version2 := space.build(t)
	for _, device := range []string{"device-a", "device-b"} {
		section := space.builder.MustExec(t, "sh", "-ec", "cd /tmp/m0 && thinkpol dev map inspect -keys keys -node-key keys/"+device+".key map.bin")
		if !strings.Contains(section, s1Addr) || strings.Contains(section, s2Addr) {
			t.Fatalf("%s's section: want server-1's address %s, not server-2's %s:\n%s", device, s1Addr, s2Addr, section)
		}
	}
	// device-b keeps v1: server-2's address and a credential for it.
	for _, name := range []string{"server-1", "server-2", "device-a"} {
		putMap(t, nodes[name], v2)
	}
	waitLog(t, up["server-2"], `msg="map applied" .*version=`+version2+` .*ingress=off egress=off`)
	waitLog(t, up["server-1"], applied(version2))
	waitLog(t, up["device-a"], applied(version2))

	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := devB.Exec(ctx, "ping", "-c", "1", "-W", "1", server2.String())
		cancel()
		if err == nil {
			t.Fatalf("ping %d: device-b reached server-2 with its ingress off", i)
		}
	}
	ping(t, devA, server2) // server-1 still relays to server-2

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
}
