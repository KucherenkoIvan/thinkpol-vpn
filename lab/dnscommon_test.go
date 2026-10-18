//go:build lab

package lab_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Answers of the two resolvers out in the world: an answer says which one
// it came from.
const (
	domesticA    = "198.51.100.53"
	domesticAAAA = "2001:db8:d::53"
	foreignA     = "203.0.113.53"
	foreignAAAA  = "2001:db8:f::53"
)

// startResolvers starts the two resolvers out in the world on the internet
// node: the devices' domestic one on :53, the exit's upstream on :5353.
func startResolvers(t *testing.T, inet *lab.Node) (domestic, foreign *lab.Process) {
	t.Helper()
	domestic = inet.Start(t, "labdns", "-listen", ":53", "-a", domesticA, "-aaaa", domesticAAAA)
	foreign = inet.Start(t, "labdns", "-listen", ":5353", "-a", foreignA, "-aaaa", foreignAAAA)
	waitLog(t, domestic, "listening on :53/udp")
	waitLog(t, foreign, "listening on :5353/udp")
	return domestic, foreign
}

// buildDNSMap builds the DNS space's map (lab/maps/dns.yaml) and installs
// it on server and the given devices; it returns the space and the map's
// version.
func buildDNSMap(t *testing.T, builder, server *lab.Node, devices ...*lab.Node) (*m0Space, string) {
	t.Helper()
	space := newM0Space(t, builder, server)
	space.spec = "/src/lab/maps/dns.yaml"
	envelope, v1 := space.build(t)
	for _, n := range append([]*lab.Node{server}, devices...) {
		space.install(t, n, n.Name, envelope)
	}
	return space, v1
}

// osResolvConf is a device's original /etc/resolv.conf for the DNS tests:
// the domestic resolver, with a search domain the rules send direct.
func osResolvConf(resolver netip.Addr) []byte {
	return []byte("nameserver " + resolver.String() + "\nsearch direct.test\noptions timeout:2 attempts:3\n")
}

// startDeviceExit starts server as a device-mode exit: its resolver's
// own queries leave from the node itself, without a worker's egress (the
// server-mode case is startServerExit).
func startDeviceExit(t *testing.T, server *lab.Node, upstream netip.Addr, version string) *lab.Process {
	t.Helper()
	exit := server.Start(t, "thinkpol", "up", "-mode", "device", "-dns-upstream", upstream.String()+":5353")
	waitLog(t, exit, applied(version))
	return exit
}

// startServerExit starts server as a server-mode exit: its resolver runs
// in the worker and asks upstream's :5353. The lab's addresses are
// private, which the worker's egress refuses unless egress allows it to
// the upstream's subnet (zero allows nothing).
func startServerExit(t *testing.T, server *lab.Node, upstream netip.Addr, version string, egress netip.Prefix) *lab.Process {
	t.Helper()
	args := []string{"thinkpol", "up", "-dns-upstream", upstream.String() + ":5353"}
	if egress.IsValid() {
		args = append(args, "-egress-allowed", egress.String())
	}
	exit := server.Start(t, args...)
	waitLog(t, exit, `worker space=\S+ .*`+applied(version))
	return exit
}

// tunnelNamesAskedOnlyOfTheExit checks the two resolvers' logs: the
// foreign one was asked the tunnel's names by the exit, the domestic one
// never a tunnel or overlay name.
func tunnelNamesAskedOnlyOfTheExit(t *testing.T, domestic, foreign *lab.Process, exit *lab.Node) {
	t.Helper()
	if out := foreign.Output(); !strings.Contains(out, "query www.tunnel.test. A from "+exit.IPv4(lab.NetServers).String()) {
		t.Errorf("the exit's upstream wasn't asked for the tunnel's names by the exit:\n%s", out)
	}
	for _, line := range strings.Split(domestic.Output(), "\n") {
		if strings.Contains(line, "tunnel") || strings.Contains(line, "internal") || strings.Contains(line, "blocked") {
			t.Errorf("the domestic resolver was asked: %s", line)
		}
	}
}

// resolve asks the node's OS resolver (glibc, through /etc/resolv.conf)
// for a name's address of one family.
func resolve(n *lab.Node, name string, v6 bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db := "ahostsv4"
	if v6 {
		db = "ahostsv6"
	}
	res, err := n.Exec(ctx, "getent", db, name)
	if err != nil {
		return "", err
	}
	f := strings.Fields(res.Stdout)
	if len(f) == 0 {
		return "", fmt.Errorf("getent %s %s: nothing", db, name)
	}
	return f[0], nil
}

// mustResolve resolves through the node's OS resolver until the name
// answers with want (a new or changed answer can take a poll to appear).
func mustResolve(t *testing.T, n *lab.Node, name string, v6 bool, want string) {
	t.Helper()
	lab.Eventually(t, 30*time.Second, func() error {
		got, err := resolve(n, name, v6)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s resolves to %s, want %s", name, got, want)
		}
		return nil
	})
}

// mustAsk asks name of a resolver at server's :53 directly (labdns's
// client mode, so the node's own resolver and its cache stay out of it)
// until the answer is want: an A record's address, or "rcode <name>
// authoritative" for an answer the resolver gave itself.
func mustAsk(t *testing.T, n *lab.Node, server netip.Addr, name, want string) {
	t.Helper()
	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := n.Exec(ctx, "labdns", "-server", server.String()+":53", "-query", name)
		got := strings.TrimSpace(res.Stdout)
		if got == want {
			return nil
		}
		if err != nil && got == "" {
			return fmt.Errorf("labdns -query %s: %v\n%s%s", name, err, res.Stdout, res.Stderr)
		}
		return fmt.Errorf("%s asked of %s answered %q, want %q", name, server, got, want)
	})
}

// noLeaks checks what a device's physical side carried: DNS only to and
// from the domestic resolver, only for names the rules send direct, and no
// tunnel-bound or overlay name in the clear in any packet.
func noLeaks(t *testing.T, packets []lab.Packet, domestic netip.Addr) {
	t.Helper()
	direct := 0
	for _, p := range packets {
		if p.Network != lab.NetDevices {
			continue // the TUN: inside the tunnel
		}
		for _, secret := range []string{"tunnel", "internal", "blocked"} {
			if bytes.Contains(p.Payload, []byte(secret)) {
				t.Errorf("a %q name in the clear: %v:%d → %v:%d", secret, p.Src, p.SrcPort, p.Dst, p.DstPort)
			}
		}
		if p.SrcPort != 53 && p.DstPort != 53 && p.SrcPort != 5353 && p.DstPort != 5353 {
			continue
		}
		if p.Outgoing && p.Dst != domestic || !p.Outgoing && p.Src != domestic {
			t.Errorf("DNS with someone but the domestic resolver: %v:%d → %v:%d", p.Src, p.SrcPort, p.Dst, p.DstPort)
		}
		if p.Outgoing && bytes.Contains(p.Payload, []byte("direct")) {
			direct++
		}
	}
	if direct == 0 {
		t.Error("no direct name was asked of the domestic resolver: the capture proves nothing")
	}
}
