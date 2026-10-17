//go:build lab

package lab_test

import (
	"net/netip"
	"strings"
	"testing"

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

// startServerExit starts server as a server-mode exit: its resolver runs
// in the worker and asks upstream's :5353. The lab's addresses are
// private, which the worker's egress refuses unless allowed to the
// upstream's subnet.
func startServerExit(t *testing.T, server *lab.Node, upstream netip.Addr, version string) *lab.Process {
	t.Helper()
	servers := netip.PrefixFrom(upstream, 24).Masked().String()
	exit := server.Start(t, "thinkpol", "up", "-egress-allowed", servers, "-dns-upstream", upstream.String()+":5353")
	waitLog(t, exit, `worker space=\S+ .*`+applied(version))
	return exit
}

// resolversAskedOnlyByTheExit checks the two resolvers' logs: the foreign
// one was asked the tunnel's names by the exit, the domestic one never a
// tunnel or overlay name.
func resolversAskedOnlyByTheExit(t *testing.T, domestic, foreign *lab.Process, exit *lab.Node) {
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
