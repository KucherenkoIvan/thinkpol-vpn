//go:build lab

package lab_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

const stateDir = "/var/lib/thinkpol"

// m0Space is the lab's M0 space (lab/maps/m0.yaml), made on a node outside
// it, the way the space's admin would.
type m0Space struct {
	builder *lab.Node
	env     []string
	ula     netip.Prefix
	spec    string // the map spec on the builder
	// flags are extra `dev map build` flags.
	flags []string
}

func newM0Space(t *testing.T, builder, server *lab.Node) *m0Space {
	t.Helper()
	s := &m0Space{builder: builder, spec: "/src/lab/maps/m0.yaml", env: []string{
		"SERVER_1_IPV4=" + server.IPv4(lab.NetServers).String(),
		"SERVER_1_IPV6=" + server.IPv6(lab.NetServers).String(),
	}}
	builder.MustExec(t, "sh", "-ec", `mkdir -p /tmp/m0 && cd /tmp/m0
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 device-a device-b >/dev/null`)
	m := regexp.MustCompile(`ipv6-network: "([^"]+)"`).FindStringSubmatch(builder.MustExec(t, "cat", "/tmp/m0/keys/space.key"))
	if m == nil {
		t.Fatal("no IPv6 network in space.key")
	}
	s.ula = netip.MustParsePrefix(m[1])
	return s
}

// build makes a new map version (with fresh link secrets) and returns it
// and its version.
func (s *m0Space) build(t *testing.T) ([]byte, string) {
	t.Helper()
	out := s.builder.MustExec(t, append(append([]string{"env"}, s.env...),
		"sh", "-ec", "cd /tmp/m0 && thinkpol dev map build -keys keys -out map.bin "+strings.Join(append(s.flags, s.spec), " "))...)
	v := regexp.MustCompile(`map version (\d+)`).FindStringSubmatch(out)
	if v == nil {
		t.Fatalf("build said %q", out)
	}
	return s.file(t, "map.bin"), v[1]
}

func (s *m0Space) file(t *testing.T, name string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s.builder.MustExec(t, "base64", "-w0", "/tmp/m0/"+name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// install gives a node its state directory: its own key, the space's
// trust and the map, nothing else.
func (s *m0Space) install(t *testing.T, n *lab.Node, name string, envelope []byte) {
	t.Helper()
	n.MustExec(t, "install", "-d", "-m", "700", stateDir)
	n.WriteFile(t, stateDir+"/node.key", s.file(t, "keys/"+name+".key"))
	n.WriteFile(t, stateDir+"/space.pub", s.file(t, "keys/space.pub"))
	n.MustExec(t, "chmod", "600", stateDir+"/node.key")
	putMap(t, n, envelope)
}

// putMap replaces a node's map the way a map arrives: written aside, then
// renamed over the old one.
func putMap(t *testing.T, n *lab.Node, envelope []byte) {
	t.Helper()
	n.WriteFile(t, "/tmp/map.new", envelope)
	n.MustExec(t, "sh", "-ec", `cp /tmp/map.new `+stateDir+`/.map.new && mv -f `+stateDir+`/.map.new `+stateDir+`/map.bin`)
}

func (s *m0Space) overlay(n byte) (netip.Addr, netip.Addr) {
	v6 := s.ula.Addr().As16()
	v6[15] = n
	return netip.AddrFrom4([4]byte{100, 64, 0, n}), netip.AddrFrom16(v6)
}

func ping(t *testing.T, from *lab.Node, to netip.Addr) {
	t.Helper()
	lab.Eventually(t, 60*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := from.Exec(ctx, "ping", "-c", "1", "-W", "1", to.String())
		return err
	})
}

func waitLog(t *testing.T, p *lab.Process, pattern string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	lab.Eventually(t, 60*time.Second, func() error {
		if !re.MatchString(p.Output()) {
			return fmt.Errorf("no %q in the log yet", pattern)
		}
		return nil
	})
}

// applied matches the log line of a node, or its worker, applying a map.
func applied(version string) string { return `msg="map applied" .*version=` + version + ` ` }

// routeTableRoutes is everything in the routing tables of the route
// table's protocol (86), both families.
func routeTableRoutes(t *testing.T, n *lab.Node) string {
	t.Helper()
	var out strings.Builder
	for _, family := range []string{"-4", "-6"} {
		out.WriteString(n.MustExec(t, "ip", family, "route", "show", "table", "all", "proto", "86"))
	}
	return out.String()
}

// hasGuard says whether the IPv6 leak guard's nftables table is there and
// holds its chain: its name in `nft list tables`, and a chain listed in
// the table itself (the name alone proves nothing).
func hasGuard(t *testing.T, n *lab.Node) bool {
	t.Helper()
	if !strings.Contains(n.MustExec(t, "nft", "list", "tables"), "thinkpol-guard") {
		return false
	}
	return strings.Contains(n.MustExec(t, "nft", "list", "table", "inet", "thinkpol-guard"), "chain")
}

// TestUpRunsTheM0Space brings the M0 space up with `thinkpol up` on every
// node (server-1 as a supervisor with a sandboxed worker, the devices in
// device mode), pings across it, moves it to a new map by file change and
// by SIGHUP, and stops it, leaving nothing behind.
func TestUpRunsTheM0Space(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, devB := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, v1 := space.build(t)
	nodes := map[string]*lab.Node{"server-1": server, "device-a": devA, "device-b": devB}
	resolvConf := map[string]string{}
	for name, n := range nodes {
		space.install(t, n, name, envelope)
		resolvConf[name] = n.MustExec(t, "cat", "/etc/resolv.conf")
		n.MustExec(t, "touch", "/tmp/before-up")
	}

	up := map[string]*lab.Process{
		"server-1": server.Start(t, "thinkpol", "up", "-map-poll", "1s"),
		"device-a": devA.Start(t, "thinkpol", "up", "-map-poll", "1s"),
		// device-b takes new maps on SIGHUP only.
		"device-b": devB.Start(t, "thinkpol", "up", "-map-poll", "1h"),
	}
	waitLog(t, up["server-1"], "mode=server")
	waitLog(t, up["device-a"], "mode=device")
	waitLog(t, up["server-1"], `worker space=\S+ .*`+applied(v1))

	s4, s6 := space.overlay(1)
	a4, a6 := space.overlay(2)
	b4, b6 := space.overlay(3)
	pingAll := func(t *testing.T) {
		t.Helper()
		ping(t, devA, s4) // the server, in its worker's namespace
		ping(t, devA, s6)
		ping(t, devA, b4) // device to device, relayed by the server
		ping(t, devA, b6)
		ping(t, devB, a4)
		ping(t, devB, a6)
		ping(t, devB, s4)
	}
	pingAll(t)
	for _, p := range up {
		waitLog(t, p, applied(v1))
	}
	// What a stop must take away is there while it runs.
	devA.MustExec(t, "ip", "link", "show", "thinkpol0")
	server.MustExec(t, "ip", "link", "show", "tp-space0")
	server.MustExec(t, "nft", "list", "table", "inet", "thinkpol-supervisor")
	server.MustExec(t, "pgrep", "-f", "thinkpol worker")

	// A new map: the server and device-a notice the file, device-b is told.
	envelope, v2 := space.build(t)
	for _, n := range nodes {
		putMap(t, n, envelope)
	}
	devB.MustExec(t, "pkill", "-HUP", "-f", "thinkpol up")
	for _, p := range up {
		waitLog(t, p, applied(v2))
	}
	waitLog(t, up["server-1"], `worker space=\S+ .*`+applied(v2))
	waitLog(t, up["device-b"], "reload requested")
	pingAll(t)

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
	for name, n := range nodes {
		t.Run("left behind on "+name, func(t *testing.T) {
			if out := n.MustExec(t, "ip", "-o", "link", "show"); strings.Contains(out, "thinkpol0") || strings.Contains(out, "tp-space") {
				t.Errorf("links left:\n%s", out)
			}
			for _, proto := range []string{"84", "85", "86"} {
				for _, family := range []string{"-4", "-6"} {
					if out := n.MustExec(t, "ip", family, "route", "show", "table", "all", "proto", proto); out != "" {
						t.Errorf("routes of proto %s left:\n%s", proto, out)
					}
				}
			}
			for _, family := range []string{"-4", "-6"} {
				for _, line := range strings.Split(strings.TrimSpace(n.MustExec(t, "ip", family, "rule")), "\n") {
					if prio, _, _ := strings.Cut(line, ":"); prio != "0" && prio != "32766" && prio != "32767" {
						t.Errorf("rule left: %s", line)
					}
				}
			}
			if out := n.MustExec(t, "nft", "list", "tables"); strings.Contains(out, "thinkpol") {
				t.Errorf("nftables tables left:\n%s", out)
			}
			if out := n.MustExec(t, "sh", "-c", "pgrep -af 'thinkpol (up|worker)' || true"); out != "" {
				t.Errorf("processes left:\n%s", out)
			}
			if out := n.MustExec(t, "ip", "netns", "list"); out != "" {
				t.Errorf("namespaces left:\n%s", out)
			}
			if out := n.MustExec(t, "ls", "-A", stateDir); out != "map.bin\nnode.key\nspace.pub\n" {
				t.Errorf("the state directory holds:\n%s", out)
			}
			// A device's OS resolved through the node while it ran, and
			// resolves as before once it stopped.
			if conf := n.MustExec(t, "cat", "/etc/resolv.conf"); conf != resolvConf[name] {
				t.Errorf("resolv.conf not restored:\n%s", conf)
			}
			// Nothing else on disk either: no logs, no pid or lock files
			// (the test's own map replacements aside).
			out := n.MustExec(t, "sh", "-c", `find / -xdev -newer /tmp/before-up \( -type f -o -type s -o -type p \) `+
				`-not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*' -not -path '/tmp/*' `+
				`-not -path '`+stateDir+`/map.bin' -not -path /etc/resolv.conf -print`)
			if out != "" {
				t.Errorf("files written while it ran:\n%s", out)
			}
		})
	}
}
