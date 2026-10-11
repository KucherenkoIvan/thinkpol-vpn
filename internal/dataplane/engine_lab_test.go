//go:build linux && !android

package dataplane_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// namespace creates a network namespace for the test and returns its name.
func namespace(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	name := prefix + "-" + hex.EncodeToString(b)
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", name).CombinedOutput(); err != nil {
			t.Errorf("ip netns del: %v: %s", err, out)
		}
	})
	return name
}

func inNamespace(ns string, args ...string) ([]byte, error) {
	return exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
}

// labNode is a node of the space running in its own network namespace:
// a real TUN there, configured by netcfg, under an engine whose links are
// real udp sockets on the lab node's loopback.
type labNode struct {
	*node
	ns string
}

func (nd *labNode) start(t *testing.T, reg *transport.Registry, tr *udp.Transport, listenOn string) {
	t.Helper()
	nsPath := "/run/netns/" + nd.ns
	dev, err := tun.CreateInNamespace(nsPath, tun.DefaultName, 1420)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := netcfg.NewInNamespace(nsPath, netcfg.OwnerOverlay)
	if err != nil {
		_ = dev.Close()
		t.Fatal(err)
	}
	e, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID: nd.id, Space: testSpace, WireGuardKey: nd.key, Registry: reg, TUN: dev, Interface: cfg, Path: fastPaths,
	})
	if err != nil {
		// Still the caller's.
		_ = cfg.Close()
		_ = dev.Close()
		t.Fatal(err)
	}
	nd.engine = e
	t.Cleanup(func() { _ = e.Close() })
	if listenOn != "" {
		l, err := tr.Listen(context.Background(), transport.ListenConfig{Address: listenOn, Peers: e.Inbound("udp")})
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = e.Serve("udp", l)
		}()
		t.Cleanup(func() { _ = l.Close(); <-served })
	}
	if err := e.Apply(context.Background(), nd.section); err != nil {
		t.Fatal(err)
	}
}

func (nd *labNode) ping(t *testing.T, dst netip.Addr) {
	t.Helper()
	// The first pings wait for WireGuard's handshake.
	deadline := time.Now().Add(wait)
	for {
		out, err := inNamespace(nd.ns, "ping", "-c", "1", "-W", "1", dst.String())
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: ping %s: %v\n%s", nd.name, dst, err, out)
		}
	}
}

// Two nodes in separate namespaces ping each other over overlay IPv4 and
// IPv6, directly and through a third as relay, with the kernel's own ping:
// TUN, router, WireGuard, path layer and udp, as in M0's acceptance.
func TestNamespacesPingOverTheOverlay(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	tr := udp.New(udp.Options{})
	reg, err := transport.NewRegistry(tr)
	if err != nil {
		t.Fatal(err)
	}
	// server-1 listens on both loopbacks: device-a dials it over IPv4,
	// device-b over IPv6.
	ports := make([]netip.AddrPort, 2)
	for i, a := range []string{"127.0.0.1:0", "[::1]:0"} {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = pc.LocalAddr().(*net.UDPAddr).AddrPort()
		_ = pc.Close()
	}
	a, s, b := m0()
	s.section.Node.Listeners = []netmap.Listener{{Transport: "udp", Address: ports[0]}, {Transport: "udp", Address: ports[1]}}
	for i, dev := range []*node{a, b} {
		cred := make([]byte, udp.MinSecretSize)
		_, _ = rand.Read(cred)
		dev.section.Links = []netmap.Link{{Peer: s.id, Endpoints: []netmap.Endpoint{{Transport: "udp", Address: ports[i], Credential: cred}}}}
		s.section.Inbound[i] = netmap.InboundLink{Peer: dev.id, Transport: "udp", Credential: cred}
	}

	nodes := map[*node]*labNode{}
	for _, nd := range []*node{s, a, b} {
		nodes[nd] = &labNode{node: nd, ns: namespace(t, "tp008-"+strings.TrimPrefix(nd.name, "device-"))}
	}
	nodes[s].start(t, reg, tr, ports[0].String())
	l6, err := tr.Listen(context.Background(), transport.ListenConfig{Address: ports[1].String(), Peers: nodes[s].engine.Inbound("udp")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = nodes[s].engine.Serve("udp", l6) }()
	t.Cleanup(func() { _ = l6.Close() })
	nodes[a].start(t, reg, tr, "")
	nodes[b].start(t, reg, tr, "")

	for _, nd := range []*labNode{nodes[a], nodes[s], nodes[b]} {
		out, err := inNamespace(nd.ns, "ip", "-o", "addr", "show", "dev", tun.DefaultName)
		if err != nil || !strings.Contains(string(out), nd.v4.String()+"/16") || !strings.Contains(string(out), nd.v6.String()+"/48") {
			t.Fatalf("%s: TUN addresses: %v\n%s", nd.name, err, out)
		}
		if out, err := inNamespace(nd.ns, "ip", "-o", "link", "show", "dev", tun.DefaultName); err != nil || !strings.Contains(string(out), "mtu 1328") {
			t.Fatalf("%s: TUN link, want MTU 1328: %v\n%s", nd.name, err, out)
		}
	}

	for _, pair := range [][2]*node{{a, s}, {s, b}, {a, b}, {b, a}} {
		from := nodes[pair[0]]
		from.ping(t, pair[1].v4)
		from.ping(t, pair[1].v6)
	}
	if st := nodes[a].engine.Status(); len(st.Peers) != 2 || st.Peers[1].FirstHop != s.id {
		t.Fatalf("device-a's peers %+v, want device-b through server-1", st.Peers)
	}
	if c := nodes[s].engine.Status().Path; c.Forwarded == 0 {
		t.Fatalf("server-1 relayed nothing: %+v", c)
	}

	// Links shaped down to less than IPv6's minimum turn IPv6 off on
	// device-a, and back on when the shaping goes. Linux drops an
	// interface's IPv6 addresses below 1280; Apply puts them back.
	shaped, err := transport.Shaping{Padding: transport.Buckets(1000, 8000)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	unshaped := a.section.Links[0].Endpoints[0]
	a.section.Links[0].Endpoints[0].Shaping = shaped
	if err := nodes[a].engine.Apply(context.Background(), a.section); err != nil {
		t.Fatal(err)
	}
	if st := nodes[a].engine.Status(); st.IPv6 || st.MTU != 1000-74-18-32 {
		t.Fatalf("shaped: status %+v, want IPv4 only", st)
	}
	if out, err := inNamespace(nodes[a].ns, "ip", "-o", "addr", "show", "dev", tun.DefaultName); err != nil || strings.Contains(string(out), a.v6.String()) || !strings.Contains(string(out), a.v4.String()) {
		t.Fatalf("shaped: TUN addresses %v\n%s", err, out)
	}
	nodes[a].ping(t, b.v4)
	if out, err := inNamespace(nodes[a].ns, "ping", "-c", "1", "-W", "1", b.v6.String()); err == nil {
		t.Fatalf("IPv6 ping crossed an IPv4-only overlay:\n%s", out)
	}
	a.section.Links[0].Endpoints[0] = unshaped
	if err := nodes[a].engine.Apply(context.Background(), a.section); err != nil {
		t.Fatal(err)
	}
	if st := nodes[a].engine.Status(); !st.IPv6 || st.MTU != 1328 {
		t.Fatalf("unshaped again: status %+v", st)
	}
	nodes[a].ping(t, b.v6)
	nodes[b].ping(t, a.v6)

	// Closing an engine takes its interface with it.
	if err := nodes[b].engine.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := inNamespace(nodes[b].ns, "ip", "link", "show", "dev", tun.DefaultName); err == nil {
		t.Fatalf("device-b's TUN outlived its engine:\n%s", out)
	}
}
