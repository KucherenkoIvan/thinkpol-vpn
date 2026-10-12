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
	domesticA   = "198.51.100.53"
	foreignA    = "203.0.113.53"
	foreignAAAA = "2001:db8:f::53"
)

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
		if other := p.Dst; p.Outgoing && other != domestic || !p.Outgoing && p.Src != domestic {
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

// TestDNSFollowsTheRules runs the DNS lab map (lab/maps/dns.yaml) with two
// resolvers out in the world on the internet node: the devices' domestic
// one (the "ISP's"), and the exit's upstream. device-a's OS resolves
// through /etc/resolv.conf, device-b's through systemd-resolved; server-1
// is the chain's exit. Overlay names resolve, direct names are asked of
// the domestic resolver, every other name leaves through the exit only,
// and stopping puts the OS's configuration back, after a crash too.
func TestDNSFollowsTheRules(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, devB, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	domestic := inet.Start(t, "labdns", "-listen", ":53", "-a", domesticA, "-aaaa", "2001:db8:d::53")
	foreign := inet.Start(t, "labdns", "-listen", ":5353", "-a", foreignA, "-aaaa", foreignAAAA)
	waitLog(t, domestic, "listening on :53/udp")
	waitLog(t, foreign, "listening on :5353/udp")

	space := newM0Space(t, inet, server)
	space.spec = "/src/lab/maps/dns.yaml"
	envelope, v1 := space.build(t)
	for name, n := range map[string]*lab.Node{"server-1": server, "device-a": devA, "device-b": devB} {
		space.install(t, n, name, envelope)
	}
	s4, _ := space.overlay(1)
	a4, _ := space.overlay(2)
	b4, b6 := space.overlay(3)

	// The exit runs its data plane in device mode: its resolver's own
	// queries leave from the node itself (a worker's need TP-014's egress).
	exit := server.Start(t, "thinkpol", "up", "-mode", "device", "-dns-upstream", inetIP.String()+":5353")
	waitLog(t, exit, applied(v1))

	parent := t // the exit outlives the subtests
	t.Run("resolv.conf", func(t *testing.T) {
		// The OS's own search domain is one the rules send direct: a name
		// that fails must never be retried under it.
		original := "nameserver " + inetIP.String() + "\nsearch direct.test\noptions timeout:2 attempts:3\n"
		devA.WriteFile(t, "/etc/resolv.conf", []byte(original))
		capture := devA.Capture(t, "")
		up := devA.Start(t, "thinkpol", "up")
		waitLog(t, up, "the system resolves through the node")
		ping(t, devA, s4)
		conf := devA.MustExec(t, "cat", "/etc/resolv.conf")
		if !strings.Contains(conf, "nameserver "+a4.String()+"\n") || !strings.Contains(conf, "\nsearch lab.internal\n") {
			t.Errorf("resolv.conf while connected:\n%s", conf)
		}

		mustResolve(t, devA, "device-b.lab.internal", false, b4.String())
		mustResolve(t, devA, "device-b.lab.internal", true, b6.String())
		mustResolve(t, devA, "server-1.lab.internal", false, s4.String())
		mustResolve(t, devA, "www.direct.test", false, domesticA)
		mustResolve(t, devA, "www.tunnel.test", false, foreignA)
		mustResolve(t, devA, "www.tunnel.test", true, foreignAAAA)
		if got, err := resolve(devA, "blocked.test", false); err == nil {
			t.Errorf("a blocked name resolved to %s", got)
		}
		if got, err := resolve(devA, "device-c.lab.internal.", false); err == nil {
			t.Errorf("a name the map doesn't have resolved to %s", got)
		}

		// With the exit down, a tunnel-bound name fails: it is never
		// retried under a search domain, nor asked of anyone else.
		if err := exit.Stop(); err != nil {
			t.Errorf("the exit: %v", err)
		}
		if got, err := resolve(devA, "down.tunnel.test", false); err == nil {
			t.Errorf("a tunnel-bound name resolved with the exit down: %s", got)
		}
		exit = server.Start(parent, "thinkpol", "up", "-mode", "device", "-dns-upstream", inetIP.String()+":5353")
		waitLog(t, exit, applied(v1))

		if err := capture.Complete(); err != nil {
			t.Fatal(err)
		}
		noLeaks(t, capture.Stop(), inetIP)

		// A crash leaves the managed file, the original inside it; the
		// next run starts from it, and stopping puts the original back.
		devA.MustExec(t, "pkill", "-KILL", "-f", "thinkpol up")
		<-up.Done()
		if conf := devA.MustExec(t, "cat", "/etc/resolv.conf"); conf == original {
			t.Fatal("the crash test proves nothing: resolv.conf was restored")
		}
		up = devA.Start(t, "thinkpol", "up")
		waitLog(t, up, "the system resolves through the node")
		mustResolve(t, devA, "www.tunnel.test", false, foreignA)
		if err := up.Stop(); err != nil {
			t.Errorf("thinkpol up: %v\n%s", err, up.Output())
		}
		if conf := devA.MustExec(t, "cat", "/etc/resolv.conf"); conf != original {
			t.Errorf("resolv.conf after stopping:\n%s\nwant\n%s", conf, original)
		}
	})

	t.Run("systemd-resolved", func(t *testing.T) {
		link := devB.Interface(lab.NetDevices)
		devB.WriteFile(t, "/etc/resolv.conf", []byte("nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n"))
		devB.MustExec(t, "sh", "-ec", "mkdir -p /run/dbus && dbus-daemon --system --fork")
		devB.Start(t, "/lib/systemd/systemd-resolved")
		lab.Eventually(t, 20*time.Second, func() error {
			_, err := devB.Exec(context.Background(), "resolvectl", "dns", link, inetIP.String())
			return err
		})
		mustResolve(t, devB, "before.direct.test", false, domesticA)

		capture := devB.Capture(t, "")
		up := devB.Start(t, "thinkpol", "up")
		waitLog(t, up, "the system resolves through the node")
		ping(t, devB, s4)
		if out := devB.MustExec(t, "resolvectl", "domain", "thinkpol0"); !strings.Contains(out, "~.") || !strings.Contains(out, "lab.internal") {
			t.Errorf("resolved's domains for the TUN: %s", out)
		}
		mustResolve(t, devB, "device-a.lab.internal", false, a4.String())
		mustResolve(t, devB, "www.direct.test", false, domesticA)
		mustResolve(t, devB, "www2.tunnel.test", false, foreignA)
		if err := capture.Complete(); err != nil {
			t.Fatal(err)
		}
		noLeaks(t, capture.Stop(), inetIP)

		// A domain on the physical link takes its names past the TUN: the
		// device says DNS isn't protected, and says so no longer once it
		// goes.
		health := func() string { return devB.MustExec(t, "thinkpol", "status") }
		if out := health(); strings.Contains(out, "dns_not_protected") {
			t.Fatalf("not protected before any other domain:\n%s", out)
		}
		devB.MustExec(t, "resolvectl", "domain", link, "~example.org")
		lab.Eventually(t, 20*time.Second, func() error {
			if out := health(); !strings.Contains(out, "dns_not_protected") {
				return fmt.Errorf("status:\n%s", out)
			}
			return nil
		})
		devB.MustExec(t, "resolvectl", "domain", link, "")
		lab.Eventually(t, 20*time.Second, func() error {
			if out := health(); strings.Contains(out, "dns_not_protected") {
				return fmt.Errorf("status:\n%s", out)
			}
			return nil
		})

		if err := up.Stop(); err != nil {
			t.Errorf("thinkpol up: %v\n%s", err, up.Output())
		}
		if out, err := devB.Exec(context.Background(), "resolvectl", "dns", "thinkpol0"); err == nil {
			t.Errorf("resolved still has the TUN: %s", out.Stdout)
		}
		if conf := devB.MustExec(t, "cat", "/etc/resolv.conf"); !strings.HasPrefix(conf, "nameserver 127.0.0.53\n") {
			t.Errorf("resolv.conf was touched:\n%s", conf)
		}
	})

	// The exit's upstream was asked the tunnel's names, by the exit; the
	// domestic resolver never was, nor about the overlay.
	if out := foreign.Output(); !strings.Contains(out, "query www.tunnel.test. A from "+server.IPv4(lab.NetServers).String()) {
		t.Errorf("the exit's upstream wasn't asked for the tunnel's names by the exit:\n%s", out)
	}
	for _, line := range strings.Split(domestic.Output(), "\n") {
		if strings.Contains(line, "tunnel") || strings.Contains(line, "internal") || strings.Contains(line, "blocked") {
			t.Errorf("the domestic resolver was asked: %s", line)
		}
	}
}
