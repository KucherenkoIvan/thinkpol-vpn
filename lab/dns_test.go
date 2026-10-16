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
	domestic, foreign := startResolvers(t, inet)

	space, v1 := buildDNSMap(t, inet, server, devA, devB)
	s4, _ := space.overlay(1)
	a4, _ := space.overlay(2)
	b4, b6 := space.overlay(3)

	// The exit runs its data plane in device mode: its resolver's own
	// queries leave from the node itself, without a worker's egress (the
	// server-mode case is TestDNSFollowsTheRulesOnAServerExit).
	exit := server.Start(t, "thinkpol", "up", "-mode", "device", "-dns-upstream", inetIP.String()+":5353")
	waitLog(t, exit, applied(v1))

	parent := t // the exit outlives the subtests
	t.Run("resolv.conf", func(t *testing.T) {
		// The OS's own search domain is one the rules send direct: a name
		// that fails must never be retried under it.
		original := string(osResolvConf(inetIP))
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
	resolversAskedOnlyByTheExit(t, domestic, foreign, server)
}

// TestDNSFollowsTheRulesOnAServerExit is the R4 leak check with the exit
// running as a server: its resolver sits in the worker, and its upstream
// queries leave through the worker's egress: the foreign resolver sees
// them from the exit's own address. device-a resolves tunnel-bound names
// through it and leaks nothing; the domestic resolver is never asked a
// tunnel or overlay name. The negative control: without the worker's
// egress opened to the upstream's subnet, the same setup fails to resolve
// a tunnel-bound name.
func TestDNSFollowsTheRulesOnAServerExit(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	domestic, foreign := startResolvers(t, inet)

	space, v1 := buildDNSMap(t, inet, server, devA)
	s4, _ := space.overlay(1)

	// No -mode device: the exit is a server, its resolver runs in the
	// worker and asks the upstream from the worker's namespace.
	exit := startServerExit(t, server, inetIP, v1)

	devA.WriteFile(t, "/etc/resolv.conf", osResolvConf(inetIP))
	capture := devA.Capture(t, "")
	up := devA.Start(t, "thinkpol", "up")
	waitLog(t, up, "the system resolves through the node")
	ping(t, devA, s4)

	mustResolve(t, devA, "www.tunnel.test", false, foreignA)
	mustResolve(t, devA, "www.tunnel.test", true, foreignAAAA)
	mustResolve(t, devA, "www.direct.test", false, domesticA)
	mustResolve(t, devA, "server-1.lab.internal", false, s4.String())
	if got, err := resolve(devA, "blocked.test", false); err == nil {
		t.Errorf("a blocked name resolved to %s", got)
	}
	if err := capture.Complete(); err != nil {
		t.Fatal(err)
	}
	noLeaks(t, capture.Stop(), inetIP)
	resolversAskedOnlyByTheExit(t, domestic, foreign, server)

	// The negative control: the same setup without the exit's egress
	// opened to the upstream's subnet. The worker's own queries are
	// refused, so a tunnel-bound name doesn't resolve, while a direct
	// name still does (the device's own path is untouched).
	if err := exit.Stop(); err != nil {
		t.Fatalf("the exit: %v\n%s", err, exit.Output())
	}
	exit = server.Start(t, "thinkpol", "up", "-dns-upstream", inetIP.String()+":5353")
	waitLog(t, exit, `worker space=\S+ .*`+applied(v1))
	if got, err := resolve(devA, "www2.tunnel.test", false); err == nil {
		t.Errorf("a tunnel-bound name resolved with the worker's egress closed: %s", got)
	}
	mustResolve(t, devA, "www.direct.test", false, domesticA)

	if err := up.Stop(); err != nil {
		t.Errorf("thinkpol up: %v\n%s", err, up.Output())
	}
	if err := exit.Stop(); err != nil {
		t.Errorf("the exit: %v\n%s", err, exit.Output())
	}
}
