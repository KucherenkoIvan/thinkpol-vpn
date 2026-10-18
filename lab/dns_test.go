//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

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

	exit := startDeviceExit(t, server, inetIP, v1)

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
		mustResolve(t, devA, "www.direct.test", true, domesticAAAA)
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
		exit = startDeviceExit(parent, server, inetIP, v1)

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
		mustResolve(t, devB, "www.direct.test", true, domesticAAAA)
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
	tunnelNamesAskedOnlyOfTheExit(t, domestic, foreign, server)
}

// TestDNSFollowsTheRulesOnAServerExit is the R4 leak check with the exit
// running as a server: its resolver sits in the worker, and its upstream
// queries leave through the worker's egress: the foreign resolver sees
// them from the exit's own address. device-a resolves tunnel-bound names
// through it and leaks nothing; the domestic resolver is never asked a
// tunnel or overlay name.
func TestDNSFollowsTheRulesOnAServerExit(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	domestic, foreign := startResolvers(t, inet)

	space, v1 := buildDNSMap(t, inet, server, devA)
	s4, _ := space.overlay(1)

	exit := startServerExit(t, server, inetIP, v1, netip.PrefixFrom(inetIP, 24).Masked())

	devA.WriteFile(t, "/etc/resolv.conf", osResolvConf(inetIP))
	capture := devA.Capture(t, "")
	up := devA.Start(t, "thinkpol", "up")
	waitLog(t, up, "the system resolves through the node")
	ping(t, devA, s4)

	mustResolve(t, devA, "www.tunnel.test", false, foreignA)
	mustResolve(t, devA, "www.tunnel.test", true, foreignAAAA)
	mustResolve(t, devA, "www.direct.test", false, domesticA)
	mustResolve(t, devA, "www.direct.test", true, domesticAAAA)
	mustResolve(t, devA, "server-1.lab.internal", false, s4.String())
	if got, err := resolve(devA, "blocked.test", false); err == nil {
		t.Errorf("a blocked name resolved to %s", got)
	}
	if err := capture.Complete(); err != nil {
		t.Fatal(err)
	}
	noLeaks(t, capture.Stop(), inetIP)
	tunnelNamesAskedOnlyOfTheExit(t, domestic, foreign, server)

	// The negative control: the same setup without the exit's egress
	// opened to the upstream's subnet. The exit's resolver serves no
	// overlay names itself (a server with egress holds none), so asked
	// directly (labdns's client mode; device-a's own resolver answers
	// such a name itself and never forwards it) it gives an
	// authoritative NXDOMAIN without asking any upstream: the tunnel and
	// the resolver both work after the restart, and the failed lookup of
	// a tunnel-bound name below can only be the worker's egress refusing
	// the upstream. A direct name still resolves (the device's own path
	// is untouched), and the foreign resolver never saw the refused name.
	if err := exit.Stop(); err != nil {
		t.Fatalf("the exit: %v\n%s", err, exit.Output())
	}
	exit = startServerExit(t, server, inetIP, v1, netip.Prefix{})
	ping(t, devA, s4)
	mustAsk(t, devA, s4, "server-1.lab.internal", "rcode NXDOMAIN authoritative")
	if got, err := resolve(devA, "www2.tunnel.test", false); err == nil {
		t.Errorf("a tunnel-bound name resolved with the worker's egress closed: %s", got)
	}
	if out := foreign.Output(); strings.Contains(out, "www2") {
		t.Errorf("the foreign resolver saw www2:\n%s", out)
	}
	mustResolve(t, devA, "www3.direct.test", false, domesticA)

	if err := up.Stop(); err != nil {
		t.Errorf("thinkpol up: %v\n%s", err, up.Output())
	}
	if err := exit.Stop(); err != nil {
		t.Errorf("the exit: %v\n%s", err, exit.Output())
	}
}
