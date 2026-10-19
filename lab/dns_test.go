//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
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
		wantNoAnswer(t, devA, "blocked.test", "a blocked name")
		wantNoAnswer(t, devA, "device-c.lab.internal.", "a name the map doesn't have")

		// With the exit down, a tunnel-bound name fails: it is never
		// retried under a search domain, nor asked of anyone else.
		if err := exit.Stop(); err != nil {
			t.Errorf("the exit: %v", err)
		}
		wantNoAnswer(t, devA, "down.tunnel.test", "a tunnel-bound name with the exit down")
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
		startResolved(t, devB, inetIP)
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
		if out, err := execRead(devB, execTimeout, "thinkpol", "status"); err != nil {
			t.Fatal(err)
		} else if strings.Contains(out, "dns_not_protected") {
			t.Fatalf("not protected before any other domain:\n%s", out)
		}
		devB.MustExec(t, "resolvectl", "domain", link, "~example.org")
		lab.Eventually(t, 30*time.Second, func() error {
			out, err := execRead(devB, pollTimeout, "thinkpol", "status")
			if err != nil {
				return err
			}
			if !strings.Contains(out, "dns_not_protected") {
				return fmt.Errorf("status:\n%s", out)
			}
			return nil
		})
		devB.MustExec(t, "resolvectl", "domain", link, "")
		lab.Eventually(t, 30*time.Second, func() error {
			out, err := execRead(devB, pollTimeout, "thinkpol", "status")
			if err != nil {
				return err
			}
			if strings.Contains(out, "dns_not_protected") {
				return fmt.Errorf("status:\n%s", out)
			}
			return nil
		})

		if err := up.Stop(); err != nil {
			t.Errorf("thinkpol up: %v\n%s", err, up.Output())
		}
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()
		// Only resolvectl's own refusal, naming the link, shows resolved
		// dropped the TUN; any other failure (docker, a timeout) shows nothing.
		if out, err := devB.Exec(ctx, "resolvectl", "dns", "thinkpol0"); err == nil {
			t.Errorf("resolved still has the TUN: %s", out.Stdout)
		} else if out.ExitCode != 1 || !strings.Contains(out.Stderr, `Failed to resolve interface "thinkpol0"`) {
			t.Errorf("resolvectl dns thinkpol0 says nothing about the TUN: %v", err)
		}
		if conf := devB.MustExec(t, "cat", "/etc/resolv.conf"); !strings.HasPrefix(conf, "nameserver 127.0.0.53\n") {
			t.Errorf("resolv.conf was touched:\n%s", conf)
		}
	})

	tunnelNamesAskedOnlyOfTheExit(t, domestic, foreign, server)
}

// TestDNSFollowsTheRulesOnAServerExit is the R4 leak check with the exit
// running as a server: its resolver asks its upstream on the internet
// node, and the foreign resolver sees the queries from the exit's own
// address. device-a resolves tunnel-bound names through it and leaks
// nothing; the domestic resolver is never asked a tunnel or overlay name.
func TestDNSFollowsTheRulesOnAServerExit(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	domestic, foreign := startResolvers(t, inet)

	space, v1 := buildDNSMap(t, inet, server, devA)
	s4, _ := space.overlay(1)

	upstreamNet := netip.PrefixFrom(inetIP, 24).Masked()
	exit := startServerExit(t, server, inetIP, v1, upstreamNet)

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
	wantNoAnswer(t, devA, "blocked.test", "a blocked name")
	if err := capture.Complete(); err != nil {
		t.Fatal(err)
	}
	noLeaks(t, capture.Stop(), inetIP)

	// The negative control: the same restart with the exit's egress
	// closed. The readiness probe asks the exit's resolver itself: a
	// server with egress holds no overlay names, so its authoritative
	// NXDOMAIN says the tunnel and the resolver are up. A fresh direct
	// name proves the device's own resolver is alive, not the tunnel.
	// Each phase resolves names never asked before: the resolvers cache
	// answers for 60 s. The positive control repeats the restart with
	// the egress allowed.
	restartExit := func(egressAllowed netip.Prefix) {
		if err := exit.Stop(); err != nil {
			t.Fatalf("the exit: %v\n%s", err, exit.Output())
		}
		exit = startServerExit(t, server, inetIP, v1, egressAllowed)
		ping(t, devA, s4)
		mustAsk(t, devA, s4, "server-1.lab.internal", "NXDOMAIN aa")
	}
	restartExit(netip.Prefix{})
	waitLog(t, exit, `worker space=\S+ .*no upstream to ask: the worker's egress refuses`)
	if refused := regexp.MustCompile(`refuses the upstream.*upstream=` + regexp.QuoteMeta(inetIP.String()) + `:5353`); !refused.MatchString(exit.Output()) {
		t.Errorf("the exit didn't report refusing %s:5353:\n%s", inetIP, exit.Output())
	}
	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
		defer cancel()
		st, err := server.Exec(ctx, "thinkpol", "status")
		if err != nil {
			return err
		}
		if !strings.Contains(st.Stdout, "dns_upstream_refused") {
			return fmt.Errorf("no dns_upstream_refused in the server's status:\n%s", st.Stdout)
		}
		return nil
	})
	wantNoAnswer(t, devA, "www2.tunnel.test", "a tunnel-bound name with the resolver's upstream refused")
	mustResolve(t, devA, "www3.direct.test", false, domesticA)
	restartExit(upstreamNet)
	mustResolve(t, devA, "www4.tunnel.test", false, foreignA)
	// The resolver's log is ordered: once the positive control's query
	// reached the foreign resolver, the absence of www2 says it never
	// saw the refused name.
	lab.Eventually(t, 30*time.Second, func() error {
		if out := foreign.Output(); !strings.Contains(out, "www4") {
			return fmt.Errorf("the foreign resolver never saw www4:\n%s", out)
		}
		return nil
	})
	if out := foreign.Output(); strings.Contains(out, "www2") {
		t.Errorf("the foreign resolver saw www2:\n%s", out)
	}
	tunnelNamesAskedOnlyOfTheExit(t, domestic, foreign, server)

	if err := up.Stop(); err != nil {
		t.Errorf("thinkpol up: %v\n%s", err, up.Output())
	}
	if err := exit.Stop(); err != nil {
		t.Errorf("the exit: %v\n%s", err, exit.Output())
	}
}
