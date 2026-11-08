//go:build lab

package lab_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestHealthWithNoLinkUp: a device whose only server never answers says so
// in `thinkpol status` (TP-140), whether the server drops every packet or
// every dial fails (no route to it), and health is ok again once the link
// comes up.
func TestHealthWithNoLinkUp(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	srv := server.Start(t, "thinkpol", "up", "-mode", "server")
	waitLog(t, srv, `worker space=\S+ .*msg="map applied"`)
	s4, s6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)

	noLinkUp := regexp.MustCompile(`(?m)^health: +down: .*no_link_up`)
	healthOK := regexp.MustCompile(`(?m)^health: +ok$`)
	status := func() (string, error) { return execRead(dev, pollTimeout, "thinkpol", "status") }
	waitStatus := func(t *testing.T, re *regexp.Regexp) {
		t.Helper()
		lab.Eventually(t, 60*time.Second, func() error {
			out, err := status()
			if err != nil {
				return err
			}
			if !re.MatchString(out) {
				return fmt.Errorf("no %q in\n%s", re, out)
			}
			return nil
		})
	}

	t.Run("the server drops every packet", func(t *testing.T) {
		server.MustExec(t, "nft", "-f", "-", "--", `table inet tp140 {
			chain input { type filter hook input priority -10; policy accept; udp dport 4500 drop; }
		}`)
		up := dev.Start(t, "thinkpol", "up")
		waitLog(t, up, "mode=device")
		waitStatus(t, noLinkUp)
		server.MustExec(t, "nft", "delete", "table", "inet", "tp140")
		waitStatus(t, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("every dial fails", func(t *testing.T) {
		dev.MustExec(t, "ip", "route", "add", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "add", "unreachable", s6.String()+"/128")
		up := dev.Start(t, "thinkpol", "up")
		waitLog(t, up, `msg="dial failed"`)
		waitStatus(t, noLinkUp)
		dev.MustExec(t, "ip", "route", "del", "unreachable", s4.String()+"/32")
		dev.MustExec(t, "ip", "-6", "route", "del", "unreachable", s6.String()+"/128")
		waitStatus(t, healthOK)
		if err := up.Stop(); err != nil {
			t.Fatal(err)
		}
	})
}
