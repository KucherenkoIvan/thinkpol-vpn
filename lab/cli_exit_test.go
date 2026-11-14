//go:build lab

package lab_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestTheCLIExitsBySysexits drives the CLI on a real device for the exit
// codes scripts branch on (docs/design/api-overview.md, "Verdicts"):
// `connect` that comes up without DNS protection exits 1, prints the
// status and names dns_not_protected on stderr, and the tunnel stays up;
// mallory, outside the local API's group, gets 77; with the agent
// stopped, 69.
func TestTheCLIExitsBySysexits(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devB, inet := l.Node(lab.Server1), l.Node(lab.DeviceB), l.Node(lab.Internet)
	space := newM0Space(t, inet, server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, devB, "device-b", envelope)
	devB.MustExec(t, "groupadd", "-g", apiGID, "thinkpol")
	waitLog(t, server.Start(t, upFor("server-1")...), `worker space=\S+ .*msg="map applied"`)

	// device-b resolves through systemd-resolved, with a domain on its
	// physical link: names under it go past the TUN, so its DNS is not
	// protected once it connects.
	startResolved(t, devB, inet.IPv4(lab.NetServers))
	devB.MustExec(t, "resolvectl", "domain", devB.Interface(lab.NetDevices), "~example.org")
	up := devB.Start(t, "thinkpol", "up", "-connect=false")
	waitLog(t, up, "mode=device")
	waitLog(t, up, `local API listening`)
	s4, _ := space.overlay(1)

	res, err := cli(t, devB, as("", "", "connect"))
	if err == nil || res.ExitCode != 1 || !regexp.MustCompile(`state: +connected`).MatchString(res.Stdout) || !strings.Contains(res.Stderr, "[dns_not_protected]") {
		t.Fatalf("connect without DNS protection: %v (exit %d)\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr)
	}
	ping(t, devB, s4) // the tunnel stays up

	for _, cmd := range [][]string{{"status"}, {"connect"}, {"disconnect"}, {"kill-switch"}, {"kill-switch", "on"}, {"connect-on-boot", "on"}} {
		res, err := cli(t, devB, as(malloryUID, "", cmd...))
		if err == nil || res.ExitCode != 77 || !strings.Contains(res.Stderr, "[permission_denied]") || res.Stdout != "" {
			t.Errorf("mallory %v: %v (exit %d)\n%s%s", cmd, err, res.ExitCode, res.Stdout, res.Stderr)
		}
	}
	ping(t, devB, s4) // mallory changed nothing

	if err := up.Stop(); err != nil {
		t.Errorf("thinkpol up: %v\n%s", err, up.Output())
	}
	res, err = cli(t, devB, as("", "", "status"))
	if err == nil || res.ExitCode != 69 || !strings.Contains(res.Stderr, "[service_down]") {
		t.Errorf("status with the agent stopped: %v (exit %d)\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr)
	}
}
