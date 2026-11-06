//go:build lab

package lab_test

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestTheNodeFileSetsUp starts device-a with its settings in the node
// file alone, then with the same key in the environment, then as a flag
// too: each source wins over the next (docs/design/configuration.md
// "Precedence and narrowing"), and `thinkpol status` shows the result.
// The key is link_mtu, which the overlay's MTU follows one for one.
func TestTheNodeFileSetsUp(t *testing.T) {
	t.Parallel()
	topo := lab.Topology{
		Networks: []lab.Network{{Name: lab.NetDevices}, {Name: lab.NetServers}},
		Nodes: []lab.NodeSpec{
			{Name: lab.Router, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
			{Name: lab.DeviceA, Networks: []string{lab.NetDevices}, Gateway: lab.Router},
			{Name: lab.Server1, Networks: []string{lab.NetServers}, Gateway: lab.Router, Forward: true},
			{Name: lab.Internet, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		},
	}
	l := lab.Start(t, topo)
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	up := server.Start(t, "thinkpol", "up")
	waitLog(t, up, `worker space=\S+ .*msg="map applied"`)
	s4, _ := space.overlay(1)

	mtuLine := regexp.MustCompile(`overlay: +mtu (\d+),`)
	// overlayMTU runs `thinkpol up` with args on device-a until it is
	// connected, reads the overlay's MTU from `thinkpol status`, and stops
	// it.
	overlayMTU := func(args ...string) int {
		t.Helper()
		p := dev.Start(t, args...)
		var mtu int
		lab.Eventually(t, 90*time.Second, func() error {
			out, err := execRead(dev, pollTimeout, "thinkpol", "status")
			if err != nil {
				return err
			}
			m := mtuLine.FindStringSubmatch(out)
			if m == nil || !regexp.MustCompile(`state: +connected\n`).MatchString(out) {
				return fmt.Errorf("not connected yet:\n%s", out)
			}
			mtu, err = strconv.Atoi(m[1])
			return err
		})
		ping(t, dev, s4)
		if err := p.Stop(); err != nil {
			t.Fatalf("%v exited with %v:\n%s", args, err, p.Output())
		}
		return mtu
	}

	byDefault := overlayMTU("thinkpol", "up")
	dev.WriteFile(t, stateDir+"/node.json", []byte(`{"link_mtu": 1400}`+"\n"))
	dev.MustExec(t, "chmod", "600", stateDir+"/node.json")
	fromFile := overlayMTU("thinkpol", "up")
	fromEnv := overlayMTU("env", "THINKPOL_LINK_MTU=1300", "thinkpol", "up")
	fromFlag := overlayMTU("env", "THINKPOL_LINK_MTU=1300", "thinkpol", "up", "-link-mtu", "1200")
	t.Logf("overlay MTU: %d by default (link MTU 1500), %d from the file (1400), %d from the environment (1300), %d from the flag (1200)",
		byDefault, fromFile, fromEnv, fromFlag)
	if byDefault-fromFile != 100 || fromFile-fromEnv != 100 || fromEnv-fromFlag != 100 {
		t.Fatalf("overlay MTU %d by default, %d from the file, %d from the environment, %d from the flag: want 100 apart each",
			byDefault, fromFile, fromEnv, fromFlag)
	}

	// A key the node doesn't know stops it with EX_CONFIG, naming it.
	dev.WriteFile(t, stateDir+"/node.json", []byte(`{"link_mut": 1400}`+"\n"))
	res, err := execResult(dev, execTimeout, "thinkpol", "up")
	if err == nil || res.ExitCode != 78 || !regexp.MustCompile(`unknown key "link_mut"`).MatchString(res.Stderr) {
		t.Fatalf("an unknown key: exit %d, %v\n%s", res.ExitCode, err, res.Stderr)
	}
}
