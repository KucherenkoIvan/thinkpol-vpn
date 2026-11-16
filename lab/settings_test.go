//go:build lab

package lab_test

import (
	"regexp"
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
	up := startUp(t, server)
	waitLog(t, up, workerApplied(""))
	s4, _ := space.overlay(1)

	// overlayMTU runs `thinkpol up` on device-a, after env and with args,
	// until it is connected, reads the overlay's MTU from its status, and
	// stops it.
	overlayMTU := func(env []string, args ...string) int {
		t.Helper()
		p := dev.Start(t, upCommand(dev, env, args...)...)
		st := waitStatusFor(t, dev, 90*time.Second, nil, connection("connected"), dataPlaneUp)
		ping(t, dev, s4)
		if err := p.Stop(); err != nil {
			t.Fatalf("%v %v exited with %v:\n%s", env, args, err, p.Output())
		}
		return st.DataPlane.MTU
	}

	byDefault := overlayMTU(nil)
	dev.WriteFile(t, stateDir+"/node.json", []byte(`{"link_mtu": 1400}`+"\n"))
	dev.MustExec(t, "chmod", "600", stateDir+"/node.json")
	fromFile := overlayMTU(nil)
	fromEnv := overlayMTU([]string{"THINKPOL_LINK_MTU=1300"})
	fromFlag := overlayMTU([]string{"THINKPOL_LINK_MTU=1300"}, "-link-mtu", "1200")
	t.Logf("overlay MTU: %d by default (link MTU 1500), %d from the file (1400), %d from the environment (1300), %d from the flag (1200)",
		byDefault, fromFile, fromEnv, fromFlag)
	if byDefault-fromFile != 100 || fromFile-fromEnv != 100 || fromEnv-fromFlag != 100 {
		t.Fatalf("overlay MTU %d by default, %d from the file, %d from the environment, %d from the flag: want 100 apart each",
			byDefault, fromFile, fromEnv, fromFlag)
	}

	// A key the node doesn't know stops it with EX_CONFIG, naming it.
	dev.WriteFile(t, stateDir+"/node.json", []byte(`{"link_mut": 1400}`+"\n"))
	res, err := execResult(dev, execTimeout, upCommand(dev, nil)...)
	if err == nil || res.ExitCode != 78 || !regexp.MustCompile(`unknown key "link_mut"`).MatchString(res.Stderr) {
		t.Fatalf("an unknown key: exit %d, %v\n%s", res.ExitCode, err, res.Stderr)
	}
}
