//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

const rowReality = "reality"

// realityRow is the matrix's reality row: server-1 serves reality through
// its shared listener (`thinkpol up -mode server`), its target the lab's
// camouflage site, from lab/maps/reality.yaml; device-a dials it. Its
// cells run in lab.Upstream. The device comes up in the cell's probe (or
// hold), after censord, so the censor reads its TLS connection from the
// first byte.
var realityRow = transport{
	name: rowReality, setup: setupReality, probe: probeReality, sawFlows: sawReality,
	upstream: true, hold: holdReality,
}

// realityLabs are the reality cells' device-a processes, started once per
// lab by whichever of hold and probe runs first.
var realityLabs sync.Map // *lab.Lab → *realityDevice

type realityDevice struct {
	once sync.Once
	err  error
}

func setupReality(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	camouflage := lab.StartCamouflage(t, l)
	space := newM0Space(t, l.Node(lab.Internet), server)
	space.spec = "/src/lab/maps/reality.yaml"
	space.env = append(space.env, "CAMOUFLAGE_IPV4="+camouflage[0].Addr().String())
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	upSrv := server.Start(t, upFor("server-1")...)
	if err := waitOutput(upSrv, applied(version), 60*time.Second); err != nil {
		return probeTarget{}, fmt.Errorf("server-1: %w", err)
	}
	realityLabs.Store(l, &realityDevice{})
	t.Cleanup(func() { realityLabs.Delete(l) })
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// realityUp starts device-a's agent once per lab and waits for its link.
func realityUp(t *testing.T, l *lab.Lab) error {
	v, ok := realityLabs.Load(l)
	if !ok {
		return fmt.Errorf("the reality row wasn't set up in this lab")
	}
	d := v.(*realityDevice)
	d.once.Do(func() {
		up := l.Node(lab.DeviceA).Start(t, "thinkpol", "up")
		d.err = waitOutput(up, `link up`, 60*time.Second)
	})
	return d.err
}

func probeReality(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	if err := realityUp(t, l); err != nil && wantPass {
		t.Fatal(err)
	}
	return probeUDP(t, l, to, wantPass)
}

// holdReality keeps the tunnel in use for d before the probe: a ping
// every 2 s, so WireGuard rekeys about every 2 minutes as it does under
// any steady use.
func holdReality(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration) {
	if err := realityUp(t, l); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d+time.Minute)
	defer cancel()
	secs := fmt.Sprint(int(d / time.Second))
	// The verdict is the probe's: lost pings during the hold aren't.
	_, _ = l.Node(lab.DeviceA).Exec(ctx, "ping", "-q", "-i", "2", "-w", secs, to.v4.String())
}

// sawReality: the link is one TCP connection from device-a to server-1's
// reality port, in either family.
func sawReality(t *testing.T, l *lab.Lab, c *censorRun) error {
	if !c.logged(t, func(e verdictLine) bool { return realityFlow(l, e) }) {
		return fmt.Errorf("no TCP flow device-a -> server-1:443 in the verdict log")
	}
	return nil
}

func realityFlow(l *lab.Lab, e verdictLine) bool {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	return e.Key.Proto == censor.ProtoTCP && e.Key.DstPort == 443 &&
		(e.Key.Src == dev.IPv4(lab.NetDevices) && e.Key.Dst == server.IPv4(lab.NetServers) ||
			e.Key.Src == dev.IPv6(lab.NetDevices) && e.Key.Dst == server.IPv6(lab.NetServers))
}

// judgedFromTheStart checks that module read the transport's connections
// from their first byte: it never tagged one of them "not framed", which
// would make a pass mean nothing.
func judgedFromTheStart(t *testing.T, l *lab.Lab, c *censorRun, module string) error {
	if c.logged(t, func(e verdictLine) bool {
		return realityFlow(l, e) && e.Event == censor.EventTag && e.Module == module && strings.HasSuffix(e.Reason, "stream not framed")
	}) {
		return fmt.Errorf("%s couldn't frame the transport's connection: its pass would mean nothing", module)
	}
	return nil
}
