//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
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
// cells run in lab.Upstream, and its ClientHello names the camouflage
// site, which the prober and the server-hello comparison point at. The
// device comes up in the cell's probe (or
// hold), after censord, so the censor reads its TLS connection from the
// first byte.
var realityRow = transport{
	name: rowReality, setup: setupReality, probe: probeReality, sawFlows: sawReality,
	upstream: true, hold: holdReality, tls: true,
	// One link, over whichever of server-1's endpoints came up first.
	oneUnderlay: true,
	// REALITY dials its target on every connection it doesn't recognize:
	// the upstream tell is reported, not a gate check (owner, 2026-11-09).
	moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}},
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

// holdReality brings device-a's link up and holds it (holdTunnel).
func holdReality(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool) {
	if err := realityUp(t, l); err != nil {
		t.Fatal(err)
	}
	holdTunnel(t, l, to, d, idle)
}

// holdTunnel keeps device-a's tunnel to server-1 up for d before the
// probe. In use: a ping every 2 s, so WireGuard rekeys about every 2
// minutes as it does under any steady use. Idle: one ping, so WireGuard
// has a session, then nothing from either end but what the tunnel sends
// on its own.
func holdTunnel(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d+time.Minute)
	defer cancel()
	dev := l.Node(lab.DeviceA)
	// The verdict is the probe's: lost pings during the hold aren't.
	if idle {
		_, _ = dev.Exec(ctx, "ping", "-c", "1", "-W", "5", to.v4.String())
		time.Sleep(d)
		return
	}
	_, _ = dev.Exec(ctx, "ping", "-q", "-i", "2", "-w", fmt.Sprint(int(d/time.Second)), to.v4.String())
}

// blockReason is the reason of module's first drop or reset in the
// verdict log, between device-a and server-1.
func (c *censorRun) blockReason(t *testing.T, module string) string {
	t.Helper()
	var why string
	c.logged(t, func(e verdictLine) bool {
		if e.Module == module && (e.Verdict == censor.Drop || e.Verdict == censor.Reset) {
			why = e.Reason
			return true
		}
		return false
	})
	return why
}

// traceSummary reads wireguard-rhythm's trace at path in the router and
// sums it up per flow: how many records of which sizes, which followed
// quiet, which answered an exchange that stood out (and how many times in
// a row it had), and the flag, at seconds from the trace's first record.
func (c *censorRun) traceSummary(t *testing.T, path string) string {
	t.Helper()
	out, err := execRead(c.router, pollTimeout, "cat", path)
	if err != nil {
		return fmt.Sprintf("no trace: %v", err)
	}
	type flowSum struct {
		n       int
		sizes   map[int]int
		quiet   []string
		stood   []string
		flagged string
	}
	var (
		order []string
		flows = map[string]*flowSum{}
		zero  time.Time
	)
	for _, line := range strings.Split(completeLines(out), "\n") {
		if line == "" {
			continue
		}
		var tl censor.WGTraceLine
		if err := json.Unmarshal([]byte(line), &tl); err != nil {
			return fmt.Sprintf("trace line %q: %v", line, err)
		}
		if zero.IsZero() {
			zero = tl.End
		}
		f := flows[tl.Flow]
		if f == nil {
			f = &flowSum{sizes: map[int]int{}}
			flows[tl.Flow] = f
			order = append(order, tl.Flow)
		}
		at := tl.End.Sub(zero).Seconds()
		f.n++
		f.sizes[tl.Size]++
		if tl.AfterQuiet {
			f.quiet = append(f.quiet, fmt.Sprintf("%.1fs:%dB", at, tl.Size))
		}
		if tl.StoodOut > 0 {
			f.stood = append(f.stood, fmt.Sprintf("%.1fs:%dB(x%d)", at, tl.Size, tl.StoodOut))
		}
		if tl.Flagged != "" {
			f.flagged = fmt.Sprintf("%.1fs: %s", at, tl.Flagged)
		}
	}
	capped := func(xs []string) string {
		if len(xs) > 30 {
			return fmt.Sprintf("%v and %d more", xs[:30], len(xs)-30)
		}
		return fmt.Sprint(xs)
	}
	var b strings.Builder
	for _, name := range order {
		f := flows[name]
		sizes := slices.Sorted(maps.Keys(f.sizes))
		var hist []string
		for _, sz := range sizes {
			hist = append(hist, fmt.Sprintf("%dB x%d", sz, f.sizes[sz]))
		}
		fmt.Fprintf(&b, "%s: %d records by size %s\n  after quiet: %s\n  answered an exchange that stood out: %s\n  flagged: %q\n",
			name, f.n, capped(hist), capped(f.quiet), capped(f.stood), f.flagged)
	}
	return b.String()
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
