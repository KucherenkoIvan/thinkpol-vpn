//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
// ClientHello names the camouflage site, which the prober and the
// server-hello comparison point at. The device comes up in the cell's
// probe (or hold), after censord, so the censor reads its TLS connection
// from the first byte.
var realityRow = transport{
	name: rowReality, setup: setupReality, probe: probeReality, sawFlows: sawReality,
	hold: holdReality, tls: true,
	// One link, over whichever of server-1's endpoints came up first.
	oneUnderlay: true,
	// REALITY dials its target on every connection it doesn't recognize:
	// the upstream tell is reported, not a gate check (owner, 2026-11-09).
	moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}},
}

// realityLabs are the reality cells' device-a processes, started once per
// cell (the row's lab runs one cell at a time) by whichever of hold and
// probe runs first.
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
	startUp(t, server)
	if _, err := statusWithin(server, 60*time.Second, nil, mapApplied(version)); err != nil {
		return probeTarget{}, err
	}
	realityLabs.Store(l, &realityDevice{})
	t.Cleanup(func() { realityLabs.Delete(l) })
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// realityUp starts device-a's agent once per lab and waits for its link,
// for a minute, or, with the budget's watch, until the censor blocked a
// 2 s wait of it (its redials are new flows): a cell that should not
// cross doesn't wait out the minute. The first caller's budget decides:
// a cell's warm-up probe passes the cell's watch on.
func realityUp(t *testing.T, l *lab.Lab, b probeBudget) error {
	v, ok := realityLabs.Load(l)
	if !ok {
		return fmt.Errorf("the reality row wasn't set up in this lab")
	}
	d := v.(*realityDevice)
	d.once.Do(func() {
		dev := l.Node(lab.DeviceA)
		startUp(t, dev)
		deadline := time.Now().Add(60 * time.Second)
		var watch func() func() bool
		if b.watch != nil {
			// One link, over either family (oneUnderlay): the watch
			// counts both.
			watch = b.watch.attempts(false)
		}
		for {
			var blocked func() bool
			if watch != nil {
				blocked = watch()
			}
			_, err := statusWithin(dev, 2*time.Second, nil, linkUp)
			switch {
			case err == nil:
				return
			case errors.Is(err, errSchemaVersion):
				d.err = err
				return
			case blocked != nil && blocked():
				d.err = fmt.Errorf("the censor blocked device-a's link: %w", err)
				return
			case time.Now().After(deadline):
				d.err = err
				return
			}
		}
	})
	return d.err
}

func probeReality(t *testing.T, l *lab.Lab, to probeTarget, b probeBudget) crossed {
	if err := realityUp(t, l, b); err != nil && b.pass {
		t.Fatal(err)
	}
	return probeUDP(t, l, to, b)
}

// holdReality brings device-a's link up and holds it (holdTunnel).
func holdReality(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool) {
	if err := realityUp(t, l, probeBudget{pass: true}); err != nil {
		t.Fatal(err)
	}
	holdTunnel(t, l, to, d, idle)
}

// holdTunnel keeps device-a's tunnel to server-1 up for d before the
// probe. In use: a ping every rhythmPing (2 s at real time), so WireGuard
// rekeys about every REKEY_AFTER_TIME (2 minutes, sped up in the lab) as
// it does under any steady use. Idle: one ping, so WireGuard
// has a session, then nothing from either end but what the tunnel sends
// on its own; no case holds idle until TP-080 brings the idle rhythm case
// back (results_test.go), and the branch stays for it. A hold whose pings
// didn't cross held no tunnel, and its cell would mean nothing: it fails
// the test.
func holdTunnel(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool) {
	ctx, cancel := context.WithTimeout(t.Context(), d+time.Minute)
	defer cancel()
	dev := l.Node(lab.DeviceA)
	if idle {
		res, err := dev.Exec(ctx, "ping", "-c", "1", "-W", "5", to.v4.String())
		if sent, got, perr := pingReceived(res.Stdout); perr != nil || sent != 1 || got != 1 {
			t.Fatalf("the idle hold's ping didn't cross (%d of %d, %v): %v", got, sent, perr, err)
		}
		select {
		case <-time.After(d):
		case <-ctx.Done():
			t.Fatalf("the idle hold was cut short: %v", ctx.Err())
		}
		return
	}
	interval := strconv.FormatFloat(rhythmPing(wgTimerScale).Seconds(), 'f', -1, 64)
	res, err := dev.Exec(ctx, "ping", "-q", "-i", interval, "-w", fmt.Sprint(int(d/time.Second)), to.v4.String())
	sent, got, perr := pingReceived(res.Stdout)
	// A censor's block of the held connection costs the redial a few
	// pings, so 4 may be lost however short the hold; else 10%.
	if allowed := max(4, sent/10); perr != nil || sent == 0 || sent-got > allowed {
		t.Fatalf("the hold's pings didn't cross: %d of %d came back, want all but %d (%v): %v", got, sent, allowed, perr, err)
	}
	t.Logf("the hold's pings: %d of %d came back", got, sent)
}

// pingReceived reads how many pings were sent and how many came back from
// iputils ping's summary line.
func pingReceived(out string) (sent, received int, err error) {
	m := pingSummary.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("no ping summary in %q", out)
	}
	sent, _ = strconv.Atoi(m[1])
	received, _ = strconv.Atoi(m[2])
	return sent, received, nil
}

var pingSummary = regexp.MustCompile(`(?m)^(\d+) packets transmitted, (\d+) (?:packets )?received`)

// TestPingReceived: the hold reads ping's summary, from either iputils or
// busybox, and a missing one is an error.
func TestPingReceived(t *testing.T) {
	for _, c := range []struct {
		out            string
		sent, received int
		ok             bool
	}{
		{"PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n\n--- 10.0.0.1 ping statistics ---\n225 packets transmitted, 224 received, 0.444444% packet loss, time 448012ms\nrtt min/avg/max/mdev = 0.1/0.2/0.3/0.1 ms\n", 225, 224, true},
		{"--- 10.0.0.1 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", 1, 0, true},
		{"--- 10.0.0.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0% packet loss\n", 1, 1, true},
		{"ping: connect: Network is unreachable\n", 0, 0, false},
	} {
		sent, received, err := pingReceived(c.out)
		if sent != c.sent || received != c.received || (err == nil) != c.ok {
			t.Errorf("%q: %d of %d, %v; want %d of %d, ok %v", c.out, received, sent, err, c.received, c.sent, c.ok)
		}
	}
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

// blockReasons is every reason module dropped or reset a flow for in the
// verdict log, read once: the cell already found the block, so the lines
// are there.
func (c *censorRun) blockReasons(module string) ([]string, error) {
	log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
	if err != nil {
		return nil, fmt.Errorf("reading the verdict log: %w", err)
	}
	var reasons []string
	_, err = matchVerdicts(completeLines(log), func(e verdictLine) bool {
		if e.Module == module && (e.Verdict == censor.Drop || e.Verdict == censor.Reset) && !slices.Contains(reasons, e.Reason) {
			reasons = append(reasons, e.Reason)
		}
		return false
	})
	return reasons, err
}

// traceSummary reads wireguard-rhythm's trace at path in the router and
// sums it up per flow: how many records of which sizes, which followed
// quiet, which answered an exchange that stood out (and how many times in
// a row it had), and the flag, at seconds from the trace's first record.
// With THINKPOL_LAB_TRACES set, the whole trace is also kept there, as
// <cell>.jsonl, for analysis offline.
func (c *censorRun) traceSummary(t *testing.T, path, cell string) string {
	t.Helper()
	out, err := execRead(c.router, pollTimeout, "cat", path)
	if err != nil {
		return fmt.Sprintf("no trace: %v", err)
	}
	if dir := os.Getenv("THINKPOL_LAB_TRACES"); dir != "" {
		name := filepath.Join(dir, strings.NewReplacer(" ", "_", "(", "", ")", "", "/", "_").Replace(cell)+".jsonl")
		if err := os.WriteFile(name, []byte(out), 0o644); err != nil {
			t.Errorf("keeping the trace: %v", err)
		} else {
			t.Logf("trace kept in %s", name)
		}
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
		if tl.Flagged != "" {
			f.flagged = fmt.Sprintf("%.1fs: %s", at, tl.Flagged)
		}
		if tl.Size == 0 {
			continue // the flag's own line, no record
		}
		f.n++
		f.sizes[tl.Size]++
		if tl.AfterQuiet {
			f.quiet = append(f.quiet, fmt.Sprintf("%.1fs:%dB", at, tl.Size))
		}
		if tl.StoodOut > 0 {
			f.stood = append(f.stood, fmt.Sprintf("%.1fs:%dB(x%d)", at, tl.Size, tl.StoodOut))
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
