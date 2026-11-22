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
// probe (or hold), after censord (deviceUp), so the censor reads its TLS
// connection from the first byte. The row's recorded off cell also
// watches server-1 idle after start-up (idleServerLeavesItsTarget).
var realityRow = transport{
	name: rowReality, setup: setupReality, probe: probeWithDevice, sawFlows: sawReality,
	hold: holdWithDevice, tunnel: realityFlow, tls: true, labs: 3, cellTime: 20 * time.Second,
	// One link, over whichever of server-1's endpoints came up first.
	oneUnderlay: true,
	// REALITY dials its target on every connection it doesn't recognize:
	// the upstream tell is reported, not a gate check (owner, 2026-11-09).
	moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}},
}

func setupReality(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server, dev, site := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Camouflage)
	camouflage := lab.StartCamouflage(t, l)
	space := newM0Space(t, site, server)
	space.spec = "/src/lab/maps/reality.yaml"
	space.env = append(space.env, "CAMOUFLAGE_IPV4="+camouflage[0].Addr().String())
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	up := startUp(t, server)
	if _, err := statusWithin(server, 60*time.Second, nil, mapApplied(version)); err != nil {
		return probeTarget{}, err
	}
	if recordedOffCell(t, rowReality) {
		if err := idleServerLeavesItsTarget(t, server, site, up); err != nil {
			return probeTarget{}, err
		}
	}
	deferDevice(t, l)
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// idleHold is how long idleServerLeavesItsTarget watches an idle server:
// at least two of the server's apply retries (3 to 7 s apart, 5 s on
// average: agent.RetryAfter, a wall clock constant the lab doesn't speed
// up).
const idleHold = 15 * time.Second

// recordedOffCell says whether t is the off cell the row's first lab
// records (TestCensorMatrix/<row>/off, in each stream that runs it): a
// check of the row's setup that holds the cell runs there once, not in
// every cell.
func recordedOffCell(t *testing.T, row string) bool {
	parts := strings.Split(t.Name(), "/")
	n := len(parts)
	return n >= 2 && parts[n-2] == row && parts[n-1] == offCase
}

// offCase is the name of the matrix's off cell, censorCases[0].
const offCase = "off"

// idleServerLeavesItsTarget watches server-1, serving the reality map
// with no client (device-a starts later, deferDevice), for idleHold after
// its start-up: the map's listeners are derived from its endpoints
// (reality 0.0.0.0:443 and reality [::]:443), both must open, so the
// apply doesn't retry, and nothing it retries may dial the target. Before
// TP-230, [::]:443 couldn't bind next to 0.0.0.0:443's dual-stack socket,
// and every retry, every 5 s, made a TLS handshake with the target from
// the server's address.
func idleServerLeavesItsTarget(t *testing.T, server, site *lab.Node, up *lab.Process) error {
	// Start-up has ended: the caller's mapApplied passes only once the
	// first apply has opened every listener and checked the target.
	// The target is IPv4 (CAMOUFLAGE_IPV4): every connection to it opens
	// with a SYN this filter sees.
	dials := site.Capture(t, "tcp dst port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")
	logged := len(up.Output())
	var errs []error
	for deadline := time.Now().Add(idleHold); ; {
		st, err := readStatus(server, pollTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("server-1's status: %w", err))
			break
		}
		if st.Retrying {
			errs = append(errs, fmt.Errorf("server-1 retries its map %s while idle", st.MapVersion))
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(min(5*time.Second, time.Until(deadline)))
	}
	if syns := dials.Stop(); len(syns) > 0 {
		var from []string
		for _, p := range syns {
			from = append(from, fmt.Sprintf("%s %s", p.Time.UTC().Format("15:04:05.000"), p.Src))
		}
		errs = append(errs, fmt.Errorf("the target got %d connections from an idle server-1 within %v of its start-up: %s",
			len(syns), idleHold, strings.Join(from, ", ")))
	}
	if lines := failedLines(up.Output()[logged:]); lines != "" {
		errs = append(errs, fmt.Errorf("server-1 logged failures while idle:\n%s", lines))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w\n%s", errors.Join(errs...), failedLines(up.Output()))
	}
	return nil
}

// failedLines are the lines of a node's log that say something failed.
func failedLines(log string) string {
	var out []string
	for line := range strings.Lines(log) {
		if strings.Contains(line, "failed") {
			out = append(out, strings.TrimRight(line, "\n"))
		}
	}
	return strings.Join(out, "\n")
}

// holdTunnel keeps device-a's tunnel to server-1 up for d before the
// probe. In use: a ping every rhythmPing (2 s at real time), so WireGuard
// rekeys about every REKEY_AFTER_TIME (2 minutes, sped up in the lab) as
// it does under any steady use. Idle: one ping, so WireGuard
// has a session, then nothing from either end but what the tunnel sends
// on its own: its path probes (rhythmIdleCase). A hold whose pings
// didn't cross held no tunnel, and its cell would mean nothing: it fails
// the test. blocks is how many connections the censor blocked meanwhile,
// read once the pings are done.
func holdTunnel(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool, blocks func() int) {
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
	interval := rhythmPing(wgTimerScale)
	res, err := dev.Exec(ctx, "ping", "-q", "-i", strconv.FormatFloat(interval.Seconds(), 'f', -1, 64),
		"-w", fmt.Sprint(int(d/time.Second)), to.v4.String())
	sent, got, perr := pingReceived(res.Stdout)
	// 10% may be lost, at least 4, and the pings of one redial per block
	// the censor logged: a block of the held connection costs its redial
	// up to 7 s at any timer scale (thinkpol's path gives up on a link 6 s
	// after its probes go unanswered, at real time), 3 pings at real time,
	// 17 at a factor of 10. A scaled hold can see two blocks: udp's
	// connection is caught about 24 s into its 55 s, and the redialled
	// one again before the hold ends.
	n := blocks()
	if allowed := max(4, sent/10) + n*int(holdRedial/interval); perr != nil || sent == 0 || sent-got > allowed {
		t.Fatalf("the hold's pings didn't cross: %d of %d came back, want all but %d (%d blocks) (%v): %v", got, sent, allowed, n, perr, err)
	}
	t.Logf("the hold's pings: %d of %d came back, %d blocks", got, sent, n)
}

// holdRedial is the longest a held tunnel's redial after a block takes.
const holdRedial = 7 * time.Second

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

// blocks is how many flows module dropped or reset in the verdict log,
// each a connection the hold's tunnel redialled after. A flow that
// started over under the same addresses and ports counts once.
func (c *censorRun) blocks(t *testing.T, module string) int {
	t.Helper()
	if c == nil {
		return 0
	}
	flows := map[string]bool{}
	c.logged(t, func(e verdictLine) bool {
		if e.Module == module && (e.Event == censor.EventDecision || e.Event == censor.EventFlag) && (e.Verdict == censor.Drop || e.Verdict == censor.Reset) {
			flows[e.Flow] = true
		}
		return false
	})
	return len(flows)
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
	if !c.logged(t, func(e verdictLine) bool { return realityFlow(l, e.Key) }) {
		return fmt.Errorf("no TCP flow device-a -> server-1:443 in the verdict log")
	}
	return nil
}

func realityFlow(l *lab.Lab, k censor.FlowKey) bool {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	return k.Proto == censor.ProtoTCP && k.DstPort == 443 &&
		(k.Src == dev.IPv4(lab.NetDevices) && k.Dst == server.IPv4(lab.NetServers) ||
			k.Src == dev.IPv6(lab.NetDevices) && k.Dst == server.IPv6(lab.NetServers))
}
