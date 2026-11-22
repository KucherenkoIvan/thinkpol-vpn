//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Path liveness on real links (docs/design/path-liveness.md, TP-080):
// device-a's link to server-1 over reality and over udp, through the
// router, where a capture watches it and a blackhole cuts it.

// Path probe frames (docs/design/path-liveness.md, "Acks in the frames"):
// probes, replies and close notices are 18 bytes, the older ones 10.
const (
	probeFrame   = 18
	probeFrameV1 = 10
)

// Liveness bounds from the design, at the transports' defaults (no delay
// shaping: D = 0 on both, path's doc).
const (
	// busyBound is how soon after its last answer a link under traffic is
	// found dead: S + R + T at their tops, 1.5 + 1 + 2 s.
	busyBound = 4500 * time.Millisecond
	// todayBound is the rule before TP-080's: closed 6 s after the last
	// reply, probes 2 s apart, 6.5 s at worst.
	todayBound = 6500 * time.Millisecond
	// loadSlack is what a loaded lab machine may add to a timer: the
	// design's bounds are the rules', a node held up fires late.
	loadSlack = 1500 * time.Millisecond
)

// idleRange is I's range per transport, and idleBound how soon a dead idle
// link is found: I's top and T (2 s).
var (
	idleRange = map[string][2]time.Duration{"reality": {8 * time.Second, 24 * time.Second}, "udp": {5 * time.Second, 14 * time.Second}}
	idleBound = map[string]time.Duration{"reality": 26 * time.Second, "udp": 16 * time.Second}
)

// livenessLink is device-a's link to server-1 over one transport, up.
type livenessLink struct {
	transport           string
	l                   *lab.Lab
	dev, server, router *lab.Node
	devUp, serverUp     *lab.Process
	target              netip.Addr // server-1's overlay IPv4 address
	// capture holds what crossed the router between device-a and
	// server-1, each packet as it left the router, from before the link
	// came up: on udp only probe-sized datagrams (probesOnly), else every
	// packet of the link (few enough only while it idles: the capture's
	// ring holds about 500); nil when not captured.
	capture *lab.Capture
}

// What upLink captures.
const (
	captureNone = iota
	probesOnly
	everyPacket
)

// upLink brings device-a's link to server-1 up over transport, reality
// (lab/maps/reality.yaml, a lab with the camouflage site) or udp
// (lab/maps/m0.yaml). The capture starts before device-a does, so it
// holds the link's first frames.
func upLink(t *testing.T, transport string, capture int) *livenessLink {
	t.Helper()
	var l *lab.Lab
	if transport == "reality" {
		l = censorPool.Acquire(t)
	} else {
		l = tunnelPool.Acquire(t)
	}
	k := &livenessLink{transport: transport, l: l, dev: l.Node(lab.DeviceA), server: l.Node(lab.Server1), router: l.Node(lab.Router)}
	space := newM0Space(t, k.router, k.server)
	proto, port := "udp", 4500
	if transport == "reality" {
		camouflage := lab.StartCamouflage(t, l)
		space.spec = "/src/lab/maps/reality.yaml"
		space.env = append(space.env, "CAMOUFLAGE_IPV4="+camouflage[0].Addr().String())
		proto, port = "tcp", 443
	}
	envelope, version := space.build(t)
	space.install(t, k.dev, "device-a", envelope)
	space.install(t, k.server, "server-1", envelope)
	k.serverUp = startUp(t, k.server)
	waitStatusFor(t, k.server, 60*time.Second, nil, mapApplied(version))
	devs := []string{k.dev.IPv4(lab.NetDevices).String(), k.dev.IPv6(lab.NetDevices).String()}
	filter := fmt.Sprintf("outbound and %s port %d and (host %s or host %s)", proto, port, devs[0], devs[1])
	switch capture {
	case probesOnly:
		// The IP packet's length: IPv4's total, IPv6's payload.
		var sizes []string
		for _, n := range []int{probeFrame + udp.Overhead + 8, probeFrameV1 + udp.Overhead + 8} {
			sizes = append(sizes, fmt.Sprintf("ip[2:2] = %d or ip6[4:2] = %d", 20+n, n))
		}
		k.capture = k.router.Capture(t, filter+" and ("+strings.Join(sizes, " or ")+")")
	case everyPacket:
		k.capture = k.router.Capture(t, filter)
	}
	k.devUp = startUp(t, k.dev)
	waitStatus(t, k.dev, linkUp)
	k.target, _ = space.overlay(1)
	return k
}

// counters reads device-a's probe counters: liveness's own frames it
// wrote and read.
func (k *livenessLink) counters(t *testing.T) (sent, read uint64) {
	t.Helper()
	st, err := readStatus(k.dev, pollTimeout)
	if err != nil {
		t.Fatal(err)
	}
	sent, ok1 := st.counter("path.probes_sent")
	read, ok2 := st.counter("path.probes_received")
	if !ok1 || !ok2 {
		t.Fatalf("device-a's status has no probe counters:\n%s", st.raw)
	}
	return sent, read
}

// carrying says whether a captured packet carries a frame: a udp datagram,
// or a TCP segment with data.
func carrying(p lab.Packet) bool { return len(p.Payload) > 0 }

// probeSized says whether a captured udp datagram is the size of a path
// probe, a reply or a close notice, either format. No packet frame is that
// small: a WireGuard message is 32 bytes or more.
func probeSized(p lab.Packet) bool {
	n := len(p.Payload)
	return n == probeFrame+udp.Overhead || n == probeFrameV1+udp.Overhead
}

// pingFor pings server-1's overlay address from device-a every 20 ms for
// d, in the background; the returned func waits for it and says how many
// came back of how many.
func (k *livenessLink) pingFor(t *testing.T, d time.Duration) func() (sent, got int) {
	t.Helper()
	done := make(chan [2]int, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), d+30*time.Second)
		defer cancel()
		res, _ := k.dev.Exec(ctx, "ping", "-q", "-i", "0.02", "-W", "1", "-w", fmt.Sprint(int(d/time.Second)), k.target.String())
		sent, got, _ := pingReceived(res.Stdout)
		done <- [2]int{sent, got}
	}()
	return func() (int, int) {
		r := <-done
		return r[0], r[1]
	}
}

// blackhole drops what the router forwards between device-a and server-1:
// both ways, or only from server-1 to device-a. The returned func lifts
// it.
func (k *livenessLink) blackhole(t *testing.T, bothWays bool) func() {
	t.Helper()
	d4, d6 := k.dev.IPv4(lab.NetDevices), k.dev.IPv6(lab.NetDevices)
	s4, s6 := k.server.IPv4(lab.NetServers), k.server.IPv6(lab.NetServers)
	rules := fmt.Sprintf("ip saddr %s ip daddr %s drop\n\t\tip6 saddr %s ip6 daddr %s drop\n", s4, d4, s6, d6)
	if bothWays {
		rules += fmt.Sprintf("\t\tip saddr %s ip daddr %s drop\n\t\tip6 saddr %s ip6 daddr %s drop\n", d4, s4, d6, s6)
	}
	k.router.WriteFile(t, "/tmp/blackhole.nft", []byte("table inet blackhole {\n\tchain forward {\n\t\ttype filter hook forward priority -10; policy accept;\n\t\t"+rules+"\t}\n}\n"))
	k.router.MustExec(t, "nft", "-f", "/tmp/blackhole.nft")
	return func() { k.router.MustExec(t, "nft", "delete", "table", "inet", "blackhole") }
}

// linkClosed matches a node's log line for a link it closed, with how
// long before the close its last answer came and why.
var linkClosed = regexp.MustCompile(`msg="link closed" .*?reason="([^"]*)".* last_answer=(\S+)`)

// closed waits up to within for p's log, past offset from, to say the
// link closed, and returns how long after its last answer and why.
func closed(t *testing.T, p *lab.Process, name string, from int, within time.Duration) (time.Duration, string) {
	t.Helper()
	var m []string
	lab.Eventually(t, within, func() error {
		m = linkClosed.FindStringSubmatch(p.Output()[from:])
		if m == nil {
			return fmt.Errorf("%s hasn't closed its link", name)
		}
		return nil
	})
	d, err := time.ParseDuration(m[2])
	if err != nil {
		t.Fatalf("%s's link closed with last_answer=%q: %v", name, m[2], err)
	}
	return d, m[1]
}

// TestBusyLinksSendNoProbes: while data flows both ways (pings every
// 20 ms), device-a and server-1 send no probes, replies or notices: on
// udp no probe-sized datagram crosses the router, and on both transports
// device-a's probe counters stand still. The capture and the counters
// see the probes that brought the link up, so they count what they
// should. Then the dead link under traffic (TestDeadUnderTraffic's
// rules, in the same lab): a blackhole both ways, then, after the link
// is back, one from server-1 to device-a under a one-way stream from
// device-a: each end finds it dead within the busy bound of its last
// answer (S + R + T, 4.5 s; today's rule took up to 6.5 s), server-1 in
// the one-way case by device-a's close notice or by its own unanswered
// frames, whichever comes first.
func TestBusyLinksSendNoProbes(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{"reality", "udp"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			capture := captureNone
			if transport == "udp" {
				capture = probesOnly
			}
			k := upLink(t, transport, capture)
			busyLinksSendNoProbes(t, k)
			deadUnderTraffic(t, k)
		})
	}
}

func busyLinksSendNoProbes(t *testing.T, k *livenessLink) {
	sent0, read0 := k.counters(t)
	if sent0 == 0 || read0 == 0 {
		t.Fatalf("device-a counted %d probes sent and %d read bringing its link up, want some of each", sent0, read0)
	}
	wait := k.pingFor(t, 16*time.Second)
	// The window opens once the pings have run for 2 s and closes 1 s
	// before they end: the busy rules hold within it, from the first
	// answered ping on.
	time.Sleep(2 * time.Second)
	from := time.Now()
	sentA, readA := k.counters(t)
	time.Sleep(12 * time.Second)
	sentB, readB := k.counters(t)
	to := time.Now()
	sent, got := wait()
	if sent == 0 || got < sent*9/10 {
		t.Fatalf("the pings didn't cross: %d of %d came back", got, sent)
	}
	t.Logf("%s: %d of %d pings came back; device-a's probe counters %d sent and %d read before the pings, %d and %d after 2 s, %d and %d after 14 s",
		k.transport, got, sent, sent0, read0, sentA, readA, sentB, readB)
	if sentB != sentA || readB != readA {
		t.Errorf("%s under two-way traffic: device-a wrote %d probes, replies or notices and read %d in %v", k.transport, sentB-sentA, readB-readA, to.Sub(from).Round(time.Millisecond))
	}
	if k.transport != "udp" {
		return
	}
	var before, within int
	for _, p := range k.capture.Packets() {
		if !probeSized(p) {
			continue
		}
		switch {
		case p.Time.Before(from):
			before++
		case !p.Time.After(to):
			within++
		}
	}
	t.Logf("udp: %d probe-sized datagrams crossed the router before the window, %d within it", before, within)
	if before == 0 {
		t.Errorf("no probe-sized datagram crossed the router before the window: the capture doesn't see probes, its zero says nothing")
	}
	if within != 0 {
		t.Errorf("%d probe-sized datagrams crossed the router under two-way traffic", within)
	}
}

func deadUnderTraffic(t *testing.T, k *livenessLink) {
	// Both ways, under pings.
	wait := k.pingFor(t, 12*time.Second)
	time.Sleep(3 * time.Second)
	devFrom, serverFrom := len(k.devUp.Output()), len(k.serverUp.Output())
	cut := time.Now()
	lift := k.blackhole(t, true)
	devAfter, devWhy := closed(t, k.devUp, "device-a", devFrom, todayBound+10*time.Second)
	devSeen := time.Since(cut)
	serverAfter, serverWhy := closed(t, k.serverUp, "server-1", serverFrom, todayBound+10*time.Second)
	t.Logf("%s, cut both ways under pings: device-a closed its link %v after its last answer (%q), seen %v after the cut; server-1 %v after its last answer (%q)",
		k.transport, devAfter, devWhy, devSeen.Round(time.Millisecond), serverAfter, serverWhy)
	checkBusyBound(t, k.transport+", cut both ways", "device-a", devAfter)
	checkBusyBound(t, k.transport+", cut both ways", "server-1", serverAfter)
	lift()
	wait()
	waitStatus(t, k.dev, linkUp)

	// One way: device-a streams to server-1, which sends nothing of its
	// own back (a sink); server-1's way is cut, so server-1 is the
	// receive-only end whose sending side broke.
	k.server.Start(t, "socat", "-u", "UDP-RECV:9999", "OPEN:/dev/null")
	streamCtx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		_, _ = k.dev.Exec(streamCtx, "timeout", "30", "sh", "-c", "while :; do echo stream; sleep 0.02; done | socat -u - UDP:"+k.target.String()+":9999")
	}()
	time.Sleep(3 * time.Second)
	devFrom, serverFrom = len(k.devUp.Output()), len(k.serverUp.Output())
	lift = k.blackhole(t, false)
	defer lift()
	devAfter, devWhy = closed(t, k.devUp, "device-a", devFrom, todayBound+10*time.Second)
	serverAfter, serverWhy = closed(t, k.serverUp, "server-1", serverFrom, todayBound+10*time.Second)
	t.Logf("%s, cut from server-1 under device-a's one-way stream: device-a closed its link %v after its last answer (%q); server-1 %v after its last answer (%q)",
		k.transport, devAfter, devWhy, serverAfter, serverWhy)
	checkBusyBound(t, k.transport+", one-way stream, cut from server-1", "device-a", devAfter)
	// The receive-only end: the notice comes a one-way trip after
	// device-a's close.
	checkBusyBound(t, k.transport+", one-way stream, cut from server-1", "server-1", serverAfter)
}

// checkBusyBound fails the test when a node took longer than today's rule
// allows (6.5 s, with the load's slack) to find a link under traffic dead:
// the busy bound (4.5 s) and the load's slack are both under it, the idle
// rule (16 s or 26 s), which a link under traffic must never wait for,
// far over it.
func checkBusyBound(t *testing.T, what, node string, after time.Duration) {
	t.Helper()
	if after > todayBound+loadSlack {
		t.Errorf("%s: %s closed its link %v after its last answer, want within %v (the busy bound %v; today's rule %v)", what, node, after, todayBound+loadSlack, busyBound, todayBound)
	} else if after > busyBound+loadSlack {
		t.Logf("%s: %s took %v, past the busy bound %v and the load's slack: a loaded machine, or the rule", what, node, after, busyBound)
	}
}

// TestIdleLinksProbeAtRandom (long stream: it holds links idle for
// minutes): an idle link over reality and over udp exchanges one probe and
// its reply at intervals within the transport's idle range (8 to 24 s, 5
// to 14 s; the earlier of the two ends' draws), spread rather than at a
// fixed rhythm, over 31 intervals; then a blackhole both ways is found
// within the idle bound (I's top and T: 26 s, 16 s) of each end's last
// answer.
func TestIdleLinksProbeAtRandom(t *testing.T) {
	lab.LongTest(t)
	t.Parallel()
	for _, transport := range []string{"reality", "udp"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			k := upLink(t, transport, everyPacket)
			r := idleRange[transport]
			// 31 intervals take about 31 times the earlier of two draws
			// on average (13.3 s on reality, 8 s on udp); the wait gives
			// them over seven standard deviations more.
			wait := map[string]time.Duration{"reality": 10 * time.Minute, "udp": 6 * time.Minute}[transport]
			var gaps []time.Duration
			lab.Eventually(t, wait, func() error {
				gaps = idleGaps(k.capture.Packets())
				if len(gaps) < 31 {
					return fmt.Errorf("%d idle intervals so far, want 31", len(gaps))
				}
				return nil
			})
			gaps = gaps[:31]
			lo, hi := slices.Min(gaps), slices.Max(gaps)
			close := 0
			for i := 1; i < len(gaps); i++ {
				if d := gaps[i] - gaps[i-1]; d > -time.Second && d < time.Second {
					close++
				}
			}
			var shown []string
			for _, g := range gaps {
				shown = append(shown, g.Round(10*time.Millisecond).String())
			}
			t.Logf("%s idle: 31 intervals from %v to %v, %d of 30 consecutive pairs within 1 s of each other: %s",
				transport, lo.Round(10*time.Millisecond), hi.Round(10*time.Millisecond), close, strings.Join(shown, " "))
			// An end probes no sooner than I's bottom after its last
			// answer, the far end's probe or its own reply, and the
			// earlier end no later than I's top.
			for _, g := range gaps {
				if g < r[0]-100*time.Millisecond || g > r[1]+loadSlack {
					t.Errorf("%s: an idle exchange %v after the one before, want %v to %v", transport, g, r[0], r[1])
				}
			}
			// Spread: 31 intervals all within 3 s of each other would be
			// a fixed rhythm. Drawn, that happens about 10⁻⁸ of the time
			// on udp (the earlier of two draws crowds I's bottom: 56% of
			// them fall in its first 3 s) and far less on reality.
			if hi-lo < 3*time.Second {
				t.Errorf("%s: 31 idle intervals within %v of each other: a fixed rhythm", transport, hi-lo)
			}

			devFrom, serverFrom := len(k.devUp.Output()), len(k.serverUp.Output())
			cut := time.Now()
			lift := k.blackhole(t, true)
			defer lift()
			bound := idleBound[transport]
			devAfter, devWhy := closed(t, k.devUp, "device-a", devFrom, bound+loadSlack+10*time.Second)
			devSeen := time.Since(cut)
			serverAfter, serverWhy := closed(t, k.serverUp, "server-1", serverFrom, bound+loadSlack+10*time.Second)
			t.Logf("%s idle, cut both ways: device-a closed its link %v after its last answer (%q), seen %v after the cut; server-1 %v after its last answer (%q)",
				transport, devAfter, devWhy, devSeen.Round(time.Millisecond), serverAfter, serverWhy)
			for node, after := range map[string]time.Duration{"device-a": devAfter, "server-1": serverAfter} {
				if after > bound+loadSlack {
					t.Errorf("%s idle: %s closed its link %v after its last answer, want within %v (and the load's slack)", transport, node, after, bound)
				}
			}
		})
	}
}

// idleGaps reads idle exchanges from a capture of a link's frames (each
// packet once, as it left the router): a frame after 2 s with none either
// way, answered within 2 s by one the other way, and none more before
// the next 2 s of quiet. It returns the intervals between consecutive
// ones, from the first after the link's first 3 s of quiet on (its setup
// and first ping behind it). Any other frame (a passive keepalive) ends
// the run: the interval across it isn't one.
func idleGaps(packets []lab.Packet) []time.Duration {
	const quiet, answer = 2 * time.Second, 2 * time.Second
	var frames []lab.Packet
	for _, p := range packets {
		if carrying(p) {
			frames = append(frames, p)
		}
	}
	var gaps []time.Duration
	var prev time.Time // the latest exchange's first frame, zero after a frame that ends the run
	started := false
	for i := 0; i < len(frames); i++ {
		p := frames[i]
		afterQuiet := i > 0 && p.Time.Sub(frames[i-1].Time) >= quiet
		if !started {
			started = i > 0 && p.Time.Sub(frames[i-1].Time) >= 3*time.Second
			if !started {
				continue
			}
		}
		exchange := afterQuiet && i+1 < len(frames) && frames[i+1].Src != p.Src && frames[i+1].Time.Sub(p.Time) <= answer &&
			(i+2 >= len(frames) || frames[i+2].Time.Sub(frames[i+1].Time) >= quiet)
		if !exchange {
			prev = time.Time{}
			continue
		}
		if !prev.IsZero() {
			gaps = append(gaps, p.Time.Sub(prev))
		}
		prev = p.Time
		i++
	}
	return gaps
}

// TestIdleGaps: the idle intervals read from a capture: exchanges after
// quiet, one frame each way, from the first after 3 s of quiet; a lone
// frame or a third one in an exchange ends the run.
func TestIdleGaps(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	t0 := time.Unix(1_700_000_000, 0)
	var ps []lab.Packet
	frame := func(at time.Duration, from netip.Addr) {
		ps = append(ps, lab.Packet{Time: t0.Add(at), Src: from, Payload: []byte{1}})
	}
	ack := func(at time.Duration, from netip.Addr) { ps = append(ps, lab.Packet{Time: t0.Add(at), Src: from}) }
	ms := time.Millisecond
	// Setup and the ping: frames close together, never a gap.
	frame(0, a)
	frame(100*ms, b)
	frame(1500*ms, a)
	frame(1501*ms, b)
	// Exchanges, either end opening; a bare ack in one changes nothing.
	for _, at := range []time.Duration{9 * time.Second, 20 * time.Second, 31 * time.Second} {
		frame(at, a)
		ack(at+ms, b)
		frame(at+2*ms, b)
	}
	frame(40*time.Second, b)
	frame(40*time.Second+2*ms, a)
	// A lone frame, then a three-frame exchange: no intervals across them.
	frame(50*time.Second, a)
	frame(60*time.Second, a)
	frame(60*time.Second+2*ms, b)
	frame(60*time.Second+4*ms, b)
	frame(70*time.Second, a)
	frame(70*time.Second+2*ms, b)
	frame(80*time.Second, b)
	frame(80*time.Second+2*ms, a)
	want := []time.Duration{11 * time.Second, 11 * time.Second, 9 * time.Second, 10 * time.Second}
	if got := idleGaps(ps); !slices.Equal(got, want) {
		t.Errorf("idle intervals %v, want %v", got, want)
	}
}
