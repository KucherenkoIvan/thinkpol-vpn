//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Path liveness on real links (docs/design/path-liveness.md): device-a's
// link to server-1 over reality and over udp, through the router, where a
// capture watches it, a blackhole cuts it and netem blacks it out.

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
	// v1Bound is the V1 rule's: closed 6 s after the last reply, probes
	// 2 s apart, 6.5 s at worst.
	v1Bound = 6500 * time.Millisecond
	// loadSlack is what a loaded lab machine may add to a timer: the
	// design's bounds are the rules', a node held up fires late.
	loadSlack = 1500 * time.Millisecond
	// labTrip is a generous one-way trip through the lab's router (it
	// takes under a millisecond): what a close notice adds.
	labTrip = 100 * time.Millisecond
)

// idleRange is I's range per transport, and idleBound how soon a dead idle
// link is found: I's top and T (2 s).
var (
	idleRange = map[string][2]time.Duration{"reality": {8 * time.Second, 24 * time.Second}, "udp": {5 * time.Second, 14 * time.Second}}
	idleBound = map[string]time.Duration{"reality": 26 * time.Second, "udp": 16 * time.Second}
)

// idleIntervals is how many idle intervals TestIdleLinksProbeAtRandom
// reads per transport: enough that all of them falling within 3 s of each
// other by chance, the spread check failing, stays under 10⁻⁷. The
// earlier of two draws crowds I's bottom, udp's most (56% of its intervals
// fall in the first 3 s): 31 intervals take that chance to 3.5·10⁻⁸ on
// udp; reality's 20 take it to 2.2·10⁻⁹ (computed).
var idleIntervals = map[string]int{"reality": 20, "udp": 31}

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

// counters reads device-a's control counters: liveness's own frames
// (probes, replies, close notices) it wrote and read.
func (k *livenessLink) counters(t *testing.T) (sent, read uint64) {
	t.Helper()
	st, err := readStatus(k.dev, pollTimeout)
	if err != nil {
		t.Fatal(err)
	}
	sent, ok1 := st.counter("path.control_sent")
	read, ok2 := st.counter("path.control_received")
	if !ok1 || !ok2 {
		t.Fatalf("device-a's status has no control counters:\n%s", st.raw)
	}
	return sent, read
}

// pathSentIn is how many packets device-a's path sent over d.
func (k *livenessLink) pathSentIn(t *testing.T, d time.Duration) uint64 {
	t.Helper()
	read := func() uint64 {
		st, err := readStatus(k.dev, pollTimeout)
		if err != nil {
			t.Fatal(err)
		}
		n, ok := st.counter("path.sent")
		if !ok {
			t.Fatalf("device-a's status has no path.sent:\n%s", st.raw)
		}
		return n
	}
	before := read()
	time.Sleep(d)
	return read() - before
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
	wait := k.pingTimed(t, d)
	return func() (int, int) {
		sent, got, _ := wait()
		return sent, got
	}
}

// pingTimed is pingFor that also returns when each reply came, by
// device-a's clock (the lab's nodes share the host's).
func (k *livenessLink) pingTimed(t *testing.T, d time.Duration) func() (sent, got int, replies []time.Time) {
	t.Helper()
	type result struct {
		sent, got int
		replies   []time.Time
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), d+30*time.Second)
		defer cancel()
		res, _ := k.dev.Exec(ctx, "ping", "-D", "-i", "0.02", "-W", "1", "-w", fmt.Sprint(int(d/time.Second)), k.target.String())
		sent, got, _ := pingReceived(res.Stdout)
		var replies []time.Time
		for _, m := range pingReply.FindAllStringSubmatch(res.Stdout, -1) {
			if at, err := strconv.ParseFloat(m[1], 64); err == nil {
				replies = append(replies, time.Unix(0, int64(at*1e9)))
			}
		}
		done <- result{sent, got, replies}
	}()
	return func() (int, int, []time.Time) {
		r := <-done
		return r.sent, r.got, r.replies
	}
}

// pingReply matches a reply line of iputils' ping -D, its time.
var pingReply = regexp.MustCompile(`(?m)^\[(\d+\.\d+)\] \d+ bytes from `)

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

// blackout and blackoutSlack: blackoutRiddenOut's blackout, and how much
// longer than it the router may hold it (a fork and a tc each end) before
// the test calls its setup broken.
const (
	blackout      = time.Second
	blackoutSlack = 250 * time.Millisecond
)

// holdBlackout drops everything leaving the router on ifaces for d, with
// netem, in one exec inside the router: an exec from the host takes up to
// seconds on a loaded machine, and four of them stretched a 1 s blackout. It
// returns when each interface's blackout began and ended, by the router's
// clock: stamped before each add and after each del, so a late stamp can
// only widen a window, never hide part of the real drop.
func (k *livenessLink) holdBlackout(t *testing.T, ifaces []string, d time.Duration) (on, off []time.Time) {
	t.Helper()
	script := "set -e\n"
	for _, i := range ifaces {
		script += "date +%s%N\ntc qdisc add dev " + i + " root netem loss 100%\n"
	}
	script += fmt.Sprintf("sleep %.3f\n", d.Seconds())
	for _, i := range ifaces {
		script += "tc qdisc del dev " + i + " root\ndate +%s%N\n"
	}
	out := k.router.MustExec(t, "sh", "-c", script)
	var stamps []time.Time
	for _, f := range strings.Fields(out) {
		ns, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			t.Fatalf("the router's blackout printed %q: not timestamps", out)
		}
		stamps = append(stamps, time.Unix(0, ns))
	}
	if len(stamps) != 2*len(ifaces) {
		t.Fatalf("the router's blackout printed %q, want %d timestamps", out, 2*len(ifaces))
	}
	return stamps[:len(ifaces)], stamps[len(ifaces):]
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

// TestLinksUnderTraffic (long stream, for the default stream's budget):
// device-a's link to server-1 while data flows, over reality and over
// udp, one lab each, in turn:
//   - no probes (busyLinksSendNoProbes): under pings both ways, no probe,
//     reply or notice either way;
//   - on reality, a 1 s blackout ridden out (blackoutRiddenOut);
//   - dead both ways (deadBothWays): a blackhole under the pings, found
//     within the busy bound at each end;
//   - dead one way (deadOneWay): a blackhole from server-1 under a
//     one-way stream from device-a, found within the busy bound by
//     device-a and by server-1, the receive-only end, on udp (by
//     device-a's close notice), within the idle bound on reality (owner,
//     2026-11-22: the notice waits behind the stalled stream there).
func TestLinksUnderTraffic(t *testing.T) {
	lab.LongTest(t)
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
			if transport == "reality" {
				blackoutRiddenOut(t, k)
			}
			deadBothWays(t, k)
			deadOneWay(t, k)
		})
	}
}

// busyLinksSendNoProbes: while data flows both ways (pings every 20 ms),
// device-a and server-1 send no probes, replies or notices: on udp no
// probe-sized datagram crosses the router, and on both transports
// device-a's control counters stand still. The capture and the counters
// see the probes that brought the link up, so they count what they
// should.
func busyLinksSendNoProbes(t *testing.T, k *livenessLink) {
	t.Helper()
	sent0, read0 := k.counters(t)
	if sent0 == 0 || read0 == 0 {
		t.Fatalf("device-a counted %d control frames sent and %d read bringing its link up, want some of each", sent0, read0)
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
	t.Logf("%s: %d of %d pings came back; device-a's control counters %d sent and %d read before the pings, %d and %d after 2 s, %d and %d after 14 s",
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

// blackoutRiddenOut: under pings, netem on the router drops everything
// between device-a and server-1 for 1 s, both ways; TCP retransmits once
// it lifts, well within the busy rules' S + R + T, so neither end closes
// its link and the pings come back. The router holds the blackout itself
// (holdBlackout), so a loaded machine's slow execs can't stretch it.
func blackoutRiddenOut(t *testing.T, k *livenessLink) {
	t.Helper()
	wait := k.pingTimed(t, 12*time.Second)
	time.Sleep(3 * time.Second)
	devFrom, serverFrom := len(k.devUp.Output()), len(k.serverUp.Output())
	ifaces := []string{k.router.Interface(lab.NetDevices), k.router.Interface(lab.NetServers)}
	on, off := k.holdBlackout(t, ifaces, blackout)
	sent, got, replies := wait()
	var held []time.Duration
	for n := range ifaces {
		held = append(held, off[n].Sub(on[n]).Round(time.Millisecond))
	}
	began, lifted := slices.MinFunc(on, time.Time.Compare), slices.MaxFunc(off, time.Time.Compare)
	var before, after time.Time
	for _, r := range replies {
		if r.Before(began) {
			before = r
		} else if after.IsZero() && r.After(lifted) {
			after = r
		}
	}
	whole := lifted.Sub(began).Round(time.Millisecond)
	t.Logf("%s, a %v blackout under pings: held %v toward the devices, %v toward the servers, %v from the first add to the last del; replies stopped %v before it and came back %v after it lifted",
		k.transport, blackout, held[0], held[1], whole, began.Sub(before).Round(time.Millisecond), after.Sub(lifted).Round(time.Millisecond))
	for n, d := range held {
		if d < blackout || d > blackout+blackoutSlack {
			t.Fatalf("broken setup, not a liveness failure: the blackout on %s held %v, want %v to %v", ifaces[n], d, blackout, blackout+blackoutSlack)
		}
	}
	// The pings see the whole outage, from the first add to the last del.
	if whole > blackout+blackoutSlack {
		t.Fatalf("broken setup, not a liveness failure: the blackout held %v from the first add to the last del, want at most %v", whole, blackout+blackoutSlack)
	}
	for name, out := range map[string]string{"device-a": k.devUp.Output()[devFrom:], "server-1": k.serverUp.Output()[serverFrom:]} {
		if m := linkClosed.FindStringSubmatch(out); m != nil {
			t.Errorf("%s, a %v blackout under pings: %s closed its link (%q, last answer %s before)", k.transport, blackout, name, m[1], m[2])
		}
	}
	t.Logf("%s, a %v blackout under pings: %d of %d pings came back", k.transport, blackout, got, sent)
	if sent == 0 || got < sent*3/4 {
		t.Errorf("%s, a %v blackout under pings: %d of %d pings came back, want the blackout lost at most", k.transport, blackout, got, sent)
	}
}

// deadBothWays: a blackhole both ways under the pings, where each end
// finds the link dead within the busy bound of its last answer (S + R + T,
// 4.5 s; the V1 rule took up to 6.5 s).
func deadBothWays(t *testing.T, k *livenessLink) {
	t.Helper()
	wait := k.pingFor(t, 12*time.Second)
	time.Sleep(3 * time.Second)
	devFrom, serverFrom := len(k.devUp.Output()), len(k.serverUp.Output())
	cut := time.Now()
	lift := k.blackhole(t, true)
	devAfter, devWhy := closed(t, k.devUp, "device-a", devFrom, v1Bound+10*time.Second)
	devSeen := time.Since(cut)
	serverAfter, serverWhy := closed(t, k.serverUp, "server-1", serverFrom, v1Bound+10*time.Second)
	t.Logf("%s, cut both ways under pings: device-a closed its link %v after its last answer (%q), seen %v after the cut; server-1 %v after its last answer (%q)",
		k.transport, devAfter, devWhy, devSeen.Round(time.Millisecond), serverAfter, serverWhy)
	checkBusyBound(t, k.transport+", cut both ways", "device-a", devAfter, 0)
	checkBusyBound(t, k.transport+", cut both ways", "server-1", serverAfter, 0)
	lift()
	wait()
	waitStatus(t, k.dev, linkUp)
}

// deadOneWay: device-a streams to server-1, which sends nothing of its own
// back (a sink); server-1's way is cut, so server-1 is the receive-only end
// whose sending side broke. device-a, the sender, finds the link dead
// within the busy bound; server-1 hears device-a's close notice a trip
// after device-a's close on udp. On reality it can't: device-a's TCP
// stalls without server-1's acknowledgements and the notice waits behind
// the stream, so server-1 has its own frames' deadlines, or none (it
// sends only what expects no answer), and then the idle bound.
func deadOneWay(t *testing.T, k *livenessLink) {
	t.Helper()
	k.server.Start(t, "socat", "-u", "UDP-RECV:9999", "OPEN:/dev/null")
	streamCtx, stop := context.WithCancel(context.Background())
	defer stop()
	// Unconnected (UDP-SENDTO): an ICMP error back doesn't stop it.
	go func() {
		_, _ = k.dev.Exec(streamCtx, "timeout", "30", "sh", "-c", "while :; do echo stream; sleep 0.02; done | socat -u - UDP-SENDTO:"+k.target.String()+":9999")
	}()
	time.Sleep(2 * time.Second)
	if n := k.pathSentIn(t, time.Second); n < 20 {
		t.Fatalf("device-a's one-way stream isn't flowing: %d packets sent in 1 s", n)
	}
	devFrom, serverFrom := len(k.devUp.Output()), len(k.serverUp.Output())
	lift := k.blackhole(t, false)
	defer lift()
	devAfter, devWhy := closed(t, k.devUp, "device-a", devFrom, v1Bound+10*time.Second)
	serverAfter, serverWhy := closed(t, k.serverUp, "server-1", serverFrom, idleBound[k.transport]+loadSlack+10*time.Second)
	t.Logf("%s, cut from server-1 under device-a's one-way stream: device-a closed its link %v after its last answer (%q); server-1 %v after its last answer (%q)",
		k.transport, devAfter, devWhy, serverAfter, serverWhy)
	what := k.transport + ", one-way stream, cut from server-1"
	checkBusyBound(t, what, "device-a", devAfter, 0)
	if k.transport == "udp" {
		checkBusyBound(t, what, "server-1, the receive-only end,", serverAfter, labTrip)
		return
	}
	if bound := idleBound[k.transport]; serverAfter > bound+loadSlack {
		t.Errorf("%s: server-1, the receive-only end, closed its link %v after its last answer, want within %v (the idle bound) and the load's slack", what, serverAfter, bound)
	}
}

// checkBusyBound fails the test when a node took longer than the busy
// bound (4.5 s), the load's slack and extra (a notice's trip) to find a
// link under traffic dead, measured from its last answer.
func checkBusyBound(t *testing.T, what, node string, after, extra time.Duration) {
	t.Helper()
	if bound := busyBound + extra; after > bound+loadSlack {
		t.Errorf("%s: %s closed its link %v after its last answer, want within %v (the busy bound) and the load's slack %v (the V1 rule took up to %v)", what, node, after, bound, loadSlack, v1Bound)
	}
}

// TestIdleLinksProbeAtRandom (long stream: it holds links idle for
// minutes): an idle link over reality and over udp exchanges one probe and
// its reply at intervals within the transport's idle range (8 to 24 s, 5
// to 14 s; the earlier of the two ends' draws), spread rather than at a
// fixed rhythm (idleIntervals of them); then a blackhole both ways is
// found within the idle bound (I's top and T: 26 s, 16 s) of each end's
// last answer.
func TestIdleLinksProbeAtRandom(t *testing.T) {
	lab.LongTest(t)
	t.Parallel()
	for _, transport := range []string{"reality", "udp"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			k := upLink(t, transport, everyPacket)
			r, n := idleRange[transport], idleIntervals[transport]
			// n intervals take about n times the earlier of two draws on
			// average (13.3 s on reality, 8 s on udp); the wait gives them
			// over seven standard deviations more.
			wait := map[string]time.Duration{"reality": 7 * time.Minute, "udp": 6 * time.Minute}[transport]
			var gaps []time.Duration
			lab.Eventually(t, wait, func() error {
				gaps = idleGaps(k.capture.Packets())
				if len(gaps) < n {
					return fmt.Errorf("%d idle intervals so far, want %d", len(gaps), n)
				}
				return nil
			})
			gaps = gaps[:n]
			lo, hi := slices.Min(gaps), slices.Max(gaps)
			alike := 0
			for i := 1; i < len(gaps); i++ {
				if d := gaps[i] - gaps[i-1]; d > -time.Second && d < time.Second {
					alike++
				}
			}
			var shown []string
			for _, g := range gaps {
				shown = append(shown, g.Round(10*time.Millisecond).String())
			}
			t.Logf("%s idle: %d intervals from %v to %v, %d of %d consecutive pairs within 1 s of each other: %s",
				transport, n, lo.Round(10*time.Millisecond), hi.Round(10*time.Millisecond), alike, n-1, strings.Join(shown, " "))
			// An end probes no sooner than I's bottom after its last
			// answer, the far end's probe or its own reply, and the
			// earlier end no later than I's top.
			for _, g := range gaps {
				if g < r[0]-100*time.Millisecond || g > r[1]+loadSlack {
					t.Errorf("%s: an idle exchange %v after the one before, want %v to %v", transport, g, r[0], r[1])
				}
			}
			// Spread: all n within 3 s of each other would be a fixed
			// rhythm (idleIntervals has the chance of it by draws).
			if hi-lo < 3*time.Second {
				t.Errorf("%s: %d idle intervals within %v of each other: a fixed rhythm", transport, n, hi-lo)
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
