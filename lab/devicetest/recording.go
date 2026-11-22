//go:build darwin || linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// recording checks, before and after an ask's wait, that the run still
// records: no restore has run (the dead-man's, when the budget ran out or
// the helper died), and the capture, if the plan has one, still sees a
// marker (one, as the self-test's, sent again once if it isn't seen).
// Between asks nothing calls the helper, so without this check a run
// whose dead-man fired, or whose tcpdump stopped at its packet limit,
// would go on asking with nothing recorded. It returns "ok", or the line
// saying why not, printed (again at each later ask) and saved in
// recording-stopped.txt the first time.
func (r *runner) recording(ctx context.Context) string {
	if r.notRecording == "" {
		why, at := r.probe(ctx)
		if why == "" {
			return "ok"
		}
		what := "THE RUN STOPPED"
		if r.capIface != "" {
			what = "THE CAPTURE STOPPED"
		}
		r.notRecording = fmt.Sprintf("%s at %s: %s; what you do now isn't recorded", what, at.Local().Format("15:04:05"), why)
		r.ev.WriteFile("recording-stopped.txt", fmt.Appendf(nil, "%s (found %s)\n", r.notRecording, time.Now().UTC().Format(time.RFC3339)))
	}
	r.ev.Logf("%s", r.notRecording)
	return r.notRecording
}

// probe says why the run no longer records, and since when, or "".
func (r *runner) probe(ctx context.Context) (string, time.Time) {
	if res, at, ok := r.newestResult(); ok {
		return fmt.Sprintf("the run was restored (%s) by %s", res.Verdict, res.By), at
	}
	if r.capIface == "" {
		return "", time.Time{}
	}
	seen, sendErr, callErr := r.markerSeen(ctx)
	switch {
	case sendErr != nil:
		r.ev.Logf("the capture can't be checked now: %v", sendErr)
		return "", time.Time{}
	case callErr != nil:
		return fmt.Sprintf("the helper doesn't answer (%v): its dead-man restores the run", callErr), time.Now()
	case !seen:
		return r.captureEnded()
	}
	return "", time.Time{}
}

// markerSeen sends a marker on the capture's interface, from a port the
// self-test's filter lets through, and asks the helper whether the
// capture saw it (a capture that ended answers at once).
func (r *runner) markerSeen(ctx context.Context) (seen bool, sendErr, callErr error) {
	bcast, a, b, err := markerSockets(ctx, r.capIface)
	if err != nil {
		return false, err, nil
	}
	defer func() { _ = a.Close(); _ = b.Close() }()
	conn := a
	if a.LocalAddr().(*net.UDPAddr).Port == r.negPort {
		conn = b
	}
	res := &captureCheck{Iface: r.capIface}
	for try := 0; try < 2 && !seen; try++ {
		n := nonce()
		if err := r.sendMarker(conn, bcast, res, n, "check"); err != nil {
			return false, err, nil
		}
		resp, err := r.c.call(safety.Request{Op: safety.OpCaptureSeen, Iface: r.capIface, Nonce: n, TimeoutMS: 2000})
		if err != nil {
			return false, nil, err
		}
		seen = resp.Seen
	}
	return seen, nil, nil
}

// captureEnded says why a capture missed its marker: tcpdump's own last
// words, when it has ended (it prints its packet counts as it exits, at
// its packet limit too), with the time it wrote them; else that it sees
// nothing, as of now.
func (r *runner) captureEnded() (string, time.Time) {
	name := filepath.Join(r.ev.Path, "captures", r.capIface+".tcpdump.err")
	if f, err := os.Open(name); err == nil {
		defer func() { _ = f.Close() }()
		var counts []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "packets ") {
				counts = append(counts, strings.TrimSpace(sc.Text()))
			}
		}
		if fi, err := f.Stat(); err == nil && len(counts) > 0 {
			return fmt.Sprintf("tcpdump on %s ended (%s)", r.capIface, strings.Join(counts, "; ")), fi.ModTime()
		}
	}
	return fmt.Sprintf("a marker sent on %s wasn't captured (2 tries): the capture sees nothing", r.capIface), time.Now()
}

// budgetLeft says how much of the dead-man's budget is left.
func (r *runner) budgetLeft() string {
	left := time.Until(r.deadline)
	if left <= 0 {
		return fmt.Sprintf("the budget ran out at %s: the dead-man restores the run", r.deadline.Local().Format("15:04:05"))
	}
	return fmt.Sprintf("budget: %v left", left.Round(time.Second))
}
