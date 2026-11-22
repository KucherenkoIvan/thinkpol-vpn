//go:build lab

package lab_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// idleHold is how long TestRealityIdleServerLeavesItsTarget watches an
// idle server: six of the agent's retries (agent.RetryAfter, 5 s, a wall
// clock constant the lab doesn't speed up).
const idleHold = 30 * time.Second

// TestRealityIdleServerLeavesItsTarget: a dual-stack reality server, its
// listeners derived from the map's endpoints (reality 0.0.0.0:443 and
// reality [::]:443, as the matrix's reality row serves them), with no
// client, dials its target only while it starts. Both listeners open, so
// the server's apply doesn't retry, and nothing it retries dials the
// target: before TP-230, [::]:443 couldn't bind next to 0.0.0.0:443's
// dual-stack socket, and every retry, every 5 s, made a TLS handshake with
// the target from the server's address.
func TestRealityIdleServerLeavesItsTarget(t *testing.T) {
	t.Parallel()
	l := censorPool.Acquire(t)
	server, site := l.Node(lab.Server1), l.Node(lab.Camouflage)
	camouflage := lab.StartCamouflage(t, l)
	space := newM0Space(t, site, server)
	space.spec = "/src/lab/maps/reality.yaml"
	space.env = append(space.env, "CAMOUFLAGE_IPV4="+camouflage[0].Addr().String())
	envelope, version := space.build(t)
	space.install(t, server, "server-1", envelope)
	up := startUp(t, server)
	if _, err := statusWithin(server, 60*time.Second, nil, mapApplied(version)); err != nil {
		t.Fatalf("server-1: %v\n%s", err, failedLines(up.Output()))
	}
	// The target is IPv4 (CAMOUFLAGE_IPV4): every connection to it opens
	// with a SYN this filter sees.
	dials := site.Capture(t, "tcp dst port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")
	logged := len(up.Output())
	deadline := time.Now().Add(idleHold)
	for time.Now().Before(deadline) {
		st, err := readStatus(server, pollTimeout)
		if err != nil {
			t.Fatalf("server-1's status: %v", err)
		}
		if st.Retrying {
			t.Errorf("server-1 retries its map %s while idle\n%s", st.MapVersion, failedLines(up.Output()))
			break
		}
		time.Sleep(5 * time.Second)
	}
	if syns := dials.Stop(); len(syns) > 0 {
		var from []string
		for _, p := range syns {
			from = append(from, fmt.Sprintf("%s %s", p.Time.Format("15:04:05.000"), p.Src))
		}
		t.Errorf("the target got %d connections from an idle server-1 within %v of its start-up: %s\n%s",
			len(syns), idleHold, strings.Join(from, ", "), failedLines(up.Output()))
	}
	if lines := failedLines(up.Output()[logged:]); lines != "" {
		t.Errorf("server-1 logged failures while idle:\n%s", lines)
	}
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
