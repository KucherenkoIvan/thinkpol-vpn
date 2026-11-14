package wg

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

type fakePeer string

func (p fakePeer) String() string { return string(p) }

// At info level a log shows a peer's handshake timing out and the
// handshake that ended it; WireGuard's retries in between, routine
// handshakes and keepalives stay at debug.
func TestHandshakeTimeoutsAreLoggedAtInfoLevel(t *testing.T) {
	var out bytes.Buffer
	h := newHandshakes(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})))
	a, b := fakePeer("peer(A)"), fakePeer("peer(B)")
	// WireGuard's own formats (device/timers.go, device/send.go).
	h.verbosef("%v - Received handshake response", a)
	h.verbosef("%v - Sending keepalive packet", a)
	h.verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", a, 15)
	h.verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", a, 5, 2)
	h.verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", a, 5, 3)
	h.verbosef("%v - Received handshake response", b) // another peer's routine one
	h.verbosef("%v - Received handshake response", a)
	h.verbosef("%v - Received handshake response", a) // routine again
	want := []string{
		"peer(A) - Retrying handshake because we stopped hearing back after 15 seconds",
		"peer(A) - Received handshake response",
	}
	var got []string
	for line := range strings.Lines(out.String()) {
		if !strings.Contains(line, "level=INFO") {
			t.Errorf("not at info: %s", line)
		}
		_, msg, _ := strings.Cut(strings.TrimSpace(line), "msg=")
		got = append(got, strings.Trim(msg, `"`))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("logged:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A peer WireGuard removes while its handshake keeps failing leaves no
// trace behind.
func TestRemovedPeersAreForgotten(t *testing.T) {
	h := newHandshakes(nil)
	var kept, removed netmap.WireGuardKey
	kept[0], removed[0] = 1, 2
	for _, k := range []netmap.WireGuardKey{kept, removed} {
		h.verbosef("%v - Sending handshake initiation", fakePeer(peerName(k)))
		h.verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", fakePeer(peerName(k)), 5, 2)
	}
	h.forget([]netmap.WireGuardKey{removed})
	if len(h.late) != 1 || !h.late[peerName(kept)] {
		t.Errorf("late %v", h.late)
	}
	if len(h.unanswered) != 1 || h.pendingSince(kept).IsZero() {
		t.Errorf("unanswered %v", h.unanswered)
	}
}

// A peer pending from before some moment (its link coming back) is graded
// from the first initiation since: none while WireGuard sends nothing,
// then the next one, at WireGuard's own pace. A completed handshake clears
// them all.
func TestTheFirstInitiationSinceAMomentSkipsOnesBeforeIt(t *testing.T) {
	h := newHandshakes(nil)
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return clock }
	var k netmap.WireGuardKey
	k[0] = 1
	initiate := func(after time.Duration) time.Time {
		clock = clock.Add(after)
		h.verbosef("%v - Sending handshake initiation", fakePeer(peerName(k)))
		return clock
	}
	first := initiate(0)
	retry := initiate(RekeyTimeout)
	linkUp := retry.Add(time.Second)
	if got := h.firstSince(k, linkUp); !got.IsZero() {
		t.Fatalf("nothing sent since the link came up, got %v", got)
	}
	// WireGuard gave up; traffic resumes long after the link came back.
	next := initiate(time.Minute)
	if got := h.firstSince(k, linkUp); got != next {
		t.Errorf("since the link came up: %v, want %v", got, next)
	}
	initiate(RekeyTimeout)
	if got := h.firstSince(k, linkUp); got != next {
		t.Errorf("since the link came up, after a retry: %v, want %v", got, next)
	}
	if got := h.firstSince(k, first); got != first || h.pendingSince(k) != first {
		t.Errorf("since the first: %v, pending since %v, want %v", got, h.pendingSince(k), first)
	}
	h.verbosef("%v - Received handshake response", fakePeer(peerName(k)))
	if got := h.firstSince(k, first); !got.IsZero() || !h.pendingSince(k).IsZero() {
		t.Errorf("after the response: %v, pending since %v", got, h.pendingSince(k))
	}
}

// A peer WireGuard keeps retrying for long keeps its first initiation and
// the latest ones: a moment among those dropped gets the oldest kept,
// over 70 s old like the true one.
func TestAPeerRetriedForLongKeepsItsFirstAndLatestInitiations(t *testing.T) {
	h := newHandshakes(nil)
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return clock }
	var k netmap.WireGuardKey
	k[0] = 1
	var sent []time.Time
	for range 100 {
		h.verbosef("%v - Sending handshake initiation", fakePeer(peerName(k)))
		sent = append(sent, clock)
		clock = clock.Add(RekeyTimeout)
	}
	last := sent[len(sent)-1]
	if got := h.pendingSince(k); got != sent[0] {
		t.Errorf("pending since %v, want the first, %v", got, sent[0])
	}
	if got := h.firstSince(k, sent[90].Add(-time.Second)); got != sent[90] {
		t.Errorf("among the latest: %v, want %v", got, sent[90])
	}
	got := h.firstSince(k, sent[10].Add(-time.Second))
	if got.Before(sent[10]) || last.Sub(got) < 70*time.Second {
		t.Errorf("among those dropped: %v, want one from %v on and 70 s before the last, %v", got, sent[10], last)
	}
	if n := len(h.unanswered[peerName(k)]); n != keptInitiations {
		t.Errorf("%d kept", n)
	}
}
