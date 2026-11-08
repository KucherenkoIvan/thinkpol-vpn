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
	if pending, last := h.of(kept); len(h.pending) != 1 || len(h.initiated) != 1 || pending.IsZero() || last.IsZero() {
		t.Errorf("pending %v, initiated %v", h.pending, h.initiated)
	}
}

// The last initiation moves with every one sent, while the pending time
// stays at the first unanswered one; a completed handshake clears only
// the pending time.
func TestTheLastInitiationMovesWithEachOne(t *testing.T) {
	h := newHandshakes(nil)
	var k netmap.WireGuardKey
	k[0] = 1
	h.verbosef("%v - Sending handshake initiation", fakePeer(peerName(k)))
	first, _ := h.of(k)
	time.Sleep(10 * time.Millisecond)
	h.verbosef("%v - Sending handshake initiation", fakePeer(peerName(k)))
	pending, last := h.of(k)
	if pending != first || !last.After(first) {
		t.Fatalf("pending %v (first %v), last initiation %v", pending, first, last)
	}
	h.verbosef("%v - Received handshake response", fakePeer(peerName(k)))
	if p, l := h.of(k); !p.IsZero() || l != last {
		t.Errorf("after the response: pending %v, last initiation %v (was %v)", p, l, last)
	}
}
