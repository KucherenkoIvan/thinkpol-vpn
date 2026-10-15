package wg

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

type fakePeer string

func (p fakePeer) String() string { return string(p) }

// At info level a log shows a peer's handshake timing out and the
// handshake that ended it; WireGuard's retries in between, routine
// handshakes and keepalives stay at debug.
func TestHandshakeTimeoutsAreLoggedAtInfoLevel(t *testing.T) {
	var out bytes.Buffer
	h := &handshakeLog{log: slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})), late: make(map[string]bool)}
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

// A peer the map takes away while its handshake keeps failing leaves the
// log's memory with it.
func TestRemovedPeersAreForgotten(t *testing.T) {
	h := &handshakeLog{log: slog.New(slog.DiscardHandler), late: make(map[string]bool)}
	var kept, removed netmap.WireGuardKey
	kept[0], removed[0] = 1, 2
	for _, k := range []netmap.WireGuardKey{kept, removed} {
		h.verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", fakePeer(peerName(k)), 5, 2)
	}
	h.keep(map[netmap.WireGuardKey]Peer{kept: {}})
	if len(h.late) != 1 || !h.late[peerName(kept)] {
		t.Errorf("late %v", h.late)
	}
}
