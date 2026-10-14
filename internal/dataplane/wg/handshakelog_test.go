package wg

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

type fakePeer string

func (p fakePeer) String() string { return string(p) }

// At info level a log shows a peer's handshake timing out, WireGuard's
// retries, and the handshake that ended it; routine handshakes and
// keepalives stay at debug.
func TestHandshakeTimeoutsAreLoggedAtInfoLevel(t *testing.T) {
	var out bytes.Buffer
	h := &handshakeLog{log: slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})), late: make(map[string]bool)}
	a, b := fakePeer("peer(A)"), fakePeer("peer(B)")
	// WireGuard's own formats (device/timers.go, device/send.go).
	h.verbosef("%v - Received handshake response", a)
	h.verbosef("%v - Sending keepalive packet", a)
	h.verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", a, 15)
	h.verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", a, 5, 2)
	h.verbosef("%v - Received handshake response", b) // another peer's routine one
	h.verbosef("%v - Received handshake response", a)
	h.verbosef("%v - Received handshake response", a) // routine again
	want := []string{
		"peer(A) - Retrying handshake because we stopped hearing back after 15 seconds",
		"peer(A) - Handshake did not complete after 5 seconds, retrying (try 2)",
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
