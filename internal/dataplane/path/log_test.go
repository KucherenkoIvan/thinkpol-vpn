package path_test

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

// lockedBuffer is a log both nodes write to.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) lines(msg string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for line := range strings.Lines(l.b.String()) {
		if strings.Contains(line, "msg=\""+msg+"\"") {
			out = append(out, line)
		}
	}
	return out
}

// A drop explains itself in a log at info level: the link that went
// quiet closes with its reason and what it last heard, the redial's first
// failure says why (the rest are debug until a link comes up), and the
// link that comes back is logged.
func TestALinksLifeIsLoggedAtInfoLevel(t *testing.T) {
	var log lockedBuffer
	f := newFabric(t, memory.Datagram)
	f.opts.Log = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	f.add("A", "B")
	f.dial("A", "B")
	eventually(t, "the link up logged", func() bool { return len(log.lines("link up")) >= 1 })

	// The first dial may have raced B's table and gone unanswered: only
	// what follows the silence counts.
	before := len(log.lines("dial failed"))
	f.silence("A", "B", true)
	eventually(t, "A sees B down", func() bool { return !f.isUp("A", "B") })
	// Several redials go unanswered meanwhile.
	time.Sleep(4 * fastOptions.DeadAfter)
	var closed string // A's
	for _, l := range log.lines("link closed") {
		if strings.Contains(l, "neighbor="+hexID("B")) {
			closed = l
		}
	}
	for _, want := range []string{"reason=\"no answer to its probes within 150ms\"", "dialed=true", "was_up_for=", "last_in=", "last_proof="} {
		if !strings.Contains(closed, want) {
			t.Errorf("A's link closed line %q lacks %s", closed, want)
		}
	}
	failed := log.lines("dial failed")[before:]
	if len(failed) != 1 || !strings.Contains(failed[0], "failures=1") || !strings.Contains(failed[0], "no answer within 150ms") {
		t.Errorf("dial failed lines %q", failed)
	}

	f.silence("A", "B", false)
	f.waitUp("A", "B")
	eventually(t, "the link back up logged", func() bool {
		var dialed int
		for _, l := range log.lines("link up") {
			if strings.Contains(l, "dialed=true") {
				dialed++
			}
		}
		return dialed >= 2
	})
}
