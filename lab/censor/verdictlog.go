package censor

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// The verdict log's events.
const (
	// EventDecision is a flow's first packet's decision, and every later
	// one that changes the verdict or the module: a flow of a million
	// accepted packets is one line.
	EventDecision = "decision"
	// EventTag is a passive module tagging a flow for the active ones.
	EventTag = "tag"
	// EventFlag is an active module flagging a flow.
	EventFlag = "flag"
	// EventSummary is a flow's totals, one per flow when the censor stops.
	EventSummary = "summary"
)

// LogEntry is one line of the verdict log.
type LogEntry struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
	Flow  string    `json:"flow"`
	// Packets and Bytes are the flow's counts when the entry was written.
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Module  string `json:"module"`
	// Verdict is the flow's verdict: Throttle for a throttled flow, whose
	// packets are accepted or dropped by its policer.
	Verdict Verdict `json:"verdict"`
	// Rate is Throttle's, in bytes per second.
	Rate   int    `json:"rate,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Applied is a summary's: the flow's packets by what the queue did
	// with them (accept, drop, reset).
	Applied map[string]uint64 `json:"applied,omitempty"`
}

// flushEvery is how stale the log file may be behind the censor: tests
// poll it for a few seconds.
const flushEvery = 100 * time.Millisecond

// verdictLog writes the entries as JSONL through a buffer, flushed every
// flushEvery and on close, with no fsync: readers in the same machine see
// each line once flushed (a full buffer may write part of a line early:
// readers trust what precedes the last newline), and a write per packet
// would stall the queue.
type verdictLog struct {
	mu     sync.Mutex
	w      *bufio.Writer
	enc    *json.Encoder
	closed bool
	done   chan struct{}
}

func newVerdictLog(w io.Writer) *verdictLog {
	l := &verdictLog{w: bufio.NewWriterSize(w, 64<<10), done: make(chan struct{})}
	l.enc = json.NewEncoder(l.w)
	l.enc.SetEscapeHTML(false)
	go l.flusher()
	return l
}

func (l *verdictLog) flusher() {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			l.mu.Lock()
			_ = l.w.Flush()
			l.mu.Unlock()
		}
	}
}

// write adds an entry; after close it is written through at once.
func (l *verdictLog) write(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(entry)
	if l.closed {
		_ = l.w.Flush()
	}
}

func (l *verdictLog) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// close stops the flusher and flushes what is buffered.
func (l *verdictLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	close(l.done)
	_ = l.w.Flush()
}
