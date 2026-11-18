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
	// EventDecision is the first packet of a flow to get a verdict from a
	// module (Accept from none included, or from the first module that gave
	// a reason for it): a flow has at most one per verdict and module,
	// however many packets, or however often its packets alternate between
	// them.
	EventDecision = "decision"
	// EventTag is a passive module tagging a flow for the active ones.
	EventTag = "tag"
	// EventFlag is an active module flagging a flow.
	EventFlag = "flag"
	// EventIgnore is the first packet of a flow whose payload the censor
	// kept out of the flow's stream (or first datagram) for a reason, the
	// receiver discarding it: once per flow and reason.
	EventIgnore = "ignore"
	// EventUnnoticed is a snapshot (a new flow, Module empty, or a tag by
	// Module) an active module had no room for ([Engine.Unnoticed]).
	EventUnnoticed = "unnoticed"
	// EventSummary is a flow's totals, one per flow when it starts over
	// ([Engine.Handle]) or the censor stops.
	EventSummary = "summary"
	// EventWatermark says every packet the queue handed the censor up to
	// Through (the kernel's packet id, [QueueStats.Sequence]) has been
	// decided, its entries on the lines before this one. It is written at
	// a flush, when the queue has moved since the last one: a reader that
	// finds one at or past the id_sequence it read has every passive
	// decision on those packets. An active module's flag comes on its
	// own time, after the watermark or before.
	EventWatermark = "watermark"
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
	// Ignored is a summary's: the flow's packets whose payload the censor
	// kept out, by why (EventIgnore).
	Ignored map[string]uint64 `json:"ignored,omitempty"`
	// Through is a watermark's (EventWatermark): the last packet id
	// decided.
	Through uint64 `json:"through,omitempty"`
}

// flushEvery is how stale the log file may be behind the censor: tests
// wait for its watermark (EventWatermark).
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
	// decided is the last packet id decided (handled), marked the last
	// one a watermark was written for.
	decided, marked uint64
	now             func() time.Time
}

func newVerdictLog(w io.Writer) *verdictLog {
	l := openVerdictLog(w)
	go l.flusher()
	return l
}

// openVerdictLog is the log without its flusher.
func openVerdictLog(w io.Writer) *verdictLog {
	l := &verdictLog{w: bufio.NewWriterSize(w, 64<<10), done: make(chan struct{}), now: time.Now}
	l.enc = json.NewEncoder(l.w)
	l.enc.SetEscapeHTML(false)
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
			l.flush()
		}
	}
}

// flush writes a watermark when packets were decided since the last one,
// then the buffer.
func (l *verdictLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.watermark()
	_ = l.w.Flush()
}

// watermark writes EventWatermark through the last packet decided, unless
// one is written already. l.mu is held.
func (l *verdictLog) watermark() {
	if l.decided == l.marked {
		return
	}
	_ = l.enc.Encode(LogEntry{Time: l.now(), Event: EventWatermark, Through: l.decided})
	l.marked = l.decided
}

// handled records that the queue's packet id has been decided: its
// entries are written already, so the next watermark may cover it.
func (l *verdictLog) handled(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.decided = id
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
	l.watermark()
	_ = l.w.Flush()
}
