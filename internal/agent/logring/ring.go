// Package logring keeps an agent's logs in memory only (PRD S2): a bounded
// ring of lines, oldest dropped first, gone when the process exits.
package logring

import (
	"bytes"
	"strings"
	"sync"
)

// Ring is a bounded in-memory log. It is an io.Writer that splits what is
// written into lines, so slog handlers and a child process's output can
// write to it directly. Safe for concurrent use.
//
// Lines are kept in a slice used as a ring: head is the oldest live line,
// and dropping the oldest only advances head, so a flood of lines is
// amortised O(1) per line; the backing slice is compacted only when the
// dead prefix grows past the live part.
type Ring struct {
	mu      sync.Mutex
	max     int      // bytes of live lines kept, newlines included
	lines   []string // ring; live range is [head:]
	head    int
	size    int    // bytes of the live lines
	partial []byte // an unfinished last line, not yet counted in size
	dropped uint64
}

// MaxLine bounds one line; a longer one is cut there and continues on the
// next line, so a writer without newlines can't grow the ring past its size.
const MaxLine = 4096

// New returns a ring that keeps at most maxBytes of log lines.
func New(maxBytes int) *Ring {
	return &Ring{max: max(maxBytes, MaxLine)}
}

// Write appends p, line by line. It never fails.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			room := MaxLine - len(r.partial)
			if len(p) < room {
				r.partial = append(r.partial, p...)
				break
			}
			r.partial = append(r.partial, p[:room]...)
			p = p[room:]
			r.flushPartial()
			continue
		}
		line := p[:i]
		p = p[i+1:]
		for len(r.partial)+len(line) > MaxLine {
			room := MaxLine - len(r.partial)
			r.partial = append(r.partial, line[:room]...)
			line = line[room:]
			r.flushPartial()
		}
		r.partial = append(r.partial, line...)
		r.flushPartial()
	}
	return n, nil
}

func (r *Ring) flushPartial() {
	r.push(string(r.partial))
	r.partial = r.partial[:0]
}

func (r *Ring) push(line string) {
	r.lines = append(r.lines, line)
	r.size += len(line) + 1
	for r.size > r.max && r.head < len(r.lines)-1 {
		r.size -= len(r.lines[r.head]) + 1
		r.lines[r.head] = "" // let the string be collected
		r.head++
		r.dropped++
	}
	// Compact once the dead prefix is at least as large as what is live, so
	// the backing slice can't grow without bound.
	if r.head > len(r.lines)-r.head {
		r.lines = append(r.lines[:0], r.lines[r.head:]...)
		r.head = 0
	}
}

// Lines returns the kept lines, oldest first, including an unfinished last
// line.
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	live := r.lines[r.head:]
	out := make([]string, len(live), len(live)+1)
	copy(out, live)
	if len(r.partial) > 0 {
		out = append(out, string(r.partial))
	}
	return out
}

// String returns the kept lines joined by newlines.
func (r *Ring) String() string { return strings.Join(r.Lines(), "\n") }

// Dropped is how many lines were dropped to stay within the size.
func (r *Ring) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
