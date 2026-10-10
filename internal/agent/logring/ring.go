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
type Ring struct {
	mu      sync.Mutex
	max     int      // bytes of lines kept, newlines included
	lines   []string // oldest first
	size    int
	partial []byte // an unfinished last line
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
	drop := 0
	for r.size > r.max {
		r.size -= len(r.lines[drop]) + 1
		drop++
	}
	if drop > 0 {
		r.dropped += uint64(drop)
		// Copy the survivors down so the dropped lines can be collected.
		r.lines = append(r.lines[:0], r.lines[drop:]...)
	}
}

// Lines returns the kept lines, oldest first, including an unfinished last
// line.
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines), len(r.lines)+1)
	copy(out, r.lines)
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
