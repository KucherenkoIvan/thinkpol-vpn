package agent

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// LogRingSize bounds the agent's in-memory log.
const LogRingSize = 256 << 10

// Logs are where a node's agent logs: text lines to the process's stderr
// and to an in-memory ring, never to a file (PRD S2; under systemd stderr
// is the journal, which provisioning makes volatile). The ring is what the
// local API serves (TP-022).
type Logs struct {
	*slog.Logger
	Ring *logring.Ring
	// out is where the logger writes: stderr and Ring.
	out io.Writer
}

// NewLogs returns the agent's logs at level, writing to stderr.
func NewLogs(level string, stderr io.Writer) (Logs, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return Logs{}, err
	}
	ring := logring.New(LogRingSize)
	out := io.MultiWriter(stderr, ring)
	h := slog.NewTextHandler(out, &slog.HandlerOptions{Level: lvl})
	return Logs{Logger: slog.New(h), Ring: ring, out: out}, nil
}

// ParseLevel parses debug, info, warn or error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log level %q: want debug, info, warn or error", s)
}

// workerOutput copies each worker's output to w, line by line, each line
// prefixed with its space, so the workers' logs show up in the node's own
// log stream next to the supervisor's.
type workerOutput struct {
	mu sync.Mutex // one whole line at a time to w
	w  io.Writer
}

func (o *workerOutput) forSpace(space netmap.SpaceID) io.Writer {
	return &prefixedLines{out: o, prefix: "worker space=" + space.String() + " "}
}

const hexDigits = "0123456789abcdef"

// prefixedLines buffers a worker's partial line until it ends; a line
// longer than logring.MaxLine is cut there.
type prefixedLines struct {
	out     *workerOutput
	prefix  string
	partial []byte
}

func (p *prefixedLines) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.partial = append(p.partial, b...)
			if len(p.partial) >= logring.MaxLine {
				p.flush()
			}
			break
		}
		p.partial = append(p.partial, b[:i]...)
		b = b[i+1:]
		p.flush()
	}
	return n, nil
}

func (p *prefixedLines) flush() {
	line := make([]byte, 0, len(p.prefix)+len(p.partial)+1)
	line = append(line, p.prefix...)
	// The space's bytes never reach a terminal or a log viewer as control
	// sequences.
	for _, c := range p.partial {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			line = append(line, '\\', 'x', hexDigits[c>>4], hexDigits[c&0xf])
			continue
		}
		line = append(line, c)
	}
	line = append(line, '\n')
	p.partial = p.partial[:0]
	p.out.mu.Lock()
	_, _ = p.out.w.Write(line)
	p.out.mu.Unlock()
}
