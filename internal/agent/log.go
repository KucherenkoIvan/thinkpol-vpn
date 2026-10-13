package agent

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/KucherenkoIvan/go-kernel/observability"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// LogRingSize bounds the agent's in-memory log.
const LogRingSize = 256 << 10

// LogService is the service attribute on every line of the agent's log.
const LogService = "thinkpol"

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
	// The level is the node's own setting, never go-kernel's LOG_LEVEL.
	logger, err := observability.NewLoggerWith(LogService, observability.Options{Writer: out, Level: lvl, Format: "text"})
	if err != nil {
		return Logs{}, err
	}
	return Logs{Logger: logger, Ring: ring, out: out}, nil
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

// Sanitize returns s with nothing left in it that acts on a terminal or a
// log viewer (see appendSanitized), for rendering text that came from
// elsewhere: a worker's output, or anything a local API client received.
func Sanitize(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c >= 0x7f {
			return string(appendSanitized(make([]byte, 0, len(s)+8), []byte(s)))
		}
	}
	return s
}

// appendSanitized appends a space's bytes so that nothing in them acts on
// a terminal or a log viewer: invalid UTF-8 and C0 controls (but tab) as
// \xNN, DEL as \x7f, C1 controls and bidirectional overrides as \uNNNN.
func appendSanitized(dst, b []byte) []byte {
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && n <= 1, r < 0x20 && r != '\t', r == 0x7f:
			dst = append(dst, '\\', 'x', hexDigits[b[0]>>4], hexDigits[b[0]&0xf])
		case r >= 0x80 && r <= 0x9f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			dst = append(dst, '\\', 'u', hexDigits[r>>12&0xf], hexDigits[r>>8&0xf], hexDigits[r>>4&0xf], hexDigits[r&0xf])
		default:
			dst = append(dst, b[:n]...)
		}
		b = b[n:]
	}
	return dst
}

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
	line = appendSanitized(line, p.partial)
	line = append(line, '\n')
	p.partial = p.partial[:0]
	p.out.mu.Lock()
	_, _ = p.out.w.Write(line)
	p.out.mu.Unlock()
}
