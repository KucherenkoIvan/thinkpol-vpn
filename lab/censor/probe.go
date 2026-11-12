package censor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// answerKept is how much of a probe's answer the prober keeps to classify
// it (answerKind).
const answerKept = 64

// reaction is how a server answered one probe.
type reaction struct {
	// answer is the kind of bytes it sent back (see answerKind), end how
	// the connection ended: "closed", "reset", "open" (the probe's
	// timeout passed), or "no connection".
	answer, end string
	// read counts the bytes answered; first is when the first came, from
	// the dial on. Neither is compared: they are for the report.
	read  int
	first time.Duration
}

func (r reaction) like(o reaction) bool { return r.answer == o.answer && r.end == o.end }

func (r reaction) String() string {
	if r.read == 0 {
		return fmt.Sprintf("answered nothing, %s", r.end)
	}
	return fmt.Sprintf("answered %s (%d bytes, first after %s), %s", r.answer, r.read, r.first.Round(time.Millisecond/10), r.end)
}

// react sends one probe on a connection of its own and watches the
// answer until the server closes or resets it, or the timeout passes.
func (m *prober) react(ctx context.Context, addr netip.AddrPort, payload []byte) reaction {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	start := time.Now()
	c, err := m.dial(ctx, "tcp", addr.String())
	if err != nil {
		return reaction{answer: "nothing", end: "no connection"}
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	var r reaction
	if _, err := c.Write(payload); err != nil {
		r.end = connEnd(err)
	}
	var answer []byte
	buf := make([]byte, 4096)
	for r.end == "" {
		n, err := c.Read(buf)
		if n > 0 && r.read == 0 {
			r.first = time.Since(start)
		}
		r.read += n
		if room := answerKept - len(answer); room > 0 {
			answer = append(answer, buf[:min(n, room)]...)
		}
		if err != nil {
			r.end = connEnd(err)
		}
	}
	r.answer = answerKind(answer, payload)
	return r
}

// connEnd names how a connection ended from the error that ended it. A
// failure is named by its errno alone: the error's text holds the
// connection's addresses and ports, which differ between the server's and
// the reference's.
func connEnd(err error) string {
	var ne net.Error
	var errno syscall.Errno
	switch {
	case errors.Is(err, io.EOF):
		return "closed"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "open"
	case errors.As(err, &errno):
		return "failed: " + errno.Error()
	}
	return "failed"
}

// answerKind classifies the first bytes a server answered a probe with.
func answerKind(answer, probe []byte) string {
	switch {
	case len(answer) == 0:
		return "nothing"
	case len(answer) <= len(probe) && bytes.Equal(answer, probe[:len(answer)]):
		return "an echo"
	case len(answer) >= 2 && answer[0] == 0x15 && answer[1] == 3:
		return "a TLS alert"
	case len(answer) >= 2 && answer[0] == tlsHandshake && answer[1] == 3:
		return "a TLS handshake"
	case bytes.HasPrefix(answer, []byte("HTTP/")):
		return "an HTTP response"
	}
	return "other bytes"
}
