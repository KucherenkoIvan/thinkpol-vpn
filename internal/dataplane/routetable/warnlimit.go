package routetable

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

// warnEvery: a failure that keeps coming back (each retried every
// RetryAfter) is warned at most once a minute; the failures in between
// are counted and said with the next warn, not kept silent.
const warnEvery = time.Minute

// warnLimit limits the warns of one site's failure: allow lets one
// through per warnEvery, and any whose text differs from the last one
// warned, and counts the others; reset starts over once the failure has
// cleared. It has no lock: each site's warns come from one goroutine at
// a time (applyGuard's under e.mu, the rest from Enforce while the
// watcher is paused or from the watcher).
type warnLimit struct {
	last     time.Time // the last warn; zero: none since the reset
	lastText string    // what it said
	heldBack int
}

// allow reports whether a warn saying text at now goes out, and then how
// many were held back since the last one; a warn held back is counted.
func (l *warnLimit) allow(now time.Time, text string) (ok bool, heldBack int) {
	if !l.last.IsZero() && now.Sub(l.last) < warnEvery && text == l.lastText {
		l.heldBack++
		return false, 0
	}
	heldBack = l.heldBack
	l.last, l.lastText, l.heldBack = now, text, 0
	return true, heldBack
}

// reset starts over, so the next failure warns at once, and returns how
// many warns were held back since the last one.
func (l *warnLimit) reset() int {
	n := l.heldBack
	*l = warnLimit{}
	return n
}

// warnRetry warns msg, a failure retried in RetryAfter, through l, with
// err's text, its addresses redacted (logs may leave the device).
func (e *Enforcer) warnRetry(l *warnLimit, msg string, err error) {
	text := path.RedactError(err)
	ok, heldBack := l.allow(e.now(), text)
	if !ok {
		return
	}
	args := []any{"in", RetryAfter}
	if heldBack > 0 {
		args = append(args, "suppressed", heldBack)
	}
	e.log.Warn(msg, append(args, "err", text)...)
}

// logCleared starts l over now that its failure is gone and, if warns of
// it were held back since the last one, says how many: once, with msg.
func (e *Enforcer) logCleared(l *warnLimit, msg string) {
	if n := l.reset(); n > 0 {
		e.log.Info(msg, "suppressed", n)
	}
}
