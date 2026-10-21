package routetable

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

const (
	// warnEvery: a failure that keeps coming back (each retried every
	// RetryAfter) is warned at most once a minute; the failures in between
	// are counted, not kept silent: said with the next warn of the same
	// text, or, for a text that didn't come back within the window, with
	// the next warn of any text.
	warnEvery = time.Minute
	// warnTexts caps the distinct failures one site warns a minute: two
	// that alternate warn once each, and a text that changes on every
	// retry (a count in it) can't warn on every retry.
	warnTexts = 4
)

// warnLimit limits the warns of one site's failures: in each window of
// warnEvery, allow lets through each distinct text once, up to warnTexts
// of them, and counts the others; reset starts over once the failure has
// cleared. It has no lock: each site's warns come from one goroutine at
// a time (applyGuard's under e.mu, the rest from Enforce while the
// watcher is paused or from the watcher).
type warnLimit struct {
	window time.Time       // when the current window began; zero: none
	said   map[string]bool // the texts warned in it
	// heldBack counts, per text (at most warnTexts of them), the warns of
	// it held back since its last; others counts the rest: texts past
	// that, and those a window ended without warning. The next warn of
	// any text says others.
	heldBack map[string]int
	others   int
}

// allow reports whether a warn saying text at now goes out, and then how
// many warns were held back since: of that text, and of others; a warn
// held back is counted.
func (l *warnLimit) allow(now time.Time, text string) (ok bool, heldBack, others int) {
	if l.window.IsZero() || now.Sub(l.window) >= warnEvery {
		l.roll(now)
	}
	if l.said[text] || len(l.said) >= warnTexts {
		l.holdBack(text)
		return false, 0, 0
	}
	l.said[text] = true
	heldBack = l.heldBack[text]
	delete(l.heldBack, text)
	others, l.others = l.others, 0
	return true, heldBack, others
}

// roll starts a window at now. The counts of texts the ending window
// didn't warn go to others: such a text may never come back (a count in
// it that changes every retry), and its count must still be said.
func (l *warnLimit) roll(now time.Time) {
	for text, n := range l.heldBack {
		if !l.said[text] {
			l.others += n
			delete(l.heldBack, text)
		}
	}
	l.window, l.said = now, map[string]bool{}
}

// holdBack counts a warn of text held back.
func (l *warnLimit) holdBack(text string) {
	if l.heldBack == nil {
		l.heldBack = map[string]int{}
	}
	if _, ok := l.heldBack[text]; !ok && len(l.heldBack) >= warnTexts {
		l.others++
		return
	}
	l.heldBack[text]++
}

// reset starts over, so the next failure warns at once, and returns how
// many warns were held back, of every text, since each one's last.
func (l *warnLimit) reset() int {
	n := l.others
	for _, c := range l.heldBack {
		n += c
	}
	*l = warnLimit{}
	return n
}

// warnRetry warns msg, a failure retried in RetryAfter, through l, with
// err's text, its addresses redacted (logs may leave the device).
func (e *Enforcer) warnRetry(l *warnLimit, msg string, err error) {
	text := path.RedactError(err)
	ok, heldBack, others := l.allow(e.now(), text)
	if !ok {
		return
	}
	args := []any{"in", RetryAfter}
	if heldBack > 0 {
		args = append(args, "suppressed", heldBack)
	}
	if others > 0 {
		args = append(args, "suppressed_other", others)
	}
	e.log.Warn(msg, append(args, "err", text)...)
}

// logCleared starts l over now that its failure is gone and, if warns of
// it were held back, says how many: once, with msg.
func (e *Enforcer) logCleared(l *warnLimit, msg string) {
	if n := l.reset(); n > 0 {
		e.log.Info(msg, "suppressed", n)
	}
}
