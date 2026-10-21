package routetable

import (
	"sync"
	"time"
)

// warnEvery: a failure that keeps coming back (each retried every
// RetryAfter) is warned at most once a minute; the failures in between
// are counted and said with the next warn, not kept silent.
const warnEvery = time.Minute

// warnLimit limits the warns of one failure: allow lets one through per
// warnEvery and counts the others, reset starts over once the failure
// has cleared.
type warnLimit struct {
	mu         sync.Mutex
	last       time.Time // the last warn; zero: none since the reset
	suppressed int
}

// allow reports whether a warn at now goes out, and then how many were
// held back since the last one; a warn held back is counted.
func (l *warnLimit) allow(now time.Time) (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < warnEvery {
		l.suppressed++
		return false, 0
	}
	suppressed = l.suppressed
	l.last, l.suppressed = now, 0
	return true, suppressed
}

// reset starts over, so the next failure warns at once, and returns how
// many warns were held back since the last one.
func (l *warnLimit) reset() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.suppressed
	l.last, l.suppressed = time.Time{}, 0
	return n
}

// warnRetry warns msg, a failure retried in RetryAfter, through l; err
// is what went wrong.
func (e *Enforcer) warnRetry(l *warnLimit, msg, err string) {
	ok, suppressed := l.allow(e.now())
	if !ok {
		return
	}
	args := []any{"in", RetryAfter}
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	e.log.Warn(msg, append(args, "err", err)...)
}

// cleared starts l over now that its failure is gone and, if warns of it
// were held back since the last one, says how many: once, with msg.
func (e *Enforcer) cleared(l *warnLimit, msg string) {
	if n := l.reset(); n > 0 {
		e.log.Info(msg, "suppressed", n)
	}
}
