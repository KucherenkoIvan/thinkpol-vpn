package censor

import "time"

// Throttle's defaults: about 14 kbit/s, what whitelisting censors leave
// unlisted traffic (docs/design/lab.md), and two full segments at once.
const (
	defaultRate  = 1750
	defaultBurst = 3000
)

// rule is a verdict as the engine applies it: a module's Decision, a
// pinned flow verdict or an active module's flag.
type rule struct {
	verdict     Verdict
	rate, burst int // Throttle's
	module, why string
}

func ruleOf(d Decision, module string) rule {
	return rule{verdict: d.Verdict, rate: d.Rate, burst: d.Burst, module: module, why: d.Reason}
}

// severity orders the verdicts for composition: a flow's verdict is only
// ever replaced by a more severe one, and only the most severe (2) ends
// the module walk.
func (r rule) severity() int {
	switch r.verdict {
	case Drop, Reset:
		return 2
	case Throttle:
		return 1
	}
	return 0
}

// ruleKey is what a verdict log decision entry is about: a flow logs a
// new entry only when it changes.
type ruleKey struct {
	verdict Verdict
	module  string
}

// tokenBucket polices a throttled flow. A packet passes while the bucket
// isn't empty, and its bytes may take it below zero: a segment larger than
// the burst still gets through, and the debt holds the flow to the rate
// on average.
type tokenBucket struct {
	rate, burst int
	tokens      float64
	at          time.Time
}

func newTokenBucket(rate, burst int, now time.Time) *tokenBucket {
	if rate <= 0 {
		rate = defaultRate
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	return &tokenBucket{rate: rate, burst: burst, tokens: float64(burst), at: now}
}

// pass reports whether a packet of n payload bytes is within the rate,
// and takes its bytes if so. A packet without payload (a SYN, an ACK)
// always passes: the policer slows the data, not the connection's
// signalling.
func (b *tokenBucket) pass(n int, now time.Time) bool {
	if n == 0 {
		return true
	}
	if dt := now.Sub(b.at); dt > 0 {
		b.tokens = min(float64(b.burst), b.tokens+dt.Seconds()*float64(b.rate))
		b.at = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens -= float64(n)
	return true
}
