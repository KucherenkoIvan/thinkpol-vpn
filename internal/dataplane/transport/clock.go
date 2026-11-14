package transport

import "time"

// MaxClockSkew is how far nodes' clocks may disagree, and so how far a
// send time a transport seals may be from the receiver's clock and still
// be fresh: the window a captured message can be replayed in at all, and
// what a transport's replay memory must cover.
const MaxClockSkew = 5 * time.Minute

// FreshUnix reports whether a message sealed at sent, uint32 Unix seconds,
// could still be fresh at now: within MaxClockSkew either way. uint32
// seconds wrap in 2106; the distance is taken mod 2^32 and read as signed,
// so it holds across the wrap (for any skew under 68 years).
func FreshUnix(sent uint32, now time.Time) bool { return FreshWithin(sent, now, MaxClockSkew) }

// FreshWithin is FreshUnix for a transport whose window is narrower than
// MaxClockSkew.
func FreshWithin(sent uint32, now time.Time, window time.Duration) bool {
	d := time.Duration(int32(uint32(now.Unix())-sent)) * time.Second
	return d <= window && d >= -window
}

// StartRule is a receiver's start rule: one whose memory of what it
// admitted is per process, and starts empty, refuses what was sealed
// before the Unix second it started in, which could be a passive tap's
// replays of what its predecessor took. The zero StartRule refuses
// nothing. udp's doc.go, "What a receiver accepts", says why the start's
// own second is taken and how a wall clock step is handled.
type StartRule struct {
	at      time.Time // with the clock's monotonic reading
	elapsed func(start, now time.Time) time.Duration
}

// StartedAt is the start rule of a receiver started at now; elapsed is
// the time from start to now, two readings of the clock (now.Sub(start)
// outside tests).
func StartedAt(now time.Time, elapsed func(start, now time.Time) time.Duration) StartRule {
	return StartRule{at: now, elapsed: elapsed}
}

// At is when the receiver started.
func (r StartRule) At() time.Time { return r.at }

// Refuses reports whether a message sealed at sent was sealed before the
// second the receiver started in, that second read on today's wall
// clock: now less the monotonic time since the start. A wall clock step
// since the start (an NTP sync) moves it along with the clock, so a step
// back doesn't refuse every sender for as long as the step, and a step
// forward doesn't let in what was sealed in the gap. MaxClockSkew after
// the start, the freshness check refuses everything the rule would.
func (r StartRule) Refuses(sent uint32, now time.Time) bool {
	if r.elapsed == nil {
		return false
	}
	started := uint32(now.Add(-r.elapsed(r.at, now)).Unix())
	return int32(started-sent) > 0 // wraps in 2106, as the sealed send time does
}
