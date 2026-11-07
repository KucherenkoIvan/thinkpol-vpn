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
func FreshUnix(sent uint32, now time.Time) bool {
	d := time.Duration(int32(uint32(now.Unix())-sent)) * time.Second
	return d <= MaxClockSkew && d >= -MaxClockSkew
}
