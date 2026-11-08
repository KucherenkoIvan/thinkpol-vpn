package censor

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// blockSettings are the settings every blocking module shares:
//
//	{"verdict": "drop", "rate": 1750, "burst": 3000}
//
// verdict is drop, reset or throttle ("" is the module's default); rate
// and burst are throttle's, in bytes (Decision).
type blockSettings struct {
	Verdict string `json:"verdict"`
	Rate    int    `json:"rate"`
	Burst   int    `json:"burst"`
}

// blocking is a module's verdict as its settings gave it.
type blocking struct {
	verdict     Verdict
	rate, burst int
}

func (s blockSettings) parse(def Verdict) (blocking, error) {
	b := blocking{verdict: def, rate: s.Rate, burst: s.Burst}
	switch s.Verdict {
	case "":
	case "drop":
		b.verdict = Drop
	case "reset":
		b.verdict = Reset
	case "throttle":
		b.verdict = Throttle
	default:
		return blocking{}, fmt.Errorf("verdict %q: want drop, reset or throttle", s.Verdict)
	}
	if s.Rate < 0 || s.Burst < 0 {
		return blocking{}, fmt.Errorf("rate %d, burst %d: want positive or 0 for the default", s.Rate, s.Burst)
	}
	return b, nil
}

// decide is the blocking decision, pinned to the flow.
func (b blocking) decide(reason string) Decision {
	d := b.decidePacket(reason)
	d.Flow = true
	return d
}

// decidePacket is the blocking decision for one packet, not pinned.
func (b blocking) decidePacket(reason string) Decision {
	return Decision{Verdict: b.verdict, Rate: b.rate, Burst: b.burst, Reason: reason}
}

// retired is a pinned Accept: the module has judged the flow and sees it
// no more, and the modules after it still do.
var retired = Decision{Verdict: Accept, Flow: true}

// parsePrefixes reads a list of addresses and prefixes, each called a
// field in errors; there must be one.
func parsePrefixes(field string, in []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, d := range in {
		p, err := netip.ParsePrefix(d)
		if err != nil {
			a, err := netip.ParseAddr(d)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %v", field, d, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no %s listed", field)
	}
	return prefixes, nil
}

// unmarshalSettings reads a module's settings; none at all is {}. Every
// module reads its settings through it.
func unmarshalSettings(settings json.RawMessage, into any) error {
	if len(settings) == 0 {
		return nil
	}
	return json.Unmarshal(settings, into)
}
