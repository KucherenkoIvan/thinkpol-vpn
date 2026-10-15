package censor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

func init() {
	RegisterPassive("block-ip", newBlockIP)
}

// blockIP is the framework's end-to-end proof: it decides every packet
// whose destination is on one of its networks, and nothing else. Real
// blocklist modules (TP-025) replace it in the matrix.
type blockIP struct {
	dests   []netip.Prefix
	verdict Verdict
	hold    time.Duration
	held    Verdict
}

// newBlockIP builds the module from its settings:
//
//	{"destinations": ["203.0.113.9", "2001:db8::/32"], "verdict": "drop",
//	 "hold": "200ms"}
//
// verdict is drop (default), reset or throttle; hold is for throttle, and
// held is what a throttled packet becomes after it (accept, the default).
func newBlockIP(settings json.RawMessage) (Passive, error) {
	var s struct {
		Destinations []string `json:"destinations"`
		Verdict      string   `json:"verdict"`
		Hold         string   `json:"hold"`
		Held         string   `json:"held"`
	}
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	m := &blockIP{verdict: Drop, held: Accept}
	for _, d := range s.Destinations {
		p, err := netip.ParsePrefix(d)
		if err != nil {
			a, err := netip.ParseAddr(d)
			if err != nil {
				return nil, fmt.Errorf("destination %q: %v", d, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		m.dests = append(m.dests, p)
	}
	if len(m.dests) == 0 {
		return nil, fmt.Errorf("no destinations")
	}
	switch s.Verdict {
	case "", "drop":
		m.verdict = Drop
	case "reset":
		m.verdict = Reset
	case "throttle":
		m.verdict = Throttle
	default:
		return nil, fmt.Errorf("verdict %q: want drop, reset or throttle", s.Verdict)
	}
	if s.Hold != "" {
		h, err := time.ParseDuration(s.Hold)
		if err != nil {
			return nil, fmt.Errorf("hold %q: %v", s.Hold, err)
		}
		m.hold = h
	}
	switch s.Held {
	case "", "accept":
		m.held = Accept
	case "drop":
		m.held = Drop
	default:
		return nil, fmt.Errorf("held %q: want accept or drop", s.Held)
	}
	return m, nil
}

func (m *blockIP) Name() string { return "block-ip" }

func (m *blockIP) Inspect(p *Packet, _ *Flow) Decision {
	for _, d := range m.dests {
		if d.Contains(p.Dst) {
			return Decision{Verdict: m.verdict, Hold: m.hold, Held: m.held, Reason: fmt.Sprintf("destination %s", p.Dst)}
		}
	}
	return Decision{Verdict: Accept}
}
