package censor

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

func init() {
	RegisterPassive("block-ip", newBlockIP)
}

// blockIP is the framework's end-to-end proof: it decides every packet
// whose destination is on one of its networks, and nothing else. Real
// blocklist modules (TP-025) replace it in the matrix.
type blockIP struct {
	dests       []netip.Prefix
	verdict     Verdict
	rate, burst int
	data        bool
}

// newBlockIP builds the module from its settings:
//
//	{"destinations": ["203.0.113.9", "2001:db8::/32"], "verdict": "drop",
//	 "rate": 1750, "burst": 3000, "data": false}
//
// verdict is drop (default), reset or throttle; rate and burst are
// throttle's, in bytes (Decision). With data, only packets that carry
// payload are decided: a TCP handshake completes, and the first data
// segment meets the verdict.
func newBlockIP(settings json.RawMessage) (Passive, error) {
	var s struct {
		Destinations []string `json:"destinations"`
		Verdict      string   `json:"verdict"`
		Rate         int      `json:"rate"`
		Burst        int      `json:"burst"`
		Data         bool     `json:"data"`
	}
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	dests, err := parseDestinations(s.Destinations)
	if err != nil {
		return nil, err
	}
	m := &blockIP{dests: dests, rate: s.Rate, burst: s.Burst, data: s.Data}
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
	if s.Rate < 0 || s.Burst < 0 {
		return nil, fmt.Errorf("rate %d, burst %d: want positive or 0 for the default", s.Rate, s.Burst)
	}
	return m, nil
}

// parseDestinations reads addresses and prefixes; there must be one.
func parseDestinations(in []string) ([]netip.Prefix, error) {
	var dests []netip.Prefix
	for _, d := range in {
		p, err := netip.ParsePrefix(d)
		if err != nil {
			a, err := netip.ParseAddr(d)
			if err != nil {
				return nil, fmt.Errorf("destination %q: %v", d, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		dests = append(dests, p)
	}
	if len(dests) == 0 {
		return nil, fmt.Errorf("no destinations")
	}
	return dests, nil
}

func contains(dests []netip.Prefix, a netip.Addr) bool {
	for _, d := range dests {
		if d.Contains(a) {
			return true
		}
	}
	return false
}

func (m *blockIP) Name() string { return "block-ip" }

func (m *blockIP) Inspect(p *Packet, _ *Flow) Decision {
	if !contains(m.dests, p.Dst) || m.data && len(p.Payload) == 0 {
		return Decision{Verdict: Accept}
	}
	return Decision{Verdict: m.verdict, Rate: m.rate, Burst: m.burst, Reason: fmt.Sprintf("destination %s", p.Dst)}
}
