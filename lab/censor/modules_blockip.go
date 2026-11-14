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
// whose destination is on one of its networks, and nothing else. The
// matrix's address blocklist is ip-blocklist.
type blockIP struct {
	dests []netip.Prefix
	block blocking
	data  bool
}

// newBlockIP builds the module from its settings:
//
//	{"destinations": ["203.0.113.9", "2001:db8::/32"], "verdict": "drop",
//	 "rate": 1750, "burst": 3000, "data": false}
//
// with blockSettings' verdict (drop by default), rate and burst. With
// data, only packets that carry payload are decided: a TCP handshake
// completes, and the first data segment meets the verdict. Each packet is
// decided on its own, never pinned to its flow.
func newBlockIP(settings json.RawMessage) (Passive, error) {
	var s struct {
		Destinations []string `json:"destinations"`
		Data         bool     `json:"data"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	dests, err := parsePrefixes("destination", s.Destinations)
	if err != nil {
		return nil, err
	}
	b, err := s.parse(Drop)
	if err != nil {
		return nil, err
	}
	return &blockIP{dests: dests, block: b, data: s.Data}, nil
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
	return m.block.decidePacket(fmt.Sprintf("destination %s", p.Dst))
}
