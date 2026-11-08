package censor

import (
	"encoding/json"
	"fmt"
)

func init() {
	RegisterPassive("wireguard-fingerprint", newWireGuardFingerprint)
}

// wireGuardFingerprint is the usual DPI signature of WireGuard over UDP,
// on any port: a datagram starting with a message type from 1 to 4 and
// three zero bytes, at the size its type has on the wire (148-byte
// initiations, 92-byte responses, 64-byte cookie replies, transport data
// of at least 32 bytes). The first such datagram blocks its flow (drop by
// default). Transport data alone is enough, so a tunnel that came up
// before the censor did is caught by its next packet; random bytes match
// the header about once in a billion datagrams, the size aside.
type wireGuardFingerprint struct {
	block blocking
}

// newWireGuardFingerprint builds the module from blockSettings: verdict
// (drop by default; reset drops, WireGuard being UDP), rate and burst.
func newWireGuardFingerprint(settings json.RawMessage) (Passive, error) {
	var s blockSettings
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	b, err := s.parse(Drop)
	if err != nil {
		return nil, err
	}
	return &wireGuardFingerprint{block: b}, nil
}

func (m *wireGuardFingerprint) Name() string { return "wireguard-fingerprint" }

func (m *wireGuardFingerprint) Inspect(p *Packet, _ *Flow) Decision {
	if p.Proto != ProtoUDP {
		return retired
	}
	// The receiver discards a datagram with a bad checksum.
	if p.BadChecksum {
		return Decision{Verdict: Accept}
	}
	if what := wireGuardMessage(p.Payload); what != "" {
		return m.block.decide(fmt.Sprintf("wireguard %s, %d bytes", what, len(p.Payload)))
	}
	return Decision{Verdict: Accept}
}

// wireGuardMessage names the WireGuard message b is, "" for none.
func wireGuardMessage(b []byte) string {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return ""
	}
	switch {
	case b[0] == wgTypeInitiation && len(b) == wgInitiation:
		return "handshake initiation"
	case b[0] == wgTypeResponse && len(b) == wgResponse:
		return "handshake response"
	case b[0] == wgTypeCookieReply && len(b) == wgCookieReply:
		return "cookie reply"
	case b[0] == wgTypeTransport && len(b) >= wgTransportMin:
		return "transport data"
	}
	return ""
}
