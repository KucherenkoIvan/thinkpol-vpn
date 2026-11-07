package censor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

func init() {
	RegisterPassive("openvpn-fingerprint", newOpenVPNFingerprint)
}

// OpenVPN's opcodes (the high five bits of a packet's first byte, the low
// three its key id), from its ssl_pkt.h.
const (
	ovpnControlV1               = 4
	ovpnAckV1                   = 5
	ovpnControlHardResetClient2 = 7
	ovpnControlHardResetServer2 = 8
	ovpnControlHardResetClient3 = 10
	ovpnControlWKCV1            = 11
)

const (
	// ovpnHead is what the fingerprint reads of a packet: its opcode and
	// key id, and the sender's 8-byte session id, sent in the clear in
	// every control packet with or without tls-auth or tls-crypt.
	ovpnHead = 1 + 8
	// ovpnHeads is how many distinct packets per direction the module
	// reads before it gives up on a connection: the fingerprint is
	// decided by the client's second.
	ovpnHeads = 4
)

// openVPNFingerprint is the opcode fingerprint of OpenVPN's handshake
// ("OpenVPN is Open to VPN Fingerprinting", Xue et al., USENIX Security
// 2022), over UDP and over TCP (each packet behind a 2-byte length), on
// any port. A connection is OpenVPN when its client's first packet is a
// hard reset (opcode 7, or 10 with tls-crypt-v2, key id 0), the server's
// first is the reset's answer (opcode 8, key id 0), and the client's next
// packet is a control or ack packet (opcode 4, 5 or 11, key id 0) with
// the session id of its reset. Three opcodes and a repeated 64-bit id:
// random bytes don't match, and tls-auth and tls-crypt don't hide them.
// The client is the side that sent payload first. The client's second
// packet meets the verdict (drop by default), and so does every packet of
// the connection after it, both ways; a connection that strays from the
// pattern before it is not OpenVPN, and the module retires from it.
// Retransmitted packets (one head twice in a row) count once. A
// connection already past its handshake when the censor started passes:
// its data packets carry no such pattern.
type openVPNFingerprint struct {
	block blocking
	conns map[FlowKey]*ovpnConn
}

// ovpnConn is one connection's state, keyed by the flow key of its
// client's direction.
type ovpnConn struct {
	// flows are the client's and the server's flows the state was built
	// from; a flow the engine started over is a new connection.
	flows [2]*Flow
	heads [2][][ovpnHead]byte
	// verdict is "" while undecided, else why the connection is
	// OpenVPN; notOpenVPN once it strayed from the pattern.
	verdict    string
	notOpenVPN bool
}

// newOpenVPNFingerprint builds the module from blockSettings: verdict
// (drop by default), rate and burst.
func newOpenVPNFingerprint(settings json.RawMessage) (Passive, error) {
	var s blockSettings
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	b, err := s.parse(Drop)
	if err != nil {
		return nil, err
	}
	return &openVPNFingerprint{block: b, conns: map[FlowKey]*ovpnConn{}}, nil
}

func (m *openVPNFingerprint) Name() string { return "openvpn-fingerprint" }

func (m *openVPNFingerprint) Inspect(p *Packet, f *Flow) Decision {
	if p.Proto != ProtoTCP && p.Proto != ProtoUDP {
		return retire
	}
	if f.Stream != nil && f.Stream.Midstream() {
		return retire
	}
	if p.BadChecksum || !m.hasPayload(p, f) {
		return Decision{Verdict: Accept}
	}
	c, dir := m.conn(f)
	if c.verdict == "" && !c.notOpenVPN {
		m.read(c, dir, p, f)
		m.judge(c)
	}
	switch {
	case c.verdict != "":
		return m.block.decide(c.verdict)
	case c.notOpenVPN:
		return retire
	}
	return Decision{Verdict: Accept}
}

// hasPayload says whether the flow has given the module something to
// read: a datagram, or stream bytes.
func (m *openVPNFingerprint) hasPayload(p *Packet, f *Flow) bool {
	if f.Stream != nil {
		return len(f.Stream.Prefix()) > 0
	}
	return len(p.Payload) > 0
}

// conn finds a flow's connection state and which side the flow is: 0 the
// client, 1 the server. A connection is created by the first flow of it
// with payload, its client.
func (m *openVPNFingerprint) conn(f *Flow) (*ovpnConn, int) {
	if c, ok := m.conns[f.Key]; ok && c.flows[0] == f {
		return c, 0
	}
	if c, ok := m.conns[f.Key.Reverse()]; ok && c.flows[1] == f {
		return c, 1
	}
	if r := f.Reverse(); r != nil {
		if c, ok := m.conns[r.Key]; ok && c.flows[0] == r && c.flows[1] == nil {
			c.flows[1] = f
			return c, 1
		}
	}
	// Whatever state either key still has is of an older connection.
	delete(m.conns, f.Key.Reverse())
	c := &ovpnConn{flows: [2]*Flow{f}}
	m.conns[f.Key] = c
	return c, 0
}

// read takes the packet heads the flow has so far: the datagram's, or
// every packet the stream frames.
func (m *openVPNFingerprint) read(c *ovpnConn, dir int, p *Packet, f *Flow) {
	if f.Stream == nil {
		if len(p.Payload) < ovpnHead {
			c.notOpenVPN = true
			return
		}
		c.add(dir, p.Payload)
		return
	}
	c.heads[dir] = c.heads[dir][:0]
	b := f.Stream.Prefix()
	for len(b) >= 2 && len(c.heads[dir]) < ovpnHeads {
		n := int(binary.BigEndian.Uint16(b))
		if n < ovpnHead {
			c.notOpenVPN = true
			return
		}
		if len(b) < 2+ovpnHead {
			return
		}
		c.add(dir, b[2:])
		if len(b) < 2+n {
			return
		}
		b = b[2+n:]
	}
}

// add appends a packet's head to its direction's, unless it repeats the
// one before it (a retransmission).
func (c *ovpnConn) add(dir int, packet []byte) {
	var h [ovpnHead]byte
	copy(h[:], packet)
	heads := c.heads[dir]
	if len(heads) > 0 && heads[len(heads)-1] == h || len(heads) >= ovpnHeads {
		return
	}
	c.heads[dir] = append(heads, h)
}

func opcode(h [ovpnHead]byte) (op, keyID byte) { return h[0] >> 3, h[0] & 7 }

// judge decides the connection once its heads show the pattern or stray
// from it.
func (m *openVPNFingerprint) judge(c *ovpnConn) {
	client, server := c.heads[0], c.heads[1]
	if len(client) > 0 {
		if op, key := opcode(client[0]); op != ovpnControlHardResetClient2 && op != ovpnControlHardResetClient3 || key != 0 {
			c.notOpenVPN = true
			return
		}
	}
	if len(server) > 0 {
		if op, key := opcode(server[0]); op != ovpnControlHardResetServer2 || key != 0 {
			c.notOpenVPN = true
			return
		}
	}
	if len(client) < 2 {
		return
	}
	op, key := opcode(client[1])
	if op != ovpnControlV1 && op != ovpnAckV1 && op != ovpnControlWKCV1 || key != 0 ||
		!bytes.Equal(client[1][1:], client[0][1:]) {
		c.notOpenVPN = true
		return
	}
	if len(server) == 0 {
		// The client went on without the server's answer: wait for it,
		// but not past the heads the module reads.
		if len(client) >= ovpnHeads {
			c.notOpenVPN = true
		}
		return
	}
	cop, _ := opcode(client[0])
	c.verdict = fmt.Sprintf("openvpn handshake: client reset (opcode %d), server reset, client opcode %d, session %x", cop, op, client[0][1:])
}
