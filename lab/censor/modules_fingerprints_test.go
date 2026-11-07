package censor

import (
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"
)

// wgDatagram is a WireGuard message of type typ and n bytes: the header
// and random bytes after it, as its encrypted fields look.
func wgDatagram(r *rand.Rand, typ byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	b[0], b[1], b[2], b[3] = typ, 0, 0, 0
	return b
}

// TestWireGuardFingerprint blocks each of WireGuard's messages at its own
// size, transport data on its own included, through the engine: the flow
// stays dropped. A header at the wrong size, random datagrams, a datagram
// the receiver discards and TCP pass.
func TestWireGuardFingerprint(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	m := buildPassive(t, "wireguard-fingerprint", `{}`)
	for name, msg := range map[string][]byte{
		"handshake initiation": wgDatagram(r, 1, 148),
		"handshake response":   wgDatagram(r, 2, 92),
		"cookie reply":         wgDatagram(r, 3, 64),
		"transport data":       wgDatagram(r, 4, 32+16*40),
	} {
		eng := NewEngine([]Passive{m}, nil, nil)
		a := eng.Handle(udpPacket(clientAddr, serverAddr, 40000, 51820, msg))
		if a.Verdict != Drop || a.Module != "wireguard-fingerprint" || !strings.Contains(a.Reason, name) {
			t.Errorf("%s: %+v", name, a)
		}
		if a := eng.Handle(udpPacket(clientAddr, serverAddr, 40000, 51820, []byte("anything"))); a.Verdict != Drop {
			t.Errorf("%s: the flow's next datagram: %+v", name, a)
		}
	}
	for name, msg := range map[string][]byte{
		"initiation, 149 bytes": wgDatagram(r, 1, 149),
		"response, 148 bytes":   wgDatagram(r, 2, 148),
		"transport, unpadded":   wgDatagram(r, 4, 33),
		"transport, too short":  wgDatagram(r, 4, 16),
		"type 5":                wgDatagram(r, 5, 64),
		"short":                 {1, 0, 0},
	} {
		if d := m.Inspect(udpPacket(clientAddr, serverAddr, 1, 2, msg), &Flow{}); d.Verdict != Accept {
			t.Errorf("%s: %+v", name, d)
		}
	}
	// One in about a billion random datagrams has the header: 100000
	// match it with odds of one in ten thousand.
	for i := 0; i < 100000; i++ {
		b := make([]byte, 32+16*r.IntN(80))
		for j := range b {
			b[j] = byte(r.Uint32())
		}
		if d := m.Inspect(udpPacket(clientAddr, serverAddr, 1, 2, b), &Flow{}); d.Verdict != Accept {
			t.Fatalf("random datagram %x: %+v", b[:8], d)
		}
	}
	bad := udpPacket(clientAddr, serverAddr, 1, 2, wgDatagram(r, 1, 148))
	bad.BadChecksum = true
	if d := m.Inspect(bad, &Flow{}); d.Verdict != Accept {
		t.Errorf("bad checksum: %+v", d)
	}
	if d := m.Inspect(tcpPacket(clientAddr, serverAddr, 1, 2, 1, 1, Ack, wgDatagram(r, 1, 148)), &Flow{}); d != retire {
		t.Errorf("tcp: %+v", d)
	}
}

// ovpnPacket is an OpenVPN control packet: opcode and key id, the sender's
// session id, then rest bytes (ack array, packet id, HMAC or ciphertext).
func ovpnPacket(op, key byte, session uint64, rest int) []byte {
	b := make([]byte, 9+rest)
	b[0] = op<<3 | key
	binary.BigEndian.PutUint64(b[1:], session)
	for i := 9; i < len(b); i++ {
		b[i] = byte(i * 7)
	}
	return b
}

// ovpnTCP frames packets as OpenVPN over TCP does: each behind its length.
func ovpnTCP(packets ...[]byte) []byte {
	var b []byte
	for _, p := range packets {
		b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
		b = append(b, p...)
	}
	return b
}

const clientSession, serverSession = 0x1122334455667788, 0x99aabbccddeeff00

// TestOpenVPNFingerprintUDP: the client's reset (retransmitted), the
// server's answer and the client's next control packet with its session
// id are OpenVPN: that packet is dropped, and so is everything after it
// both ways. tls-crypt-v2's opcodes are OpenVPN too.
func TestOpenVPNFingerprintUDP(t *testing.T) {
	m := buildPassive(t, "openvpn-fingerprint", `{}`)
	for name, ops := range map[string][2]byte{"tls": {ovpnControlHardResetClient2, ovpnControlV1}, "tls-crypt-v2": {ovpnControlHardResetClient3, ovpnControlWKCV1}, "ack": {ovpnControlHardResetClient2, ovpnAckV1}} {
		eng := NewEngine([]Passive{m}, nil, nil)
		up := func(b []byte) Action { return eng.Handle(udpPacket(clientAddr, serverAddr, 40000, 1194, b)) }
		down := func(b []byte) Action { return eng.Handle(udpPacket(serverAddr, clientAddr, 1194, 40000, b)) }
		for i, a := range []Action{
			up(ovpnPacket(ops[0], 0, clientSession, 40)),
			up(ovpnPacket(ops[0], 0, clientSession, 40)),
			down(ovpnPacket(ovpnControlHardResetServer2, 0, serverSession, 52)),
		} {
			if a.Verdict != Accept {
				t.Errorf("%s: packet %d: %+v", name, i, a)
			}
		}
		a := up(ovpnPacket(ops[1], 0, clientSession, 300))
		if a.Verdict != Drop || a.Module != "openvpn-fingerprint" || !strings.Contains(a.Reason, "openvpn handshake") {
			t.Errorf("%s: the client's next packet: %+v", name, a)
		}
		if a := down(ovpnPacket(ovpnAckV1, 0, serverSession, 20)); a.Verdict != Drop {
			t.Errorf("%s: the server's next packet: %+v", name, a)
		}
	}
}

// TestOpenVPNFingerprintTCP: the same over TCP, each packet behind its
// length, the client's two packets in one segment split mid-packet over
// two: the segment completing the pattern is dropped.
func TestOpenVPNFingerprintTCP(t *testing.T) {
	m := buildPassive(t, "openvpn-fingerprint", `{"verdict": "reset"}`)
	eng := NewEngine([]Passive{m}, nil, nil)
	seq := handshake(eng)
	reset := ovpnTCP(ovpnPacket(ovpnControlHardResetClient2, 0, clientSession, 40))
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, reset)); a.Verdict != Accept {
		t.Errorf("client reset: %+v", a)
	}
	seq += uint32(len(reset))
	answer := ovpnTCP(ovpnPacket(ovpnControlHardResetServer2, 0, serverSession, 52))
	if a := eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5001, seq, Ack|Psh, answer)); a.Verdict != Accept {
		t.Errorf("server reset: %+v", a)
	}
	next := ovpnTCP(ovpnPacket(ovpnControlV1, 0, clientSession, 300))
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001+uint32(len(answer)), Ack, next[:5])); a.Verdict != Accept {
		t.Errorf("the start of the client's next packet: %+v", a)
	}
	a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq+5, 5001+uint32(len(answer)), Ack|Psh, next[5:]))
	if a.Verdict != Reset || a.Module != "openvpn-fingerprint" {
		t.Errorf("the client's next packet: %+v", a)
	}
}

// TestOpenVPNFingerprintStrays: a connection that strays from the pattern
// anywhere passes, and the module retires from it.
func TestOpenVPNFingerprintStrays(t *testing.T) {
	m := buildPassive(t, "openvpn-fingerprint", `{}`)
	reset := ovpnPacket(ovpnControlHardResetClient2, 0, clientSession, 40)
	answer := ovpnPacket(ovpnControlHardResetServer2, 0, serverSession, 52)
	control := ovpnPacket(ovpnControlV1, 0, clientSession, 300)
	for name, c := range map[string]struct{ up1, down, up2 []byte }{
		"client starts with data":     {ovpnPacket(9, 0, clientSession, 40), answer, control},
		"client reset, key id 1":      {ovpnPacket(ovpnControlHardResetClient2, 1, clientSession, 40), answer, control},
		"server answers otherwise":    {reset, ovpnPacket(ovpnControlV1, 0, serverSession, 52), control},
		"another session":             {reset, answer, ovpnPacket(ovpnControlV1, 0, clientSession+1, 300)},
		"client's next isn't control": {reset, answer, ovpnPacket(ovpnControlHardResetServer2, 0, clientSession, 300)},
		"short":                       {reset[:8], answer, control},
	} {
		eng := NewEngine([]Passive{m}, nil, nil)
		for _, a := range []Action{
			eng.Handle(udpPacket(clientAddr, serverAddr, 40000, 1194, c.up1)),
			eng.Handle(udpPacket(serverAddr, clientAddr, 1194, 40000, c.down)),
			eng.Handle(udpPacket(clientAddr, serverAddr, 40000, 1194, c.up2)),
		} {
			if a.Verdict != Accept {
				t.Errorf("%s: %+v", name, a)
			}
		}
		f := eng.flows.flows[FlowKey{ProtoUDP, clientAddr, serverAddr, 40000, 1194}]
		if f.done == nil || !f.done[0] {
			t.Errorf("%s: the module didn't retire from the client's flow", name)
		}
	}
	// A TCP stream that isn't framed like OpenVPN (TLS, say) retires at
	// once.
	eng := NewEngine([]Passive{m}, nil, nil)
	seq := handshake(eng)
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, helloFor(t, "example.net")))
	if f := eng.flows.flows[FlowKey{ProtoTCP, clientAddr, serverAddr, 40000, 443}]; f.done == nil || !f.done[0] {
		t.Error("TLS: the module didn't retire")
	}
}

// TestOpenVPNFingerprintRandom: random datagrams both ways never match.
func TestOpenVPNFingerprintRandom(t *testing.T) {
	m := buildPassive(t, "openvpn-fingerprint", `{}`)
	r := rand.New(rand.NewPCG(3, 4))
	random := func() []byte {
		b := make([]byte, 20+r.IntN(1200))
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	eng := NewEngine([]Passive{m}, nil, nil)
	for port := uint16(1); port <= 20000; port++ {
		for i := 0; i < 3; i++ {
			src, dst := clientAddr, serverAddr
			sp, dp := 40000+port, uint16(1194)
			if i == 1 {
				src, dst, sp, dp = dst, src, dp, sp
			}
			if a := eng.Handle(udpPacket(src, dst, sp, dp, random())); a.Verdict != Accept {
				t.Fatalf("random connection %d: %+v", port, a)
			}
		}
	}
}
