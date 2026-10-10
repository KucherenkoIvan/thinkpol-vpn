// Package packettest builds and parses the IPv4 and IPv6 packets data-plane
// tests send through virtual TUNs: ICMP echo (ping) and UDP, with valid
// checksums, so a real stack would take them too.
package packettest

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers.
const (
	ICMPv4 = 1
	UDP    = 17
	ICMPv6 = 58
)

// ICMP echo types.
const (
	echoRequest4 = 8
	echoReply4   = 0
	echoRequest6 = 128
	echoReply6   = 129
)

// Packet is what Parse reads from an IP packet.
type Packet struct {
	Src, Dst netip.Addr
	Proto    int
	// Payload is everything after the IP header: the ICMP message, or the
	// UDP datagram with its header.
	Payload []byte
}

// Echo returns an ICMP echo request (ping) from src to dst, of the family
// of the addresses, carrying data.
func Echo(src, dst netip.Addr, id, seq uint16, data []byte) []byte {
	typ, proto := byte(echoRequest4), ICMPv4
	if dst.Is6() {
		typ, proto = echoRequest6, ICMPv6
	}
	msg := make([]byte, 8+len(data))
	msg[0] = typ
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[8:], data)
	return ip(src, dst, proto, msg)
}

// UDPDatagram returns a UDP datagram from src to dst carrying data.
func UDPDatagram(src, dst netip.AddrPort, data []byte) []byte {
	msg := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(msg[0:], src.Port())
	binary.BigEndian.PutUint16(msg[2:], dst.Port())
	binary.BigEndian.PutUint16(msg[4:], uint16(len(msg)))
	copy(msg[8:], data)
	return ip(src.Addr(), dst.Addr(), UDP, msg)
}

// Reply answers an ICMP echo request as the destination's stack would; ok
// is false for anything else.
func Reply(request []byte) (reply []byte, ok bool) {
	p, ok := Parse(request)
	if !ok || len(p.Payload) < 8 {
		return nil, false
	}
	switch {
	case p.Proto == ICMPv4 && p.Payload[0] == echoRequest4:
		msg := append([]byte{echoReply4}, p.Payload[1:]...)
		return ip(p.Dst, p.Src, ICMPv4, msg), true
	case p.Proto == ICMPv6 && p.Payload[0] == echoRequest6:
		msg := append([]byte{echoReply6}, p.Payload[1:]...)
		return ip(p.Dst, p.Src, ICMPv6, msg), true
	}
	return nil, false
}

// IsEchoRequest reports whether p is an ICMP echo request with id and seq.
func IsEchoRequest(p Packet, id, seq uint16) bool {
	return isEcho(p, id, seq, echoRequest4, echoRequest6)
}

// IsEchoReply reports whether p is an ICMP echo reply with id and seq.
func IsEchoReply(p Packet, id, seq uint16) bool {
	return isEcho(p, id, seq, echoReply4, echoReply6)
}

func isEcho(p Packet, id, seq uint16, type4, type6 byte) bool {
	if len(p.Payload) < 8 || binary.BigEndian.Uint16(p.Payload[4:]) != id || binary.BigEndian.Uint16(p.Payload[6:]) != seq {
		return false
	}
	return (p.Proto == ICMPv4 && p.Payload[0] == type4) || (p.Proto == ICMPv6 && p.Payload[0] == type6)
}

// UDPData returns the ports and data of a UDP packet.
func UDPData(p Packet) (src, dst netip.AddrPort, data []byte, ok bool) {
	if p.Proto != UDP || len(p.Payload) < 8 {
		return netip.AddrPort{}, netip.AddrPort{}, nil, false
	}
	src = netip.AddrPortFrom(p.Src, binary.BigEndian.Uint16(p.Payload[0:]))
	dst = netip.AddrPortFrom(p.Dst, binary.BigEndian.Uint16(p.Payload[2:]))
	return src, dst, p.Payload[8:], true
}

// Parse reads an IPv4 (without options) or IPv6 (without extension
// headers) packet.
func Parse(b []byte) (Packet, bool) {
	if len(b) == 0 {
		return Packet{}, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || int(binary.BigEndian.Uint16(b[2:])) != len(b) {
			return Packet{}, false
		}
		hl := int(b[0]&0xf) * 4
		if hl < 20 || hl > len(b) {
			return Packet{}, false
		}
		return Packet{
			Src:     netip.AddrFrom4([4]byte(b[12:16])),
			Dst:     netip.AddrFrom4([4]byte(b[16:20])),
			Proto:   int(b[9]),
			Payload: b[hl:],
		}, true
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:]))+40 != len(b) {
			return Packet{}, false
		}
		return Packet{
			Src:     netip.AddrFrom16([16]byte(b[8:24])),
			Dst:     netip.AddrFrom16([16]byte(b[24:40])),
			Proto:   int(b[6]),
			Payload: b[40:],
		}, true
	}
	return Packet{}, false
}

// ip wraps msg in an IP header and fills in the transport checksum.
func ip(src, dst netip.Addr, proto int, msg []byte) []byte {
	var pkt, pseudo []byte
	if dst.Is4() {
		pkt = make([]byte, 20+len(msg))
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
		pkt[8] = 64
		pkt[9] = byte(proto)
		s, d := src.As4(), dst.As4()
		copy(pkt[12:], s[:])
		copy(pkt[16:], d[:])
		binary.BigEndian.PutUint16(pkt[10:], ^sum(0, pkt[:20]))
		copy(pkt[20:], msg)
		if proto != ICMPv4 {
			pseudo = append(append(append([]byte{}, s[:]...), d[:]...), 0, byte(proto), byte(len(msg)>>8), byte(len(msg)))
		}
	} else {
		pkt = make([]byte, 40+len(msg))
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:], uint16(len(msg)))
		pkt[6] = byte(proto)
		pkt[7] = 64
		s, d := src.As16(), dst.As16()
		copy(pkt[8:], s[:])
		copy(pkt[24:], d[:])
		copy(pkt[40:], msg)
		pseudo = append(append(append([]byte{}, s[:]...), d[:]...), 0, 0, byte(len(msg)>>8), byte(len(msg)), 0, 0, 0, byte(proto))
	}
	body := pkt[len(pkt)-len(msg):]
	at := 2 // ICMP and ICMPv6
	if proto == UDP {
		at = 6
	}
	body[at], body[at+1] = 0, 0
	c := ^sum(uint32(sum(0, pseudo)), body)
	if proto == UDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(body[at:], c)
	return pkt
}

func sum(acc uint32, b []byte) uint16 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}
