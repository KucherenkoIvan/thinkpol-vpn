package censor

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Proto is the IP protocol number of a packet's payload.
type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return fmt.Sprintf("ip%d", uint8(p))
}

// TCP header flags, for Packet.Flags.
const (
	Fin uint8 = 1 << iota
	Syn
	Rst
	Psh
	Ack
)

// Packet is one forwarded IP packet, decoded as far as the modules need.
// Payload is what follows the TCP or UDP header; the engine hands the same
// buffer to every module, so a module that needs it after Inspect clones
// it first.
type Packet struct {
	Src, Dst         netip.Addr
	Proto            Proto
	SrcPort, DstPort uint16
	// Seq and Ack are the TCP sequence and acknowledgement numbers, 0 for
	// other protocols.
	Seq, Ack uint32
	// Flags are the TCP header flags, 0 for other protocols.
	Flags   uint8
	Payload []byte
}

// Clone returns a packet whose payload the module may keep.
func (p *Packet) Clone() *Packet {
	c := *p
	c.Payload = append([]byte(nil), p.Payload...)
	return &c
}

func (p *Packet) String() string {
	return fmt.Sprintf("%s %s:%d->%s:%d", p.Proto, p.Src, p.SrcPort, p.Dst, p.DstPort)
}

// decodePacket decodes an IP packet as the queue hands it over. It returns
// false for anything it cannot read — a non-IP packet, a later fragment —
// and the engine accepts those: no module can judge what it cannot see.
func decodePacket(ip []byte) (Packet, bool) {
	var pkt Packet
	if len(ip) < 1 {
		return pkt, false
	}
	var l4 []byte
	first := true
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return pkt, false
		}
		ihl := int(ip[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(ip[2:]))
		if ihl < 20 || total < ihl || total > len(ip) {
			return pkt, false
		}
		ip = ip[:total]
		pkt.Proto, pkt.Src, pkt.Dst = Proto(ip[9]),
			netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		first = binary.BigEndian.Uint16(ip[6:])&0x1fff == 0
		l4 = ip[ihl:]
	case 6:
		if len(ip) < 40 {
			return pkt, false
		}
		total := 40 + int(binary.BigEndian.Uint16(ip[4:]))
		if total > len(ip) {
			return pkt, false
		}
		ip = ip[:total]
		pkt.Src = netip.AddrFrom16([16]byte(ip[8:24]))
		pkt.Dst = netip.AddrFrom16([16]byte(ip[24:40]))
		next, rest := ip[6], ip[40:]
	exts:
		for {
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(rest) < 8 || len(rest) < 8+int(rest[1])*8 {
					return pkt, false
				}
				next, rest = rest[0], rest[8+int(rest[1])*8:]
			case 44: // fragment
				if len(rest) < 8 {
					return pkt, false
				}
				first = binary.BigEndian.Uint16(rest[2:])&0xfff8 == 0
				next, rest = rest[0], rest[8:]
			default:
				break exts
			}
		}
		pkt.Proto, l4 = Proto(next), rest
	default:
		return pkt, false
	}
	if !first {
		return pkt, false
	}
	pkt.Payload = l4
	switch pkt.Proto {
	case ProtoUDP:
		if len(l4) < 8 {
			return pkt, false
		}
		pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		pkt.Payload = l4[8:]
	case ProtoTCP:
		if len(l4) < 20 {
			return pkt, false
		}
		pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		pkt.Seq = binary.BigEndian.Uint32(l4[4:])
		pkt.Ack = binary.BigEndian.Uint32(l4[8:])
		pkt.Flags = l4[13]
		off := int(l4[12]>>4) * 4
		if off < 20 || off > len(l4) {
			return pkt, false
		}
		pkt.Payload = l4[off:]
	}
	return pkt, true
}
