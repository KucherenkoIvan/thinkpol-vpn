package censor

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/ip"
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
// false for anything it cannot read: a non-IP or malformed packet, or a
// later fragment. The queue adapter checks isFragment first.
func decodePacket(b []byte) (Packet, bool) {
	h, ok := ip.Decode(b)
	if !ok || h.LaterFragment {
		return Packet{}, false
	}
	pkt := Packet{Src: h.Src, Dst: h.Dst, Proto: Proto(h.Proto), Payload: h.Payload}
	switch pkt.Proto {
	case ProtoUDP:
		if len(h.Payload) < 8 {
			return Packet{}, false
		}
		pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(h.Payload), binary.BigEndian.Uint16(h.Payload[2:])
		pkt.Payload = h.Payload[8:]
	case ProtoTCP:
		if len(h.Payload) < 20 {
			return Packet{}, false
		}
		pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(h.Payload), binary.BigEndian.Uint16(h.Payload[2:])
		pkt.Seq = binary.BigEndian.Uint32(h.Payload[4:])
		pkt.Ack = binary.BigEndian.Uint32(h.Payload[8:])
		pkt.Flags = h.Payload[13]
		off := int(h.Payload[12]>>4) * 4
		if off < 20 || off > len(h.Payload) {
			return Packet{}, false
		}
		pkt.Payload = h.Payload[off:]
	}
	return pkt, true
}

// isFragment reports whether b is an IP fragment, first or later, IPv4 or
// IPv6, whatever extension headers (AH included) precede an IPv6 fragment
// header. The router reassembles datagrams before the censor sees them
// (see installQueueRule), so a fragment that still reaches the queue
// escaped reassembly: its later fragments carry no ports, and accepting
// them would let a blocked datagram's bytes through. The queue adapter
// drops them.
func isFragment(b []byte) bool {
	h, ok := ip.Decode(b)
	return ok && h.Fragment
}
