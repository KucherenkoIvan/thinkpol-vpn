// Package ip decodes IP packets for the lab's packet readers: the pcap
// capture and the censor's queue see the same packets and must agree on
// addresses, protocols and fragments.
package ip

import (
	"encoding/binary"
	"net/netip"
)

// Packet is one decoded IP packet.
type Packet struct {
	Src, Dst netip.Addr
	// Proto is the protocol of Payload: for IPv6, the next header past the
	// extension headers; for a later IPv6 fragment, the fragment header's.
	Proto uint8
	// Fragment is set for any fragment, first or later.
	Fragment bool
	// LaterFragment is set for a fragment past the first, which carries no
	// transport header.
	LaterFragment bool
	// Payload is what follows the IP header (and IPv6 extension headers):
	// the transport header and its data, or a later fragment's data.
	Payload []byte
	// Bytes is the packet, trimmed to the length its header declares.
	Bytes []byte
}

// Decode decodes one IPv4 or IPv6 packet. It returns false for anything it
// cannot read: a non-IP or malformed packet.
func Decode(b []byte) (Packet, bool) {
	if len(b) < 1 {
		return Packet{}, false
	}
	var h Packet
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return Packet{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) {
			return Packet{}, false
		}
		b = b[:total]
		h.Proto = b[9]
		h.Src = netip.AddrFrom4([4]byte(b[12:16]))
		h.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		// The offset alone: a first fragment still carries the transport
		// header.
		h.LaterFragment = binary.BigEndian.Uint16(b[6:])&0x1fff != 0
		// More fragments or an offset; DF and the reserved bit don't
		// count.
		h.Fragment = binary.BigEndian.Uint16(b[6:])&0x3fff != 0
		h.Payload = b[ihl:]
	case 6:
		if len(b) < 40 {
			return Packet{}, false
		}
		total := 40 + int(binary.BigEndian.Uint16(b[4:]))
		if total > len(b) {
			return Packet{}, false
		}
		b = b[:total]
		h.Src = netip.AddrFrom16([16]byte(b[8:24]))
		h.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		next, rest := b[6], b[40:]
	exts:
		for {
			switch next {
			// Hop-by-hop, routing, destination options, mobility, HIP,
			// shim6 and the two experimental types: RFC 6564's uniform
			// format, length in 8-byte units past the first 8.
			case 0, 43, 60, 135, 139, 140, 253, 254:
				if len(rest) < 8 || len(rest) < 8+int(rest[1])*8 {
					return Packet{}, false
				}
				next, rest = rest[0], rest[8+int(rest[1])*8:]
			case 51: // AH: length in 4-byte units, minus 2
				if len(rest) < 8 || len(rest) < (int(rest[1])+2)*4 {
					return Packet{}, false
				}
				next, rest = rest[0], rest[(int(rest[1])+2)*4:]
			case 44: // fragment
				if len(rest) < 8 {
					return Packet{}, false
				}
				h.Fragment = true
				h.LaterFragment = binary.BigEndian.Uint16(rest[2:])&0xfff8 != 0
				next, rest = rest[0], rest[8:]
				if h.LaterFragment {
					// The rest is fragment data, not headers.
					break exts
				}
			default: // a transport, ESP (opaque past here) or no next header
				break exts
			}
		}
		h.Proto, h.Payload = next, rest
	default:
		return Packet{}, false
	}
	h.Bytes = b
	return h, true
}
