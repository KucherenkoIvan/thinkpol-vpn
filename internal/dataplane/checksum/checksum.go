// Package checksum recomputes IP and transport checksums on packets the
// router reflects back to the TUN (macOS local overlay traffic).
package checksum

import "encoding/binary"

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	extHopByHop = 0
	extRouting  = 43
	extFragment = 44
	extDest     = 60
)

// Fix overwrites checksum fields in p when it recognises IPv4 or IPv6 with
// TCP, UDP or ICMP(v6). Extension headers are skipped on IPv6; if the next
// header is not one of those, the packet is left unchanged (except IPv4
// header checksum, which is always fixed).
func Fix(p []byte) {
	if len(p) == 0 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		fixIPv4(p)
	case 6:
		fixIPv6(p)
	}
}

func fixIPv4(p []byte) {
	if len(p) < 20 {
		return
	}
	hl := int(p[0]&0x0f) * 4
	if hl < 20 || hl > len(p) {
		return
	}
	putHeader(p[10:12], p[:hl])
	body := p[hl:]
	switch p[9] {
	case protoTCP, protoUDP:
		putTCPUDP(p[12:16], p[16:20], p[9], body)
	case protoICMP:
		putICMP(body)
	}
}

func fixIPv6(p []byte) {
	if len(p) < 40 {
		return
	}
	off, proto, ok := ipv6Transport(p)
	if !ok {
		return
	}
	body := p[off:]
	src, dst := p[8:24], p[24:40]
	switch proto {
	case protoTCP, protoUDP:
		putTCPUDPv6(src, dst, proto, body)
	case protoICMPv6:
		putICMPv6(src, dst, body)
	}
}

func ipv6Transport(p []byte) (off int, proto byte, ok bool) {
	if len(p) < 40 {
		return 0, 0, false
	}
	proto = p[6]
	off = 40
	for {
		switch proto {
		case protoTCP, protoUDP, protoICMPv6:
			return off, proto, true
		case extHopByHop, extRouting, extDest:
			if len(p) < off+2 {
				return 0, 0, false
			}
			next := p[off]
			extLen := int(p[off+1]+1) * 8
			if len(p) < off+extLen {
				return 0, 0, false
			}
			proto = next
			off += extLen
		case extFragment:
			if len(p) < off+8 {
				return 0, 0, false
			}
			proto = p[off]
			off += 8
		default:
			return 0, 0, false
		}
	}
}

func putHeader(at []byte, hdr []byte) {
	at[0], at[1] = 0, 0
	binary.BigEndian.PutUint16(at, ^ones(0, hdr))
}

func putICMP(msg []byte) {
	if len(msg) < 4 {
		return
	}
	msg[2], msg[3] = 0, 0
	binary.BigEndian.PutUint16(msg[2:], ^ones(0, msg))
}

func putTCPUDP(src4, dst4 []byte, proto byte, body []byte) {
	if csumAt(proto) < 0 || len(body) < minBody(proto) {
		return
	}
	at := csumAt(proto)
	body[at], body[at+1] = 0, 0
	pseudo := append(append([]byte{}, src4...), dst4...)
	pseudo = append(pseudo, 0, proto, byte(len(body)>>8), byte(len(body)))
	putTransport(at, proto, pseudo, body)
}

func putTCPUDPv6(src, dst []byte, proto byte, body []byte) {
	if csumAt(proto) < 0 || len(body) < minBody(proto) {
		return
	}
	at := csumAt(proto)
	body[at], body[at+1] = 0, 0
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, byte(len(body)>>24), byte(len(body)>>16), byte(len(body)>>8), byte(len(body)), 0, 0, 0, proto)
	putTransport(at, proto, pseudo, body)
}

func putICMPv6(src, dst []byte, msg []byte) {
	if len(msg) < 4 {
		return
	}
	msg[2], msg[3] = 0, 0
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, byte(len(msg)>>24), byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg)), 0, 0, 0, protoICMPv6)
	c := ^ones(uint32(ones(0, pseudo)), msg)
	binary.BigEndian.PutUint16(msg[2:], c)
}

func putTransport(at int, proto byte, pseudo, body []byte) {
	c := ^ones(uint32(ones(0, pseudo)), body)
	if proto == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(body[at:], c)
}

func csumAt(proto byte) int {
	switch proto {
	case protoTCP:
		return 16
	case protoUDP, protoICMP, protoICMPv6:
		return 6
	default:
		return -1
	}
}

func minBody(proto byte) int {
	switch proto {
	case protoTCP:
		return 20
	case protoUDP:
		return 8
	case protoICMP, protoICMPv6:
		return 8
	default:
		return 0
	}
}

func ones(acc uint32, b []byte) uint16 {
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
