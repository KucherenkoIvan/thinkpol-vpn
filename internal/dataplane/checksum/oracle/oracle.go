// Package oracle verifies IP checksums independently of checksum.Fix (tests).
package oracle

import "encoding/binary"

// OK reports whether the IPv4/IPv6 header and a recognised L4 checksum match.
func OK(pkt []byte) bool {
	if len(pkt) == 0 {
		return true
	}
	switch pkt[0] >> 4 {
	case 4:
		return ipv4OK(pkt)
	case 6:
		return ipv6OK(pkt)
	default:
		return true
	}
}

func ipv4OK(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	hl := int(pkt[0]&0x0f) * 4
	if hl < 20 || hl > len(pkt) {
		return false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < hl || total > len(pkt) {
		return false
	}
	pkt = pkt[:total]
	if sum16(pkt[:hl]) != 0xffff {
		return false
	}
	if ipv4Frag(pkt) {
		return true
	}
	body := pkt[hl:]
	switch pkt[9] {
	case 1:
		return sum16(body) == 0xffff
	case 6, 17:
		ph := ipv4Pseudo(pkt[12:16], pkt[16:20], pkt[9], len(body))
		return sum16(ph, body) == 0xffff
	default:
		return true
	}
}

func ipv4Frag(pkt []byte) bool {
	off := (int(pkt[6]&0x1f) << 8) | int(pkt[7])
	return off != 0 || pkt[6]&0x20 != 0
}

func ipv6OK(pkt []byte) bool {
	if len(pkt) < 40 {
		return false
	}
	end := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
	if end > len(pkt) {
		return false
	}
	pkt = pkt[:end]
	off, proto, ok, frag := walkV6(pkt)
	if frag {
		return true
	}
	if !ok {
		return true
	}
	body := pkt[off:]
	switch proto {
	case 6, 17:
		ph := ipv6Pseudo(pkt[8:24], pkt[24:40], proto, len(body))
		return sum16(ph, body) == 0xffff
	case 58:
		ph := ipv6Pseudo(pkt[8:24], pkt[24:40], 58, len(body))
		return sum16(ph, body) == 0xffff
	default:
		return true
	}
}

func walkV6(pkt []byte) (off int, proto byte, ok bool, frag bool) {
	proto = pkt[6]
	off = 40
	for n := 0; n < 8; n++ {
		switch proto {
		case 6, 17, 58:
			return off, proto, true, false
		case 44:
			return 0, 0, false, true
		case 0, 43, 60:
			if len(pkt) < off+2 {
				return 0, 0, false, false
			}
			next := pkt[off]
			extLen := (int(pkt[off+1]) + 1) * 8
			if extLen < 8 || len(pkt) < off+extLen {
				return 0, 0, false, false
			}
			proto = next
			off += extLen
		default:
			return 0, 0, false, false
		}
	}
	return 0, 0, false, false
}

func ipv4Pseudo(src, dst []byte, proto byte, l4len int) []byte {
	b := make([]byte, 12)
	copy(b[0:4], src)
	copy(b[4:8], dst)
	b[9] = proto
	b[10] = byte(l4len >> 8)
	b[11] = byte(l4len)
	return b
}

func ipv6Pseudo(src, dst []byte, proto byte, l4len int) []byte {
	b := make([]byte, 40)
	copy(b[0:16], src)
	copy(b[16:32], dst)
	b[32] = byte(l4len >> 24)
	b[33] = byte(l4len >> 16)
	b[34] = byte(l4len >> 8)
	b[35] = byte(l4len)
	b[39] = proto
	return b
}

func sum16(parts ...[]byte) uint32 {
	var acc uint32
	for _, p := range parts {
		i := 0
		for i+1 < len(p) {
			acc += uint32(p[i])<<8 | uint32(p[i+1])
			i += 2
		}
		if i < len(p) {
			acc += uint32(p[i]) << 8
		}
	}
	for acc > 0xffff {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return acc
}
