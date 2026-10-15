package checksum_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/checksum"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
)

func TestFixReflectedChecksums(t *testing.T) {
	src4, dst4 := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.1")
	src6, dst6 := netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:1::1")
	sp4 := netip.MustParseAddrPort("100.64.0.1:53000")
	dp4 := netip.MustParseAddrPort("100.64.0.1:53")
	sp6 := netip.MustParseAddrPort("[fd00:1::1]:53000")
	dp6 := netip.MustParseAddrPort("[fd00:1::1]:53")

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"ipv4_udp", packettest.UDPDatagram(sp4, dp4, []byte("query"))},
		{"ipv4_icmp", packettest.Echo(src4, dst4, 1, 1, []byte("ping"))},
		{"ipv4_tcp", tcp4(sp4, dp4, []byte("syn"))},
		{"ipv6_udp", packettest.UDPDatagram(sp6, dp6, []byte("query"))},
		{"ipv6_icmp", packettest.Echo(src6, dst6, 1, 1, []byte("ping"))},
		{"ipv6_tcp", tcp6(sp6, dp6, []byte("data"))},
		{"ipv6_udp_hopbyhop", udp6HopByHop(sp6, dp6, []byte("ext"))},
	}
	for _, corrupt := range []string{"zero", "pseudo", "garbage"} {
		for _, c := range cases {
			t.Run(corrupt+"/"+c.name, func(t *testing.T) {
				pkt := corruptChecksum(bytes.Clone(c.pkt), corrupt)
				if verify(pkt) == nil {
					t.Fatal("input should fail verification")
				}
				checksum.Fix(pkt)
				if err := verify(pkt); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func tcp4(src, dst netip.AddrPort, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:], src.Port())
	binary.BigEndian.PutUint16(seg[2:], dst.Port())
	copy(seg[20:], payload)
	return ip4(src.Addr(), dst.Addr(), 6, seg)
}

func tcp6(src, dst netip.AddrPort, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:], src.Port())
	binary.BigEndian.PutUint16(seg[2:], dst.Port())
	copy(seg[20:], payload)
	return ip6(src.Addr(), dst.Addr(), 6, seg)
}

func udp6HopByHop(src, dst netip.AddrPort, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	ext := []byte{17, 0, 0, 0, 0, 0, 0, 0} // next UDP, 8-byte hop-by-hop
	body := append(ext, udp...)
	return ip6(src.Addr(), dst.Addr(), 0, body)
}

func ip4(src, dst netip.Addr, proto int, body []byte) []byte {
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = byte(proto)
	s, d := src.As4(), dst.As4()
	copy(pkt[12:], s[:])
	copy(pkt[16:], d[:])
	copy(pkt[20:], body)
	fillGood(pkt, proto, s[:], d[:], body)
	return pkt
}

func ip6(src, dst netip.Addr, next int, body []byte) []byte {
	pkt := make([]byte, 40+len(body))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(body)))
	pkt[6] = byte(next)
	s, d := src.As16(), dst.As16()
	copy(pkt[8:], s[:])
	copy(pkt[24:], d[:])
	copy(pkt[40:], body)
	fillGood(pkt, next, s[:], d[:], body)
	return pkt
}

func fillGood(pkt []byte, proto int, src, dst []byte, body []byte) {
	if len(pkt) >= 20 && pkt[0]>>4 == 4 {
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:], ^fold(0, pkt[:20]))
	}
	switch proto {
	case 1:
		body[2], body[3] = 0, 0
		binary.BigEndian.PutUint16(body[2:], ^fold(0, body))
	case 6, 17:
		at := 16
		if proto == 17 {
			at = 6
		}
		body[at], body[at+1] = 0, 0
		var pseudo []byte
		if len(src) == 4 {
			pseudo = append(append(src, dst...), 0, byte(proto), byte(len(body)>>8), byte(len(body)))
		} else {
			pseudo = append(append(src, dst...), byte(len(body)>>24), byte(len(body)>>16), byte(len(body)>>8), byte(len(body)), 0, 0, 0, byte(proto))
		}
		c := ^fold(uint32(fold(0, pseudo)), body)
		if proto == 17 && c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(body[at:], c)
	case 0:
		// hop-by-hop then UDP in body
		udp := body[8:]
		udp[6], udp[7] = 0, 0
		pseudo := append(append(src, dst...), byte(len(udp)>>24), byte(len(udp)>>16), byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
		c := ^fold(uint32(fold(0, pseudo)), udp)
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:], c)
	}
}

func corruptChecksum(pkt []byte, how string) []byte {
	if len(pkt) == 0 {
		return pkt
	}
	switch pkt[0] >> 4 {
	case 4:
		pkt[10] ^= 0xff
		pkt[11] ^= 0xff
		corruptTransport(pkt, how)
	case 6:
		corruptIPv6(pkt, how)
	}
	return pkt
}

func ipv6TransportOff(pkt []byte) (off int, proto byte, ok bool) {
	if len(pkt) < 40 {
		return 0, 0, false
	}
	proto = pkt[6]
	off = 40
	for {
		switch proto {
		case 6, 17, 58:
			return off, proto, true
		case 0, 43, 60:
			if len(pkt) < off+2 {
				return 0, 0, false
			}
			next := pkt[off]
			extLen := int(pkt[off+1]+1) * 8
			if len(pkt) < off+extLen {
				return 0, 0, false
			}
			proto = next
			off += extLen
		case 44:
			if len(pkt) < off+8 {
				return 0, 0, false
			}
			proto = pkt[off]
			off += 8
		default:
			return 0, 0, false
		}
	}
}

func corruptTransport(pkt []byte, how string) {
	hl := int(pkt[0]&0x0f) * 4
	if hl < 20 || len(pkt) < hl {
		return
	}
	body := pkt[hl:]
	switch pkt[9] {
	case 6, 17:
		corruptBody(pkt[12:16], pkt[16:20], pkt[9], body, how)
	case 1:
		corruptICMP(body, how)
	}
}

func corruptIPv6(pkt []byte, how string) {
	off, proto, ok := ipv6TransportOff(pkt)
	if !ok {
		return
	}
	body := pkt[off:]
	switch proto {
	case 6, 17:
		corruptBodyv6(pkt[8:24], pkt[24:40], proto, body, how)
	case 58:
		corruptICMPv6(pkt[8:24], pkt[24:40], body, how)
	}
}

func corruptBody(src, dst []byte, proto byte, body []byte, how string) {
	at := 6
	if proto == 6 {
		at = 16
	}
	setBad(body, at, how, append(append([]byte{}, src...), dst...), 0, proto, body)
}

func corruptBodyv6(src, dst []byte, proto byte, body []byte, how string) {
	at := 6
	if proto == 6 {
		at = 16
	}
	setBad(body, at, how, append(append([]byte{}, src...), dst...), 4, proto, body)
}

func corruptICMP(body []byte, how string) {
	setBad(body, 2, how, nil, 0, 0, body)
}

func corruptICMPv6(src, dst, body []byte, how string) {
	setBad(body, 2, how, append(append([]byte{}, src...), dst...), 4, 58, body)
}

func setBad(body []byte, at int, how string, prefix []byte, lenWidth int, proto byte, whole []byte) {
	switch how {
	case "zero":
		body[at], body[at+1] = 0, 0
	case "garbage":
		body[at], body[at+1] = 0xbe, 0xef
	case "pseudo":
		body[at], body[at+1] = 0, 0
		if len(prefix) == 0 {
			return
		}
		var pseudo []byte
		switch lenWidth {
		case 0:
			pseudo = append(prefix, 0, byte(proto), byte(len(whole)>>8), byte(len(whole)))
		case 4:
			pseudo = append(prefix, byte(len(whole)>>24), byte(len(whole)>>16), byte(len(whole)>>8), byte(len(whole)), 0, 0, 0, byte(proto))
		}
		binary.BigEndian.PutUint16(body[at:], ^fold(0, pseudo))
	}
}

func verify(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		if fold(0, pkt[:20]) != 0xffff {
			return err("ipv4 header")
		}
		hl := int(pkt[0]&0x0f) * 4
		body := pkt[hl:]
		switch pkt[9] {
		case 6, 17:
			if transportOK(pkt[12:16], pkt[16:20], pkt[9], body) != 0xffff {
				return err("ipv4 transport")
			}
		case 1:
			if fold(0, body) != 0xffff {
				return err("icmp")
			}
		}
	case 6:
		off, proto, ok := ipv6TransportOff(pkt)
		if !ok {
			return err("ipv6 parse")
		}
		body := pkt[off:]
		switch proto {
		case 6, 17:
			if transportOKv6(pkt[8:24], pkt[24:40], proto, body) != 0xffff {
				return err("ipv6 transport")
			}
		case 58:
			if icmp6OK(pkt[8:24], pkt[24:40], body) != 0xffff {
				return err("icmpv6")
			}
		}
	}
	return nil
}

func transportOK(src, dst []byte, proto byte, body []byte) uint16 {
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, 0, proto, byte(len(body)>>8), byte(len(body)))
	return fold(uint32(fold(0, pseudo)), body)
}

func transportOKv6(src, dst []byte, proto byte, body []byte) uint16 {
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, byte(len(body)>>24), byte(len(body)>>16), byte(len(body)>>8), byte(len(body)), 0, 0, 0, byte(proto))
	return fold(uint32(fold(0, pseudo)), body)
}

func icmp6OK(src, dst, body []byte) uint16 {
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, byte(len(body)>>24), byte(len(body)>>16), byte(len(body)>>8), byte(len(body)), 0, 0, 0, 58)
	return fold(uint32(fold(0, pseudo)), body)
}

func fold(acc uint32, b []byte) uint16 {
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

func err(s string) error { return &verifyError{s} }

type verifyError struct{ msg string }

func (e *verifyError) Error() string { return e.msg }
