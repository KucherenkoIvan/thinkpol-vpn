package checksum_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/checksum"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/checksum/checksumtest"
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
		{"ipv6_routing_dest", udp6RoutingDest(sp6, dp6, []byte("rd"))},
		{"ipv4_options", ipv4WithOptions(sp4, dp4, []byte("opt"))},
	}
	for _, corrupt := range []string{"zero", "pseudo", "garbage"} {
		for _, c := range cases {
			t.Run(corrupt+"/"+c.name, func(t *testing.T) {
				pkt := corruptChecksum(bytes.Clone(c.pkt), corrupt)
				if checksumtest.OK(pkt) {
					t.Fatal("input should fail verification")
				}
				checksum.Fix(pkt)
				if !checksumtest.OK(pkt) {
					t.Fatal("oracle rejected fixed packet")
				}
			})
		}
	}
}

func TestFixIPv4FragmentLeavesL4(t *testing.T) {
	sp := netip.MustParseAddrPort("100.64.0.1:53000")
	dp := netip.MustParseAddrPort("100.64.0.1:53")
	whole := packettest.UDPDatagram(sp, dp, bytes.Repeat([]byte("x"), 2000))
	const fragPayload = 1480
	first := ipv4Fragment(whole, 0, true, fragPayload)
	later := ipv4Fragment(whole, fragPayload, false, len(whole)-20-fragPayload)

	for name, pkt := range map[string][]byte{"first": first, "later": later} {
		t.Run(name, func(t *testing.T) {
			pkt[10] ^= 0xff
			pkt[11] ^= 0xff
			if len(pkt) > 28 {
				pkt[26] ^= 0xaa
				pkt[27] ^= 0x55
			}
			l4Before := bytes.Clone(pkt[20:])
			checksum.Fix(pkt)
			if !bytes.Equal(pkt[20:], l4Before) {
				t.Fatal("L4 was modified on a fragment")
			}
			if !checksumtest.OK(pkt) {
				t.Fatal("IPv4 header checksum not fixed")
			}
		})
	}
}

func TestFixIPv6FragmentUnchanged(t *testing.T) {
	sp := netip.MustParseAddrPort("[fd00:1::1]:53000")
	dp := netip.MustParseAddrPort("[fd00:1::1]:53")
	udp := packettest.UDPDatagram(sp, dp, []byte("frag"))
	pkt := wrapIPv6Fragment(udp)
	pkt[10] ^= 0xff
	pkt[42] ^= 0xff
	want := bytes.Clone(pkt)
	checksum.Fix(pkt)
	if !bytes.Equal(pkt, want) {
		t.Fatal("fragmented IPv6 packet was modified")
	}
}

func TestFixIPv4UDPChecksumZero(t *testing.T) {
	sp := netip.MustParseAddrPort("100.64.0.1:53000")
	dp := netip.MustParseAddrPort("100.64.0.1:53")
	pkt := packettest.UDPDatagram(sp, dp, []byte{0, 0})
	pkt[26], pkt[27] = 0, 0
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:], 0xbeef)
	checksum.Fix(pkt)
	if !checksumtest.OK(pkt) {
		t.Fatal("fixed UDP v4")
	}
}

func TestFixExtLen255Terminates(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], 8)
	pkt[6] = 0
	pkt[40] = 0
	pkt[41] = 255
	want := bytes.Clone(pkt)
	done := make(chan struct{})
	go func() {
		checksum.Fix(pkt)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Fix hung on extension length 255")
	}
	if !bytes.Equal(pkt, want) {
		t.Fatal("packet changed")
	}
}

func TestFixBrokenExtensionChainUnchanged(t *testing.T) {
	pkt := make([]byte, 44)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], 4)
	pkt[6] = 43
	pkt[40] = 17
	pkt[41] = 1
	before := bytes.Clone(pkt)
	checksum.Fix(pkt)
	if !bytes.Equal(pkt, before) {
		t.Fatal("truncated IPv6 changed")
	}
}

func TestKnownVectors(t *testing.T) {
	for _, v := range knownVectors {
		pkt := bytes.Clone(v.raw)
		checksum.Fix(pkt)
		if !bytes.Equal(pkt, v.want) {
			t.Fatalf("%s: got %x want %x", v.name, pkt, v.want)
		}
		if !checksumtest.OK(pkt) {
			t.Fatalf("%s: oracle rejected", v.name)
		}
	}
}

var knownVectors = []struct {
	name string
	raw  []byte
	want []byte
}{
	{
		name: "ipv4_udp_min",
		raw: []byte{
			0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
			0x00, 0x00, 0x64, 0x40, 0x00, 0x01, 0x64, 0x40, 0x00, 0x01,
			0xcf, 0x08, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		},
		want: []byte{
			0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
			0xb2, 0x4f, 0x64, 0x40, 0x00, 0x01, 0x64, 0x40, 0x00, 0x01,
			0xcf, 0x08, 0x00, 0x35, 0x00, 0x08, 0x68, 0x1e, 0x01, 0x02, 0x03, 0x04,
		},
	},
	// 2001:db8::1:4660 -> 2001:db8::2:53, empty UDP; one's complement sum over
	// pseudo-header (src, dst, u32 8, zero u32, next=17) plus the UDP header = 0xffff → csum 0x9200.
	{
		name: "ipv6_udp_min",
		raw: []byte{
			0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
		},
		want: []byte{
			0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x92, 0x00,
		},
	},
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
	ext := []byte{17, 0, 0, 0, 0, 0, 0, 0}
	body := append(ext, udp...)
	return ip6(src.Addr(), dst.Addr(), 0, body)
}

func udp6RoutingDest(src, dst netip.AddrPort, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	route := []byte{60, 0, 0, 0, 0, 0, 0, 0}
	dest := []byte{17, 0, 0, 0, 0, 0, 0, 0}
	body := append(route, dest...)
	body = append(body, udp...)
	return ip6(src.Addr(), dst.Addr(), 43, body)
}

func ipv4WithOptions(src, dst netip.AddrPort, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	pkt := make([]byte, 24+len(udp))
	pkt[0] = 0x46
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = 17
	pkt[10] = 0x01
	pkt[11] = 0x04
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(pkt[12:], s[:])
	copy(pkt[16:], d[:])
	copy(pkt[24:], udp)
	fillGood(pkt, 17, s[:], d[:], udp, 24)
	return pkt
}

func ipv4Fragment(full []byte, payloadOff int, more bool, chunk int) []byte {
	hl := 20
	if int(full[0]&0x0f)*4 > hl {
		hl = int(full[0]&0x0f) * 4
	}
	total := int(binary.BigEndian.Uint16(full[2:4]))
	body := full[hl:total]
	start := payloadOff
	end := start + chunk
	if end > len(body) {
		end = len(body)
	}
	frag := make([]byte, hl+end-start)
	copy(frag[:hl], full[:hl])
	copy(frag[hl:], body[start:end])
	binary.BigEndian.PutUint16(frag[2:], uint16(len(frag)))
	off := payloadOff / 8
	frag[6] = byte(off >> 8)
	frag[7] = byte(off)
	if more {
		frag[6] |= 0x20
	}
	frag[10], frag[11] = 0, 0
	binary.BigEndian.PutUint16(frag[10:], 0)
	return frag
}

func wrapIPv6Fragment(udpPkt []byte) []byte {
	if len(udpPkt) < 40 {
		return udpPkt
	}
	payload := udpPkt[40:]
	frag := make([]byte, 48+len(payload))
	copy(frag[:40], udpPkt[:40])
	frag[6] = 44
	binary.BigEndian.PutUint16(frag[4:], uint16(8+len(payload)))
	frag[40] = 17
	frag[41] = 0
	frag[42] = 0
	frag[43] = 0
	copy(frag[48:], payload)
	return frag
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
	fillGood(pkt, proto, s[:], d[:], body, 20)
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
	fillGood(pkt, next, s[:], d[:], body, 40)
	return pkt
}

func fillGood(pkt []byte, proto int, src, dst []byte, body []byte, ipHL int) {
	if len(pkt) >= ipHL && pkt[0]>>4 == 4 {
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:], ^fold(0, pkt[:ipHL]))
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
		udp := body[8:]
		udp[6], udp[7] = 0, 0
		pseudo := append(append(src, dst...), byte(len(udp)>>24), byte(len(udp)>>16), byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
		c := ^fold(uint32(fold(0, pseudo)), udp)
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:], c)
	case 43:
		udp := body[16:]
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
		hl := int(pkt[0]&0x0f) * 4
		if hl < 20 {
			hl = 20
		}
		pkt[10] ^= 0xff
		pkt[11] ^= 0xff
		corruptTransport(pkt, how, hl)
	case 6:
		corruptIPv6(pkt, how)
	}
	return pkt
}

func corruptTransport(pkt []byte, how string, hl int) {
	if hl > len(pkt) {
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

func ipv6TransportOff(pkt []byte) (off int, proto byte, ok bool) {
	if len(pkt) < 40 {
		return 0, 0, false
	}
	proto = pkt[6]
	off = 40
	for n := 0; n < 8; n++ {
		switch proto {
		case 6, 17, 58:
			return off, proto, true
		case 44:
			return 0, 0, false
		case 0, 43, 60:
			if len(pkt) < off+2 {
				return 0, 0, false
			}
			next := pkt[off]
			extLen := (int(pkt[off+1]) + 1) * 8
			if extLen < 8 || len(pkt) < off+extLen {
				return 0, 0, false
			}
			proto = next
			off += extLen
		default:
			return 0, 0, false
		}
	}
	return 0, 0, false
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
