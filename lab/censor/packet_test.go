package censor

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) *Packet {
	return &Packet{Src: src, Dst: dst, Proto: ProtoUDP, SrcPort: sport, DstPort: dport, Payload: payload}
}

func TestDecodePacket(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")
	payload := []byte("censored")

	udp := make([]byte, 20+8+len(payload))
	udp[0] = 0x45
	binary.BigEndian.PutUint16(udp[2:], uint16(len(udp)))
	udp[8], udp[9] = 64, byte(ProtoUDP)
	copy(udp[12:], src.AsSlice())
	copy(udp[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(udp[20:], 40000)
	binary.BigEndian.PutUint16(udp[22:], 4500)
	copy(udp[28:], payload)

	p, ok := decodePacket(udp)
	if !ok {
		t.Fatal("udp not decoded")
	}
	if p.Src != src || p.Dst != dst || p.Proto != ProtoUDP || p.SrcPort != 40000 || p.DstPort != 4500 || !bytes.Equal(p.Payload, payload) {
		t.Errorf("decoded %+v", p)
	}

	// TCP: ports, flags and the payload behind the header.
	tcp := make([]byte, 20+20+4)
	tcp[0] = 0x45
	binary.BigEndian.PutUint16(tcp[2:], uint16(len(tcp)))
	tcp[9] = byte(ProtoTCP)
	copy(tcp[12:], dst.AsSlice())
	copy(tcp[16:], src.AsSlice())
	binary.BigEndian.PutUint16(tcp[20:], 443)
	binary.BigEndian.PutUint16(tcp[22:], 5000)
	binary.BigEndian.PutUint32(tcp[24:], 7)
	binary.BigEndian.PutUint32(tcp[28:], 8)
	tcp[32] = 5 << 4
	tcp[33] = Ack | Psh
	copy(tcp[40:], "abcd")

	p, ok = decodePacket(tcp)
	if !ok {
		t.Fatal("tcp not decoded")
	}
	if p.Proto != ProtoTCP || p.SrcPort != 443 || p.DstPort != 5000 || p.Seq != 7 || p.Ack != 8 || p.Flags != Ack|Psh || string(p.Payload) != "abcd" {
		t.Errorf("decoded %+v", p)
	}

	// A later fragment has no ports to judge: not decodable, accepted.
	frag := append([]byte(nil), udp[:28]...)
	binary.BigEndian.PutUint16(frag[6:], 0x2000|1) // more fragments, offset 1
	if _, ok := decodePacket(frag); ok {
		t.Error("a later fragment decoded")
	}

	if _, ok := decodePacket([]byte{0x01, 0x02, 0x03}); ok {
		t.Error("junk decoded")
	}
}

func TestDecodePacketIPv6ThroughExtensions(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	ip := make([]byte, 40+8+8+8+3) // IPv6, hop-by-hop, fragment, UDP
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+8+8+3))
	ip[6] = 0 // the hop-by-hop header comes first
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())
	ip[40], ip[41] = 44, 0 // hop-by-hop: 8 bytes, then the fragment header
	ip[48] = byte(ProtoUDP)
	binary.BigEndian.PutUint16(ip[50:], 0) // offset 0: a first fragment
	binary.BigEndian.PutUint16(ip[56:], 1234)
	binary.BigEndian.PutUint16(ip[58:], 9999)
	copy(ip[64:], "abc")

	p, ok := decodePacket(ip)
	if !ok {
		t.Fatal("ipv6 not decoded")
	}
	if p.Proto != ProtoUDP || p.SrcPort != 1234 || p.DstPort != 9999 || string(p.Payload) != "abc" {
		t.Errorf("decoded %+v", p)
	}
}
