package ip

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDecode(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")

	udp := make([]byte, 20+8+2)
	udp[0] = 0x45
	binary.BigEndian.PutUint16(udp[2:], uint16(len(udp)))
	udp[9] = 17
	copy(udp[12:], src.AsSlice())
	copy(udp[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(udp[26:], 1234)

	h, ok := Decode(append(udp, 0xff, 0xff))
	if !ok {
		t.Fatal("ipv4 not decoded")
	}
	if h.Src != src || h.Dst != dst || h.Proto != 17 || h.LaterFragment || !bytes.Equal(h.Payload, udp[20:]) || !bytes.Equal(h.Bytes, udp) {
		t.Errorf("decoded %+v", h)
	}

	// A first fragment (more fragments, offset 0) counts as first.
	binary.BigEndian.PutUint16(udp[6:], 0x2000)
	if h, ok := Decode(udp); !ok || h.LaterFragment {
		t.Errorf("first fragment: ok=%v later=%v", ok, h.LaterFragment)
	}
	// A later fragment: decodable, without a transport header.
	binary.BigEndian.PutUint16(udp[6:], 1)
	if h, ok := Decode(udp); !ok || !h.LaterFragment {
		t.Errorf("later fragment: ok=%v later=%v", ok, h.LaterFragment)
	}

	if _, ok := Decode([]byte{0x45, 0}); ok {
		t.Error("a short IPv4 packet decoded")
	}
	if _, ok := Decode([]byte{0x60, 0, 0, 0}); ok {
		t.Error("a short IPv6 packet decoded")
	}
	if _, ok := Decode([]byte{0x10, 0, 0, 0}); ok {
		t.Error("a non-IP packet decoded")
	}
}

func TestDecodeIPv6LaterFragmentBehindOptions(t *testing.T) {
	src, dst := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	ip := make([]byte, 40+8+8+3)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(ip)-40))
	ip[6] = 60 // destination options, then the fragment header
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())
	ip[40], ip[41] = 44, 0
	ip[48] = 17
	binary.BigEndian.PutUint16(ip[50:], 8) // offset 1: a later fragment

	h, ok := Decode(ip)
	if !ok {
		t.Fatal("ipv6 not decoded")
	}
	if h.Src != src || h.Dst != dst || h.Proto != 17 || !h.LaterFragment {
		t.Errorf("decoded %+v", h)
	}
}
