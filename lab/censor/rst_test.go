package censor

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestBuildRST checks the RST that answers a client's SYN: an RST|ACK in
// the other direction, acknowledging the SYN, ports swapped, checksums
// right.
func TestBuildRST(t *testing.T) {
	syn := &Packet{
		Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.2"),
		Proto: ProtoTCP, SrcPort: 40000, DstPort: 443,
		Seq: 100, Flags: Syn,
	}
	rst := buildRST(syn)
	if len(rst) != 40 {
		t.Fatalf("RST of %d bytes", len(rst))
	}
	if got := binary.BigEndian.Uint16(rst[20:]); got != 443 {
		t.Errorf("source port %d, want the packet's destination port 443", got)
	}
	if got := binary.BigEndian.Uint16(rst[22:]); got != 40000 {
		t.Errorf("destination port %d, want the packet's source port 40000", got)
	}
	if flags := rst[33]; flags != Rst|Ack {
		t.Errorf("flags %#x, want RST|ACK for a SYN without ACK", flags)
	}
	if got := binary.BigEndian.Uint32(rst[28:]); got != 101 {
		t.Errorf("ack %d, want the SYN's seq + 1", got)
	}
	if got := binary.BigEndian.Uint16(rst[10:]); got == 0 {
		t.Error("no IP checksum")
	}
	if got := binary.BigEndian.Uint16(rst[36:]); got == 0 {
		t.Error("no TCP checksum")
	}

	// An established connection's packet (with ACK) is answered with a
	// bare RST at the sequence the peer expects.
	psh := &Packet{
		Src: syn.Dst, Dst: syn.Src, Proto: ProtoTCP, SrcPort: 443, DstPort: 40000,
		Seq: 900, Ack: 200, Flags: Ack | Psh, Payload: []byte("12345"),
	}
	rst = buildRST(psh)
	if flags := rst[33]; flags != Rst {
		t.Errorf("flags %#x, want RST for a packet with ACK", flags)
	}
	if got := binary.BigEndian.Uint32(rst[24:]); got != 200 {
		t.Errorf("seq %d, want the packet's ack 200", got)
	}
}

// TestBuildRST6 is the same RST for IPv6, hop limit and checksums included.
func TestBuildRST6(t *testing.T) {
	syn := &Packet{
		Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("2001:db8::2"),
		Proto: ProtoTCP, SrcPort: 40000, DstPort: 443,
		Seq: 100, Flags: Syn,
	}
	rst := buildRST(syn)
	if len(rst) != 60 {
		t.Fatalf("RST of %d bytes", len(rst))
	}
	if rst[0] != 0x60 || rst[6] != byte(ProtoTCP) || rst[7] != 64 {
		t.Errorf("IPv6 header % x", rst[:8])
	}
	if got := binary.BigEndian.Uint16(rst[56:]); got == 0 {
		t.Error("no TCP checksum")
	}
}
