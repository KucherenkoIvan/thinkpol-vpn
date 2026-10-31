package censor

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/ip"
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
	rst := rstToSender(syn)
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
	rst = rstToSender(psh)
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
	rst := rstToSender(syn)
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

// TestRSTToReceiver: the RST toward a data packet's receiver comes from
// the packet's source, at the sequence number the receiver still expects,
// with a checksum the receiver accepts; a SYN's receiver gets none.
func TestRSTToReceiver(t *testing.T) {
	for _, src := range []string{"192.0.2.1", "2001:db8::1"} {
		dst := "198.51.100.2"
		if src != "192.0.2.1" {
			dst = "2001:db8::2"
		}
		p := tcpPacket(netip.MustParseAddr(src), netip.MustParseAddr(dst), 40000, 443, 7000, 900, Ack|Psh, []byte("hello"))
		rst, ok := rstToReceiver(p)
		if !ok {
			t.Fatalf("%s: no RST for a data packet's receiver", src)
		}
		h, ok := ip.Decode(rst)
		if !ok || h.Src != p.Src || h.Dst != p.Dst || h.Proto != uint8(ProtoTCP) {
			t.Fatalf("%s: RST header %+v", src, h)
		}
		tcp := h.Payload
		if binary.BigEndian.Uint16(tcp) != 40000 || binary.BigEndian.Uint16(tcp[2:]) != 443 {
			t.Errorf("%s: ports %d -> %d, want the packet's", src, binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:]))
		}
		if seq := binary.BigEndian.Uint32(tcp[4:]); seq != 7000 || tcp[13] != Rst {
			t.Errorf("%s: seq %d flags %#x, want the dropped packet's seq 7000 and RST", src, seq, tcp[13])
		}
		pseudo := pseudo4(h.Src, h.Dst, tcp)
		if h.Src.Is6() {
			pseudo = pseudo6(h.Src, h.Dst, tcp)
		}
		if checksum(pseudo) != 0 {
			t.Errorf("%s: TCP checksum doesn't verify", src)
		}
	}
	syn := tcpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 40000, 443, 100, 0, Syn, nil)
	if _, ok := rstToReceiver(syn); ok {
		t.Error("an RST for a SYN's receiver, which has no connection")
	}
	// A SYN-ACK's receiver, in SYN-SENT, takes only an RST acknowledging
	// its SYN.
	synAck := tcpPacket(netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("192.0.2.1"), 443, 40000, 5000, 101, Syn|Ack, nil)
	rst, ok := rstToReceiver(synAck)
	if !ok {
		t.Fatal("no RST for a SYN-ACK's receiver")
	}
	h, _ := ip.Decode(rst)
	if tcp := h.Payload; tcp[13] != Rst|Ack || binary.BigEndian.Uint32(tcp[8:]) != 101 || checksum(pseudo4(h.Src, h.Dst, tcp)) != 0 {
		t.Errorf("RST for a SYN-ACK: flags %#x ack %d, want RST|ACK acknowledging 101", tcp[13], binary.BigEndian.Uint32(tcp[8:]))
	}
}
