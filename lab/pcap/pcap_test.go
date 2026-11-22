package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestPcapStreamDecodesSLL2(t *testing.T) {
	src4, dst4 := netip.MustParseAddr("172.20.0.3"), netip.MustParseAddr("172.21.0.2")
	src6, dst6 := netip.MustParseAddr("fd00::3"), netip.MustParseAddr("fd00:1::2")
	payload := []byte("hello lab\n")

	var stream bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(hdr[20:], linkSLL2)
	stream.Write(hdr)
	record := func(ifindex uint32, outgoing bool, ip []byte) {
		sll := make([]byte, 20)
		binary.BigEndian.PutUint32(sll[4:], ifindex)
		if outgoing {
			sll[10] = 4
		}
		frame := append(sll, ip...)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec, 1700000000)
		binary.LittleEndian.PutUint32(rec[4:], 5)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
		stream.Write(rec)
		stream.Write(frame)
	}
	record(7, false, udp4(src4, dst4, 40000, 9999, payload))
	record(9, true, udp6(src6, dst6, 40000, 9999, payload))
	stream.Write([]byte{1, 2, 3}) // a stream cut mid-record ends cleanly

	r, err := NewReader(&stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []Packet{
		{Ifindex: 7, Src: src4, Dst: dst4},
		{Ifindex: 9, Outgoing: true, Src: src6, Dst: dst6},
	} {
		got, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if got.Ifindex != want.Ifindex || got.Outgoing != want.Outgoing || got.Src != want.Src || got.Dst != want.Dst ||
			got.Proto != ProtoUDP || got.SrcPort != 40000 || got.DstPort != 9999 || !bytes.Equal(got.Payload, payload) {
			t.Errorf("decoded %+v", got)
		}
		if !got.Time.Equal(time.Unix(1700000000, 5000)) {
			t.Errorf("time %v", got.Time)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("after the last record: %v", err)
	}
}

func udp4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20+8+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8], ip[9] = 64, ProtoUDP
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	udp(ip[20:], sport, dport, payload)
	return ip
}

func udp6(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 40+8+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+len(payload)))
	ip[6], ip[7] = ProtoUDP, 64
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())
	udp(ip[40:], sport, dport, payload)
	return ip
}

func udp(b []byte, sport, dport uint16, payload []byte) {
	binary.BigEndian.PutUint16(b, sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	copy(b[8:], payload)
}
