package censor

import (
	"encoding/binary"
	"net/netip"
)

// buildRST answers a TCP packet with the RST a censor sends to break the
// connection: an RST in the other direction, with a sequence number the
// peer believes for its own connection (RFC 793's reset rules).
func buildRST(p *Packet) []byte {
	rst := make([]byte, 20)
	binary.BigEndian.PutUint16(rst, p.DstPort)
	binary.BigEndian.PutUint16(rst[2:], p.SrcPort)
	flags := Rst
	if p.Flags&Ack != 0 {
		// The peer has acknowledged something: an RST with the sequence
		// number it expects acknowledged next.
		binary.BigEndian.PutUint32(rst[4:], p.Ack)
	} else {
		// No ACK yet: acknowledge what the peer sent, SYN and FIN
		// included, so it takes the RST for its own connection.
		flags |= Ack
		binary.BigEndian.PutUint32(rst[8:], p.Seq+uint32(len(p.Payload))+uint32(synOrFin(p.Flags)))
	}
	rst[12] = 5 << 4
	rst[13] = flags

	// The RST travels the other way: the packet's destination is its
	// source.
	if p.Dst.Is4() {
		return buildTCP4(p.Dst, p.Src, rst)
	}
	return buildTCP6(p.Dst, p.Src, rst)
}

// synOrFin is 1 when the packet opens or closes the connection, since
// either counts one towards the sequence number.
func synOrFin(flags uint8) uint8 {
	if flags&(Syn|Fin) != 0 {
		return 1
	}
	return 0
}

func buildTCP4(src, dst netip.Addr, tcp []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = byte(ProtoTCP)
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	out := append(ip, tcp...)
	binary.BigEndian.PutUint16(out[20+16:], checksum(pseudo4(src, dst, tcp)))
	return out
}

func buildTCP6(src, dst netip.Addr, tcp []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = byte(ProtoTCP)
	ip[7] = 64
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())

	out := append(ip, tcp...)
	binary.BigEndian.PutUint16(out[40+16:], checksum(pseudo6(src, dst, tcp)))
	return out
}

// pseudo4 and pseudo6 build the TCP checksum's pseudo-header.
func pseudo4(src, dst netip.Addr, tcp []byte) []byte {
	p := make([]byte, 0, 12+len(tcp))
	p = append(p, src.AsSlice()...)
	p = append(p, dst.AsSlice()...)
	p = append(p, 0, byte(ProtoTCP))
	p = binary.BigEndian.AppendUint16(p, uint16(len(tcp)))
	return append(p, tcp...)
}

func pseudo6(src, dst netip.Addr, tcp []byte) []byte {
	p := make([]byte, 0, 40+len(tcp))
	p = append(p, src.AsSlice()...)
	p = append(p, dst.AsSlice()...)
	p = binary.BigEndian.AppendUint32(p, uint32(len(tcp)))
	p = append(p, 0, 0, 0, byte(ProtoTCP))
	return append(p, tcp...)
}

// checksum is the internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		switch {
		case i+1 < len(b):
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		default:
			sum += uint32(b[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
