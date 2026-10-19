package lab

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/ip"
)

// IP protocol numbers, for Packet.Proto.
const (
	ProtoICMP   = 1
	ProtoIGMP   = 2
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// Packet is one captured IP packet, decoded as far as the tests need.
type Packet struct {
	Time time.Time
	// Ifindex is the interface it was seen on, in the capturing node's
	// network namespace; Network is the lab network of that interface ("" for
	// one the lab didn't create, like a TUN).
	Ifindex int
	Network string
	// Outgoing is set when the node sent the packet. A router sees each
	// forwarded packet twice: incoming on one network, outgoing on the other.
	Outgoing bool
	Src, Dst netip.Addr
	Proto    uint8
	// Ports are zero for protocols without them and for non-first fragments.
	SrcPort, DstPort uint16
	// Payload is what follows the TCP/UDP header; for ICMP it is the whole
	// ICMP message.
	Payload []byte
	// IP is the whole IP packet.
	IP []byte
}

// Link types tcpdump writes.
const (
	linkEthernet = 1
	linkRaw      = 101
	linkSLL      = 113
	linkSLL2     = 276
)

// pcapReader reads a pcap stream, as written by tcpdump -w -.
type pcapReader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	nano     bool
	linkType uint32
	// truncated counts records cut short of the frame on the wire, which
	// next can't decode and skips.
	truncated int
}

func newPcapReader(r io.Reader) (*pcapReader, error) {
	br := bufio.NewReader(r)
	var hdr [24]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	p := &pcapReader{r: br}
	switch {
	case binary.LittleEndian.Uint32(hdr[:]) == 0xa1b2c3d4:
		p.order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr[:]) == 0xa1b2c3d4:
		p.order = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr[:]) == 0xa1b23c4d:
		p.order, p.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr[:]) == 0xa1b23c4d:
		p.order, p.nano = binary.BigEndian, true
	default:
		return nil, errors.New("pcap: bad magic")
	}
	p.linkType = p.order.Uint32(hdr[20:]) & 0x0fffffff
	return p, nil
}

// next returns the next IP packet, skipping frames that carry anything else
// (ARP, for instance). It returns io.EOF at the end of the stream.
func (p *pcapReader) next() (Packet, error) {
	for {
		var rec [16]byte
		if _, err := io.ReadFull(p.r, rec[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return Packet{}, io.EOF
			}
			return Packet{}, err
		}
		sec, frac := p.order.Uint32(rec[0:]), p.order.Uint32(rec[4:])
		n, orig := p.order.Uint32(rec[8:]), p.order.Uint32(rec[12:])
		if orig > n {
			p.truncated++
		}
		if n > 1<<20 {
			return Packet{}, fmt.Errorf("pcap: record of %d bytes", n)
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(p.r, frame); err != nil {
			return Packet{}, io.EOF
		}
		if !p.nano {
			frac *= 1000
		}
		pkt, ok := decodeFrame(p.linkType, frame)
		if !ok {
			continue
		}
		pkt.Time = time.Unix(int64(sec), int64(frac))
		return pkt, nil
	}
}

// decodeFrame strips the link-layer header and decodes the IP packet.
func decodeFrame(linkType uint32, frame []byte) (Packet, bool) {
	var pkt Packet
	var b []byte
	switch linkType {
	case linkSLL2:
		if len(frame) < 20 {
			return pkt, false
		}
		pkt.Ifindex = int(binary.BigEndian.Uint32(frame[4:]))
		pkt.Outgoing = frame[10] == 4
		b = frame[20:]
	case linkSLL:
		if len(frame) < 16 {
			return pkt, false
		}
		pkt.Outgoing = binary.BigEndian.Uint16(frame[0:]) == 4
		b = frame[16:]
	case linkEthernet:
		if len(frame) < 14 {
			return pkt, false
		}
		b = frame[14:]
	case linkRaw:
		b = frame
	default:
		return pkt, false
	}
	return pkt, decodeIP(&pkt, b)
}

func decodeIP(pkt *Packet, b []byte) bool {
	h, ok := ip.Decode(b)
	if !ok {
		return false
	}
	pkt.Src, pkt.Dst, pkt.Proto = h.Src, h.Dst, h.Proto
	pkt.IP, pkt.Payload = h.Bytes, h.Payload
	if h.LaterFragment {
		return true
	}
	switch h.Proto {
	case ProtoUDP:
		if len(h.Payload) >= 8 {
			pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(h.Payload), binary.BigEndian.Uint16(h.Payload[2:])
			pkt.Payload = h.Payload[8:]
		}
	case ProtoTCP:
		if len(h.Payload) >= 20 {
			pkt.SrcPort, pkt.DstPort = binary.BigEndian.Uint16(h.Payload), binary.BigEndian.Uint16(h.Payload[2:])
			if off := int(h.Payload[12]>>4) * 4; off >= 20 && off <= len(h.Payload) {
				pkt.Payload = h.Payload[off:]
			}
		}
	}
	return true
}
