// Package pcap reads the pcap stream tcpdump writes (`tcpdump -w -`) and
// decodes its IP packets: the lab's captures and the device-test harness's
// (lab/devicetest) read packets with this one reader, so they agree on
// what a capture holds.
package pcap

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
	// network namespace (Linux cooked captures only); Network is the lab
	// network of that interface, which the lab fills in ("" for one the
	// lab didn't create, like a TUN).
	Ifindex int
	Network string
	// Outgoing is set when the node sent the packet (Linux cooked captures
	// only). A router sees each forwarded packet twice: incoming on one
	// network, outgoing on the other.
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

// Record is one record of the stream as it was read: Raw is its record
// header and frame, so a copy of the stream can be cut at a record's end;
// IsIP says Packet holds the frame's IP packet.
type Record struct {
	Raw    []byte
	Packet Packet
	IsIP   bool
}

// Link types tcpdump writes.
const (
	linkEthernet = 1
	linkRaw      = 101
	linkSLL      = 113
	linkSLL2     = 276
)

// headerLen is the length of a pcap stream's file header.
const headerLen = 24

// Reader reads a pcap stream.
type Reader struct {
	r        *bufio.Reader
	header   []byte
	order    binary.ByteOrder
	nano     bool
	linkType uint32
	// truncated counts records cut short of the frame on the wire, which
	// Next can't decode and skips.
	truncated int
}

// NewReader reads the stream's file header: an error for anything but a
// pcap stream (a pcapng file included).
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	p := &Reader{r: br, header: hdr}
	switch {
	case binary.LittleEndian.Uint32(hdr) == 0xa1b2c3d4:
		p.order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr) == 0xa1b2c3d4:
		p.order = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr) == 0xa1b23c4d:
		p.order, p.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr) == 0xa1b23c4d:
		p.order, p.nano = binary.BigEndian, true
	default:
		return nil, errors.New("pcap: bad magic")
	}
	p.linkType = p.order.Uint32(hdr[20:]) & 0x0fffffff
	return p, nil
}

// Header is the stream's file header, as read.
func (p *Reader) Header() []byte { return p.header }

// Truncated is how many records so far were cut short of their frame.
func (p *Reader) Truncated() int { return p.truncated }

// Next returns the next IP packet, skipping frames that carry anything else
// (ARP, for instance). It returns io.EOF at the end of the stream.
func (p *Reader) Next() (Packet, error) {
	for {
		rec, err := p.NextRecord()
		if err != nil {
			return Packet{}, err
		}
		if rec.IsIP {
			return rec.Packet, nil
		}
	}
}

// NextRecord returns the next record, IP or not. It returns io.EOF at the
// end of the stream, a record cut short included.
func (p *Reader) NextRecord() (Record, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(p.r, raw); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, io.EOF
		}
		return Record{}, err
	}
	sec, frac := p.order.Uint32(raw[0:]), p.order.Uint32(raw[4:])
	n, orig := p.order.Uint32(raw[8:]), p.order.Uint32(raw[12:])
	if orig > n {
		p.truncated++
	}
	if n > 1<<20 {
		return Record{}, fmt.Errorf("pcap: record of %d bytes", n)
	}
	raw = append(raw, make([]byte, n)...)
	if _, err := io.ReadFull(p.r, raw[16:]); err != nil {
		return Record{}, io.EOF
	}
	if !p.nano {
		frac *= 1000
	}
	pkt, ok := decodeFrame(p.linkType, raw[16:])
	pkt.Time = time.Unix(int64(sec), int64(frac))
	return Record{Raw: raw, Packet: pkt, IsIP: ok}, nil
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
