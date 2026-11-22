package lab

import "github.com/KucherenkoIvan/thinkpol-vpn/lab/pcap"

// IP protocol numbers, for Packet.Proto.
const (
	ProtoICMP   = pcap.ProtoICMP
	ProtoIGMP   = pcap.ProtoIGMP
	ProtoTCP    = pcap.ProtoTCP
	ProtoUDP    = pcap.ProtoUDP
	ProtoICMPv6 = pcap.ProtoICMPv6
)

// Packet is one captured IP packet, decoded as far as the tests need
// (lab/pcap reads it).
type Packet = pcap.Packet
