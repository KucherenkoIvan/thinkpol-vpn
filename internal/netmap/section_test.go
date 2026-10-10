package netmap

import (
	"testing"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// TestSectionFromProtoIsStrict: every value has exactly one accepted
// encoding, so two nodes never read one section differently.
func TestSectionFromProtoIsStrict(t *testing.T) {
	f := newFixture(t, 1, 2)
	device := f.contents.Sections[1].Section
	good := func() *netmapv1.Section { return sectionToProto(&device, f.contents.SpaceID, 1) }
	if _, err := sectionFromProto(good()); err != nil {
		t.Fatalf("control: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(pb *netmapv1.Section)
	}{
		{"no node settings", func(pb *netmapv1.Section) { pb.Node = nil }},
		{"short node id", func(pb *netmapv1.Section) { pb.Node.Id = pb.Node.Id[:7] }},
		{"long node id", func(pb *netmapv1.Section) { pb.Node.Id = append(pb.Node.Id, 0) }},
		{"kind overflowing", func(pb *netmapv1.Section) { pb.Node.Kind = 257 }},
		{"IPv4 with leading zeros", func(pb *netmapv1.Section) { pb.Node.Ipv4 = "100.100.000.002" }},
		{"IPv6 upper case", func(pb *netmapv1.Section) { pb.Node.Ipv6 = "FD12:3456:789A::2" }},
		{"IPv6 not compressed", func(pb *netmapv1.Section) { pb.Node.Ipv6 = "fd12:3456:789a:0:0:0:0:2" }},
		{"IPv6 with zone", func(pb *netmapv1.Section) { pb.Node.Ipv6 = "fd12:3456:789a::2%eth0" }},
		{"IPv4-mapped IPv6", func(pb *netmapv1.Section) { pb.Node.Ipv4 = "::ffff:100.100.0.2" }},
		{"empty address", func(pb *netmapv1.Section) { pb.Node.Ipv4 = "" }},
		{"prefix not canonical", func(pb *netmapv1.Section) { pb.Node.Ipv6Network = "fd12:3456:789a:0::/48" }},
		{"peer id short", func(pb *netmapv1.Section) { pb.Peers[0].Id = []byte{1} }},
		{"WireGuard key short", func(pb *netmapv1.Section) { pb.Peers[0].WireguardPublicKey = pb.Peers[0].WireguardPublicKey[:31] }},
		{"peer address not canonical", func(pb *netmapv1.Section) { pb.Peers[0].Addresses[1] = "FD12:3456:789A::3" }},
		{"path hop short", func(pb *netmapv1.Section) { pb.Peers[0].Paths[0].Via[0] = []byte{1, 2} }},
		{"link peer missing", func(pb *netmapv1.Section) { pb.Links[0].Peer = nil }},
		{"inbound peer short", func(pb *netmapv1.Section) {
			pb.Inbound = []*netmapv1.InboundLink{{Peer: []byte{1}, Transport: "udp", Credential: []byte{1}}}
		}},
		{"relay id short", func(pb *netmapv1.Section) { pb.RelayTo = [][]byte{{1}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := good()
			tt.mutate(pb)
			s, err := sectionFromProto(pb)
			if err == nil {
				err = s.validate()
			}
			if err == nil {
				t.Error("accepted")
			}
		})
	}
}
