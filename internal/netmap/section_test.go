package netmap

import (
	"testing"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// TestSectionFromProtoIsStrict: every value has exactly one accepted
// encoding, so two nodes never read one section differently.
func TestSectionFromProtoIsStrict(t *testing.T) {
	f := newFixture(t, 4, 2)
	h := Header{SpaceID: f.contents.SpaceID, Version: 1}
	entry := f.contents.Recipients[0].Section
	device := f.contents.Recipients[4].Section
	good := func(s *Section) func() *netmapv1.Section {
		return func() *netmapv1.Section { return sectionToProto(s, &h) }
	}
	for _, s := range []*Section{&entry, &device} {
		got, err := sectionFromProto(good(s)())
		if err != nil || got.wellFormed() != nil {
			t.Fatalf("control: %v", err)
		}
	}

	tests := []struct {
		name   string
		of     *Section
		mutate func(pb *netmapv1.Section)
	}{
		{"no node settings", &device, func(pb *netmapv1.Section) { pb.Node = nil }},
		{"short node id", &device, func(pb *netmapv1.Section) { pb.Node.Id = pb.Node.Id[:7] }},
		{"long node id", &device, func(pb *netmapv1.Section) { pb.Node.Id = append(pb.Node.Id, 0) }},
		{"IPv4 with leading zeros", &device, func(pb *netmapv1.Section) { pb.Node.Ipv4 = "100.100.000.002" }},
		{"IPv6 upper case", &device, func(pb *netmapv1.Section) { pb.Node.Ipv6 = "FD12:3456:789A::2" }},
		{"IPv6 not compressed", &device, func(pb *netmapv1.Section) { pb.Node.Ipv6 = "fd12:3456:789a:0:0:0:0:2" }},
		{"IPv6 with zone", &device, func(pb *netmapv1.Section) { pb.Node.Ipv6 = "fd12:3456:789a::2%eth0" }},
		{"prefix not canonical", &device, func(pb *netmapv1.Section) { pb.Node.Ipv6Network = "fd12:3456:789a:0::/48" }},
		{"peer id short", &device, func(pb *netmapv1.Section) { pb.Peers[0].Id = []byte{1} }},
		{"WireGuard key short", &device, func(pb *netmapv1.Section) { pb.Peers[0].WireguardPublicKey = pb.Peers[0].WireguardPublicKey[:31] }},
		{"peer address not canonical", &device, func(pb *netmapv1.Section) { pb.Peers[0].Addresses[1] = "FD12:3456:789A::3" }},
		{"peer address empty", &device, func(pb *netmapv1.Section) { pb.Peers[0].Addresses[1] = "" }},
		{"first hop short", &device, func(pb *netmapv1.Section) { pb.Peers[0].Paths[0].FirstHop = []byte{1, 2} }},
		{"first hop zero", &device, func(pb *netmapv1.Section) { pb.Peers[0].Paths[0].FirstHop = make([]byte, 8) }},
		{"link peer missing", &device, func(pb *netmapv1.Section) { pb.Links[0].Peer = nil }},
		{"section blob hash short", &device, func(pb *netmapv1.Section) { pb.Blobs[0].Sha256 = []byte{1} }},
		{"section blob of size 0", &device, func(pb *netmapv1.Section) { pb.Blobs[0].Size = 0 }},
		{"inbound peer short", &entry, func(pb *netmapv1.Section) { pb.Inbound[0].Peer = []byte{1} }},
		{"route destination short", &entry, func(pb *netmapv1.Section) { pb.Routes[0].Destination = []byte{1} }},
		{"next hop short", &entry, func(pb *netmapv1.Section) { pb.Routes[0].NextHops[0] = []byte{1} }},
		{"next hop zero", &entry, func(pb *netmapv1.Section) { pb.Routes[0].NextHops[0] = make([]byte, 8) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := good(tt.of)()
			tt.mutate(pb)
			s, err := sectionFromProto(pb)
			if err == nil {
				err = s.wellFormed()
			}
			if err == nil {
				t.Error("accepted")
			}
		})
	}
}
