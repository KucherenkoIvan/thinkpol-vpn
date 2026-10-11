package blobs

import (
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// PlanFrom is what a node's map asks of its service: a device holds the
// blobs its section names, a server every blob of the header (the
// availability set it passes on), named where its section names them. A
// section's blob the header doesn't list with the same kind and size is
// left out: no peer would serve it (the reader doesn't check this, the
// builder does). Peers are the section's WireGuard peers in order, at their
// overlay addresses (IPv4 first, IPv6 only while the overlay carries it);
// the service listens on the node's own. iface is the overlay's TUN.
func PlanFrom(header []netmap.BlobRef, s netmap.Section, ipv6 bool, iface string) Plan {
	inHeader := make(map[[32]byte]netmap.BlobRef, len(header))
	for _, ref := range header {
		inHeader[ref.SHA256] = ref
	}
	named := map[[32]byte]netmap.BlobRef{}
	var own []netmap.BlobRef
	for _, ref := range s.Blobs {
		h, ok := inHeader[ref.SHA256]
		if !ok || h.Kind != ref.Kind || h.Size != ref.Size {
			continue
		}
		if _, dup := named[ref.SHA256]; !dup {
			named[ref.SHA256] = ref
			own = append(own, ref)
		}
	}
	p := Plan{Want: own, Interface: iface}
	if s.Node.Kind == netmap.NodeServer {
		p.Want = nil
		for _, ref := range header {
			if n, ok := named[ref.SHA256]; ok {
				ref = n
			}
			p.Want = append(p.Want, ref)
		}
	}

	carried := func(a netip.Addr) bool {
		return a.Is4() && s.Node.IPv4Network.Contains(a) || ipv6 && a.Is6() && !a.Is4In6() && s.Node.IPv6Network.Contains(a)
	}
	for _, peer := range s.Peers {
		var v4, v6 []netip.Addr
		for _, a := range peer.Addresses {
			switch {
			case !carried(a):
			case a.Is4():
				v4 = append(v4, a)
			default:
				v6 = append(v6, a)
			}
		}
		if addrs := append(v4, v6...); len(addrs) > 0 {
			p.Peers = append(p.Peers, Peer{ID: peer.ID, Addrs: addrs})
		}
	}
	for _, a := range []netip.Addr{s.Node.IPv4, s.Node.IPv6} {
		if a.IsValid() && carried(a) {
			p.Listen = append(p.Listen, a)
		}
	}
	return p
}
