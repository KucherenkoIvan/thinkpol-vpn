package blobs

import (
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// PlanFrom is what a node's map asks of its service: a node that only
// fetches (a device) holds the blobs its section names; one that serves
// (a server's worker) every blob of the header, the availability set it
// passes on, named where its section names them. A
// section's blob the header doesn't list with the same kind and size, or
// whose kind and name (or hash) an earlier one has, is left out and
// reported in Skipped (readers don't check this, the builder does). Peers
// are the section's WireGuard peers in order, at their overlay addresses
// (IPv4 first, IPv6 only while the overlay carries it). Only a node that
// serves listens, on its own overlay addresses: on a device nothing
// answers on the blob port. iface is the overlay's TUN.
func PlanFrom(header []netmap.BlobRef, s netmap.Section, ipv6 bool, iface string, serve bool) Plan {
	inHeader := make(map[[32]byte]netmap.BlobRef, len(header))
	for _, ref := range header {
		inHeader[ref.SHA256] = ref
	}
	named := map[[32]byte]netmap.BlobRef{}
	type kindName struct {
		kind netmap.BlobKind
		name string
	}
	names := map[kindName]bool{}
	p := Plan{Interface: iface}
	var own []netmap.BlobRef
	for _, ref := range s.Blobs {
		h, ok := inHeader[ref.SHA256]
		_, dupHash := named[ref.SHA256]
		switch {
		case !ok || h.Kind != ref.Kind || h.Size != ref.Size:
			p.Skipped = append(p.Skipped, Skipped{ref, "not in the map's header with this kind and size"})
		case dupHash:
			p.Skipped = append(p.Skipped, Skipped{ref, "the section names this blob twice"})
		case names[kindName{ref.Kind, ref.Name}]:
			p.Skipped = append(p.Skipped, Skipped{ref, "the section names two blobs of this kind alike; the first is used"})
		default:
			named[ref.SHA256] = ref
			names[kindName{ref.Kind, ref.Name}] = true
			own = append(own, ref)
		}
	}
	p.Want = own
	if serve {
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
			p.Local = append(p.Local, a)
		}
	}
	if serve {
		p.Listen = p.Local
	}
	return p
}
