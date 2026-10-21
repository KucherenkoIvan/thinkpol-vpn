package dataplane

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// devicePeer is a peer of one device: the router sends it the peer's
// overlay addresses, and WireGuard accepts AllowedIPs from it (a chain's
// exit also has the default routes there).
type devicePeer struct {
	OverlayPeer
	AllowedIPs []netip.Prefix
}

type egressDevice struct {
	egress *router.Egress
	wg     *wg.Device
	peers  []devicePeer // what WireGuard has
}

// deviceSet is the engine's WireGuard devices, one per router egress, by
// name, and the peers each has. It keeps a peer key on one device at a
// time: remove takes peers, and addresses of peers, off the devices they
// leave before add puts them anywhere, so every Bind's peers change in one
// step. The engine's mu guards it.
type deviceSet struct {
	key    netmap.WireGuardPrivateKey
	router *router.Router
	node   *path.Node
	log    *slog.Logger
	byName map[string]*egressDevice
}

// sectionPeers is what a section that can't run allows the running
// devices: their peers whose id, key and addresses it still lists.
func (ds *deviceSet) sectionPeers(s netmap.Section) map[string][]devicePeer {
	listed := make(map[netmap.NodeID]netmap.Peer, len(s.Peers))
	for _, p := range s.Peers {
		listed[p.ID] = p
	}
	want := make(map[string][]devicePeer, len(ds.byName))
	for name, d := range ds.byName {
		want[name] = nil
		for _, p := range d.peers {
			if q, ok := listed[p.ID]; ok && q.WireGuardKey == p.Key {
				p.Addresses = slices.DeleteFunc(slices.Clone(p.Addresses), func(a netip.Addr) bool { return !slices.Contains(q.Addresses, a) })
				p.AllowedIPs = slices.DeleteFunc(slices.Clone(p.AllowedIPs), func(a netip.Prefix) bool {
					return a.IsSingleIP() && !slices.Contains(p.Addresses, a.Addr())
				})
				want[name] = append(want[name], p)
			}
		}
	}
	return want
}

// remove takes from every device the peers, and the addresses of peers,
// that want no longer gives it, and closes the devices want has none for
// (when known). Nothing is added. setTable gives the router the table
// without the departing devices, before they close.
func (ds *deviceSet) remove(want map[string][]devicePeer, known bool, paths []path.Peer, setTable func() error) error {
	departing, changed, err := ds.shrink(want, known)
	if err != nil {
		return err
	}
	if !changed && len(departing) == 0 {
		return nil
	}
	binds := make(map[*path.Bind][]path.Peer, len(ds.byName))
	for name, d := range ds.byName {
		if departing[name] == nil {
			binds[d.wg.Bind()] = pathPeers(d.peers, paths)
		}
	}
	if err := ds.node.SetPeers(binds); err != nil {
		return err
	}
	// The router stops using departing egresses before their devices close.
	for name := range departing {
		delete(ds.byName, name)
	}
	if err := setTable(); err != nil {
		return err
	}
	var errs []error
	for _, d := range departing {
		errs = append(errs, d.wg.Close())
	}
	return errors.Join(errs...)
}

// shrink configures each staying device with the peers it keeps of want,
// and returns the devices that depart (want has none for them, when
// known) and whether any peers changed.
func (ds *deviceSet) shrink(want map[string][]devicePeer, known bool) (departing map[string]*egressDevice, changed bool, err error) {
	departing = make(map[string]*egressDevice)
	for name, d := range ds.byName {
		next, stays := want[name]
		if !stays && known {
			departing[name] = d
			continue
		}
		kept := keptPeers(d.peers, next)
		if samePeers(kept, d.peers) {
			continue
		}
		if err := d.wg.Configure(ds.key, wgPeers(kept)); err != nil {
			return nil, false, err
		}
		d.peers = kept
		changed = true
	}
	return departing, changed, nil
}

// keptPeers are the peers of have that next still has, with only the
// addresses and allowed IPs next still gives them.
func keptPeers(have, next []devicePeer) []devicePeer {
	byID := make(map[netmap.NodeID]devicePeer, len(next))
	for _, p := range next {
		byID[p.ID] = p
	}
	var kept []devicePeer
	for _, p := range have {
		q, ok := byID[p.ID]
		if !ok || q.Key != p.Key {
			continue
		}
		p.Addresses = slices.DeleteFunc(slices.Clone(p.Addresses), func(a netip.Addr) bool { return !slices.Contains(q.Addresses, a) })
		p.AllowedIPs = slices.DeleteFunc(slices.Clone(p.AllowedIPs), func(a netip.Prefix) bool { return !slices.Contains(q.AllowedIPs, a) })
		if len(p.AllowedIPs) > 0 {
			kept = append(kept, p)
		}
	}
	return kept
}

// add gives each device all of want, creating the devices it lacks. Call
// it after remove took peers off the devices they leave.
func (ds *deviceSet) add(want map[string][]devicePeer, paths []path.Peer, mtu int) error {
	for name := range want {
		if ds.byName[name] != nil {
			continue
		}
		egress, err := ds.router.NewEgress(name, mtu)
		if err != nil {
			return err
		}
		ds.byName[name] = &egressDevice{egress: egress, wg: wg.New(name, egress, ds.node.NewBind(), ds.log)}
	}
	binds := make(map[*path.Bind][]path.Peer, len(ds.byName))
	for name, d := range ds.byName {
		binds[d.wg.Bind()] = pathPeers(want[name], paths)
	}
	if err := ds.node.SetPeers(binds); err != nil {
		return err
	}
	for name, d := range ds.byName {
		if err := d.egress.SetMTU(mtu); err != nil {
			return err
		}
		if err := d.wg.Configure(ds.key, wgPeers(want[name])); err != nil {
			return err
		}
		d.peers = want[name]
	}
	return nil
}

// take empties the set and returns its devices, for the caller to close.
func (ds *deviceSet) take() map[string]*egressDevice {
	devices := ds.byName
	ds.byName = map[string]*egressDevice{}
	return devices
}

func pathPeers(peers []devicePeer, paths []path.Peer) []path.Peer {
	firstHops := make(map[path.NodeID][]path.NodeID, len(paths))
	for _, p := range paths {
		firstHops[p.ID] = p.FirstHops
	}
	out := make([]path.Peer, 0, len(peers))
	for _, p := range peers {
		id := path.NodeID(p.ID)
		out = append(out, path.Peer{ID: id, FirstHops: firstHops[id]})
	}
	return out
}

func wgPeers(peers []devicePeer) []wg.Peer {
	out := make([]wg.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, wg.Peer{Key: p.Key, Node: path.NodeID(p.ID), AllowedIPs: p.AllowedIPs})
	}
	return out
}

func samePeers(a, b []devicePeer) bool {
	return slices.EqualFunc(a, b, func(p, q devicePeer) bool {
		return p.ID == q.ID && p.Key == q.Key && slices.Equal(p.Addresses, q.Addresses) && slices.Equal(p.AllowedIPs, q.AllowedIPs)
	})
}
