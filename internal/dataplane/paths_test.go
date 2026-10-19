package dataplane_test

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func nid(b byte) netmap.NodeID { return netmap.NodeID{b} }

func pid(b byte) path.NodeID { return path.NodeID{b} }

// A section as the map's reader may hand it over: well formed, but with
// everything only the map builder would have refused.
func TestPathConfigSkipsWhatItCannotUse(t *testing.T) {
	reg, err := transport.NewRegistry(udp.New(udp.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, udp.MinSecretSize)
	good := netmap.Endpoint{Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.1:4500"), Credential: secret}
	with := func(f func(*netmap.Endpoint)) netmap.Endpoint { e := good; f(&e); return e }
	buckets := transport.Shaping{Padding: transporttest.Buckets(256, 1280)}
	encoded, err := buckets.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	shaped := with(func(e *netmap.Endpoint) { e.Shaping = encoded })

	const self, relay, entry, device, stranger, nowhere = 1, 2, 3, 4, 5, 6
	s := netmap.Section{
		Node: netmap.NodeSettings{ID: nid(self)},
		Links: []netmap.Link{
			{Peer: nid(relay), Endpoints: []netmap.Endpoint{
				with(func(e *netmap.Endpoint) { e.Transport = "carrier-pigeon" }),
				with(func(e *netmap.Endpoint) { e.Address = netip.AddrPort{} }),
				with(func(e *netmap.Endpoint) { e.Address = netip.MustParseAddrPort("0.0.0.0:4500") }),
				with(func(e *netmap.Endpoint) { e.Credential = []byte("short") }),
				with(func(e *netmap.Endpoint) { e.Shaping = []byte{0xff, 0xff} }),
				shaped,
			}},
			{Peer: nid(nowhere), Endpoints: []netmap.Endpoint{with(func(e *netmap.Endpoint) { e.Transport = "tls" })}},
			{Peer: nid(self), Endpoints: []netmap.Endpoint{good}},
		},
		Inbound: []netmap.InboundLink{{Peer: nid(entry)}, {Peer: nid(device)}},
		Routes: []netmap.Route{
			{Destination: nid(device), NextHops: []netmap.NodeID{nid(stranger), nid(device)}},
			{Destination: nid(stranger), NextHops: []netmap.NodeID{nid(stranger), nid(self)}},
			{Destination: nid(self), NextHops: []netmap.NodeID{nid(relay)}},
			{Destination: nid(nowhere)},
		},
		Peers: []netmap.Peer{
			{ID: nid(device), Paths: []netmap.Path{{FirstHop: nid(nowhere)}, {FirstHop: nid(relay)}, {FirstHop: nid(entry)}}},
			{ID: nid(stranger), Paths: []netmap.Path{{FirstHop: nid(stranger)}}},
			{ID: nid(self), Paths: []netmap.Path{{FirstHop: nid(relay)}}},
		},
	}
	c := dataplane.PathConfigFrom(s, reg)

	if len(c.Table.Links) != 1 || c.Table.Links[0].Node != pid(relay) || len(c.Table.Links[0].Endpoints) != 1 {
		t.Fatalf("links %+v, want the relay with its one good endpoint", c.Table.Links)
	}
	if ep := c.Table.Links[0].Endpoints[0]; ep.Address != "192.0.2.1:4500" || ep.Transport != "udp" || !bytes.Equal(ep.Config.Credential, secret) || ep.Dialer == nil || ep.Config.Shaping != buckets {
		t.Fatalf("endpoint %+v", ep)
	}
	want := []path.Route{{Destination: pid(device), NextHops: []path.NodeID{pid(device)}}}
	if !slices.EqualFunc(c.Table.Routes, want, func(a, b path.Route) bool {
		return a.Destination == b.Destination && slices.Equal(a.NextHops, b.NextHops)
	}) {
		t.Fatalf("routes %+v, want %+v", c.Table.Routes, want)
	}
	if len(c.Peers) != 2 ||
		c.Peers[0].ID != pid(device) || !slices.Equal(c.Peers[0].FirstHops, []path.NodeID{pid(relay), pid(entry)}) ||
		c.Peers[1].ID != pid(stranger) || len(c.Peers[1].FirstHops) != 0 {
		t.Fatalf("peers %+v, want the device through the relay and the entry, and the stranger with no path", c.Peers)
	}
	var details strings.Builder
	got := make(map[dataplane.Skip]bool)
	for _, d := range c.Skipped {
		details.WriteString(d.Error() + "\n")
		got[d.Skip] = true
	}
	for _, want := range []dataplane.Skip{
		{Node: nid(relay), What: dataplane.ItemEndpoint, Reason: dataplane.ReasonUnknownTransport},
		{Node: nid(relay), What: dataplane.ItemEndpoint, Reason: dataplane.ReasonUnusableAddress},
		{Node: nid(relay), What: dataplane.ItemEndpoint, Reason: dataplane.ReasonRefused},
		{Node: nid(relay), What: dataplane.ItemEndpoint, Reason: dataplane.ReasonBadShaping},
		{Node: nid(nowhere), What: dataplane.ItemLink, Reason: dataplane.ReasonNoEndpoint},
		{Node: nid(self), What: dataplane.ItemLink, Reason: dataplane.ReasonNotANode},
		{Node: nid(device), What: dataplane.ItemHop, Reason: dataplane.ReasonNotAdjacent},
		{Node: nid(stranger), What: dataplane.ItemRoute, Reason: dataplane.ReasonNoNextHop},
		{Node: nid(self), What: dataplane.ItemRoute, Reason: dataplane.ReasonNotANode},
		{Node: nid(stranger), What: dataplane.ItemPeer, Reason: dataplane.ReasonNoPath},
		{Node: nid(self), What: dataplane.ItemPeer, Reason: dataplane.ReasonNotANode},
	} {
		if !got[want] {
			t.Errorf("no skip %v among:\n%s", want, details.String())
		}
	}
	// The details quote the map; the skips never do.
	if !strings.Contains(details.String(), "carrier-pigeon") {
		t.Errorf("details don't say which transport:\n%s", details.String())
	}
	for s := range got {
		if strings.Contains(s.String(), "192.0.2") || strings.Contains(s.String(), "carrier-pigeon") {
			t.Errorf("skip %q quotes the map", s)
		}
	}
}
