package localapi

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// statusProto is st on the wire. It copies only what agent.Status holds,
// which is free of public addresses, keys and secrets by construction.
// Names that come from the map or a transport (egresses, devices,
// transports) are sanitized here too, besides by every client.
func statusProto(st agent.Status) *localapiv1.Status {
	h := st.Health()
	out := &localapiv1.Status{
		Mode:       modeProto(st.Mode),
		SpaceId:    idString(st.Space),
		MapVersion: st.MapVersion,
		Removed:    st.Removed,
		Connection: connectionProto(st.Connection),
		Retrying:   st.Retrying,
		Health:     &localapiv1.Health{Level: healthProto(h.Level), Problems: h.Problems},
		RulePreset: st.RulePreset, RulesEnforced: st.RulesEnforced, RulePresetUnavailable: st.PresetUnavailable,
	}
	if dp := st.DataPlane; dp != nil {
		out.DataPlane = dataPlaneProto(dp, st.Listeners)
	}
	for _, w := range st.Workers {
		out.Workers = append(out.Workers, &localapiv1.Worker{
			SpaceId: idString(w.Space), Ready: w.Ready, Starts: uint32(w.Starts),
			ReadySince: timestamp(w.ReadySince), RestartAt: timestamp(w.RestartAt),
			LastExit: agent.Sanitize(w.LastExit),
		})
	}
	if e := st.Egress; e != nil {
		out.Uplink = &localapiv1.Uplink{
			Interface: agent.Sanitize(e.Uplink), Ipv4: e.IPv4, Ipv6: e.IPv6,
			Forwarding4: e.Forwarding4, Forwarding6: e.Forwarding6, Error: string(e.Err),
		}
	}
	for _, l := range st.PublicListeners {
		out.PublicListeners = append(out.PublicListeners, &localapiv1.PublicListener{
			Transport: agent.Sanitize(l.Transport), Routed: l.Routed, Unauthenticated: l.Unauthenticated, NoSpace: l.NoSpace,
			StreamsOverloaded: l.StreamsOverloaded, Rejected: uint32(l.Rejected),
		})
	}
	return out
}

func dataPlaneProto(dp *dataplane.Status, listeners int) *localapiv1.DataPlane {
	out := &localapiv1.DataPlane{
		Mtu: uint32(dp.MTU), Ipv6: dp.IPv6, Ipv6Off: string(dp.IPv6Off), LastApplyError: string(dp.LastApplyError),
		Listeners: uint32(listeners),
		Counters:  map[string]uint64{},
	}
	routeTable := dp.RouteTable.Enforced || dp.RouteTable.Error != ""
	for _, c := range dataPlaneCounters {
		if c.kind != routeTableCounter || routeTable {
			out.Counters[c.name] = c.of(dp)
		}
	}
	for _, p := range dp.Peers {
		pp := &localapiv1.Peer{
			NodeId: idString(p.ID), Device: agent.Sanitize(p.Device), FirstHop: idString(p.FirstHop),
			LastHandshake: timestamp(p.LastHandshake), RxBytes: p.RxBytes, TxBytes: p.TxBytes,
		}
		for _, a := range p.Addresses {
			pp.Addresses = append(pp.Addresses, a.String())
		}
		out.Peers = append(out.Peers, pp)
	}
	for _, n := range dp.Neighbors {
		np := &localapiv1.Neighbor{
			NodeId: idString(netmap.NodeID(n.Node)), Up: n.Up, UpFor: duration(n.UpFor), Rtt: duration(n.RTT), Dialed: n.Dialed,
		}
		for _, l := range n.Links {
			np.Links = append(np.Links, &localapiv1.Link{
				Transport: agent.Sanitize(l.Transport), Dialed: l.Dialed, Endpoint: int32(l.Endpoint), Active: l.Active, Up: l.Up,
				UpFor: duration(l.UpFor), Rtt: duration(l.RTT), PacketsIn: l.PacketsIn, PacketsOut: l.PacketsOut,
				BytesIn: l.BytesIn, BytesOut: l.BytesOut, QueueFull: l.QueueFull,
			})
		}
		out.Neighbors = append(out.Neighbors, np)
	}
	for _, e := range dp.Egresses {
		out.Egresses = append(out.Egresses, &localapiv1.Egress{
			Name: agent.Sanitize(e.Name), Mtu: uint32(e.MTU), Queued: uint32(e.Queued), Routed: e.Routed, Delivered: e.Delivered,
			NotLocal: e.NotLocal, QueueFull: e.QueueFull, TooLarge: e.TooLarge,
		})
	}
	for _, s := range dp.Skipped {
		out.Skipped = append(out.Skipped, &localapiv1.Skip{NodeId: idString(s.Node), Item: s.What.String(), Reason: s.Reason.String()})
	}
	return out
}

// counterKind is what a data plane counter counts.
type counterKind uint8

const (
	// dropCounter counts what was dropped: WriteStatus lists the nonzero
	// ones apart.
	dropCounter counterKind = iota
	// trafficCounter counts what went through, or is in place.
	trafficCounter
	// routeTableCounter is the route table's, sent only in route-table
	// mode (enforced, or failing to be); WriteStatus shows them apart.
	routeTableCounter
)

// dataPlaneCounters are the data plane's counters as the local API names
// them.
var dataPlaneCounters = []struct {
	name string
	kind counterKind
	of   func(dp *dataplane.Status) uint64
}{
	{"router.routed", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Routed }},
	{"router.delivered", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Delivered }},
	{"router.not_local", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.NotLocal }},
	{"router.forwarded", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Forwarded }},
	{"router.no_route", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.NoRoute }},
	{"router.blocked", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Blocked }},
	{"router.malformed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Malformed }},
	{"router.too_large", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.TooLarge }},
	{"router.queue_full", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.QueueFull }},
	{"router.read_errors", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.ReadErrors }},
	{"router.direct", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Direct }},
	{"router.reflected", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.Reflected }},
	{"router.reflect_failed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.ReflectFailed }},
	{"router.foreign_source", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Router.ForeignSource }},
	{"path.sent", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Path.Sent }},
	{"path.delivered", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Path.Delivered }},
	{"path.forwarded", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.Path.Forwarded }},
	{"path.no_route", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.NoRoute }},
	{"path.spoofed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.Spoofed }},
	{"path.hop_limit", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.HopLimit }},
	{"path.no_path", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.NoPath }},
	{"path.unknown_peer", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.UnknownPeer }},
	{"path.queue_full", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.QueueFull }},
	{"path.malformed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.Malformed }},
	{"path.other_space", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.OtherSpace }},
	{"path.too_large", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.TooLarge }},
	{"path.write_failed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.WriteFailed }},
	{"path.read_failed", dropCounter, func(dp *dataplane.Status) uint64 { return dp.Path.ReadFailed }},
	{"interface.reapplies", trafficCounter, func(dp *dataplane.Status) uint64 { return dp.InterfaceReapplies }},
	{"route_table.routes", routeTableCounter, func(dp *dataplane.Status) uint64 { return uint64(dp.RouteTable.Routes) }},
	{"route_table.reapplies", routeTableCounter, func(dp *dataplane.Status) uint64 { return dp.RouteTable.Reapplies }},
	{"route_table.rules_ahead", routeTableCounter, func(dp *dataplane.Status) uint64 { return uint64(dp.RouteTable.RulesAhead) }},
	{"route_table.overlay_routes_ahead", routeTableCounter, func(dp *dataplane.Status) uint64 { return uint64(dp.RouteTable.OverlayAhead) }},
}

// idString is an id in hex, empty for the zero id.
func idString[ID interface {
	String() string
	IsZero() bool
}](id ID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func duration(d time.Duration) *durationpb.Duration {
	if d == 0 {
		return nil
	}
	return durationpb.New(d)
}

func modeProto(m agent.Mode) localapiv1.Mode {
	switch m {
	case agent.ModeDevice:
		return localapiv1.Mode_MODE_DEVICE
	case agent.ModeServer:
		return localapiv1.Mode_MODE_SERVER
	}
	return localapiv1.Mode_MODE_UNSPECIFIED
}

func connectionProto(c agent.Connection) localapiv1.Connection {
	switch c {
	case agent.Disconnected:
		return localapiv1.Connection_CONNECTION_DISCONNECTED
	case agent.Connecting:
		return localapiv1.Connection_CONNECTION_CONNECTING
	case agent.Connected:
		return localapiv1.Connection_CONNECTION_CONNECTED
	case agent.Serving:
		return localapiv1.Connection_CONNECTION_SERVING
	}
	return localapiv1.Connection_CONNECTION_UNSPECIFIED
}

func healthProto(l agent.HealthLevel) localapiv1.HealthLevel {
	switch l {
	case agent.HealthOK:
		return localapiv1.HealthLevel_HEALTH_LEVEL_OK
	case agent.HealthDegraded:
		return localapiv1.HealthLevel_HEALTH_LEVEL_DEGRADED
	case agent.HealthDown:
		return localapiv1.HealthLevel_HEALTH_LEVEL_DOWN
	}
	return localapiv1.HealthLevel_HEALTH_LEVEL_UNSPECIFIED
}
