package agent

// EventKind is what happened to a node. Each is an edge, told once when
// it happens, never again while it holds.
type EventKind uint8

const (
	// EventRemovedFromSpace: a valid newer map has no section for the
	// node (or the node started on one). Told once per removal.
	EventRemovedFromSpace EventKind = iota + 1
	// EventBackInSpace: a map has the node's section again after a
	// removal. Told once per return.
	EventBackInSpace
	// EventConnected: a device's data plane came up. Told each time it
	// does.
	EventConnected
	// EventDNSUnprotected: the status of a connected device says its OS
	// may resolve names outside the node's resolver (Status.DNSUnprotected:
	// pointing it failed, or the OS's configuration says names may go
	// elsewhere). Told when the status starts saying so, not while it
	// goes on; again once it said otherwise or the data plane went down.
	EventDNSUnprotected
	// EventRouteTableNotEnforced: the status of a running data plane says
	// the OS routing table doesn't hold its rules: any DataPlane.RouteTable
	// Error, whether an Apply, a rule change or the direct DNS upstreams'
	// update failed to put them in place, the route table failed to put
	// them back on its own, the TUN is down, or the OS can't hold them.
	// Told when the status starts saying so, not while it goes on; again
	// once it said otherwise or the data plane went down.
	EventRouteTableNotEnforced
)

func (k EventKind) String() string {
	switch k {
	case EventRemovedFromSpace:
		return "removed_from_space"
	case EventBackInSpace:
		return "back_in_space"
	case EventConnected:
		return "connected"
	case EventDNSUnprotected:
		return "dns_not_protected"
	case EventRouteTableNotEnforced:
		return "route_table_not_enforced"
	}
	return "unknown"
}

// Event is something that happened to a node, as Node.Subscribe hears it.
// Like Status, it holds nothing from the map but its version.
type Event struct {
	Kind EventKind
	// MapVersion is the version of the map the node follows as it is
	// told.
	MapVersion uint64
}

// emitter tells a node's subscribers of its events; nil tells no one (a
// server's worker).
type emitter func(Event)

func (e emitter) emit(kind EventKind, version uint64) {
	if e != nil {
		e(Event{Kind: kind, MapVersion: version})
	}
}
