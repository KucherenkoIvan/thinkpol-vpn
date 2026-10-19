package agent

// EventKind is what happened to a node. Each is an edge, told once when
// it happens, never again while it holds. Kinds told together are told in
// the order below.
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
	// EventDNSUnprotected: a connected device's OS may resolve names
	// outside the node's resolver (Status.DNSUnprotected): pointing it
	// failed, or it says names may go elsewhere as it is pointed. Told
	// when that starts, not on each failed retry; again only after
	// pointing it worked or the data plane went down.
	EventDNSUnprotected
	// EventRouteTableNotEnforced: putting a running data plane's rules
	// into the OS routing table failed (an Apply, a rule change, new
	// lists). Told when that starts, not on each failed retry; again only
	// after the rules were put in place or the data plane went down.
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
