package agent

// EventKind is what happened to a node.
type EventKind uint8

const (
	// EventConnected: the data plane came up (a device's connection is
	// connected).
	EventConnected EventKind = iota + 1
	// EventRemovedFromSpace: a valid newer map has no section for the
	// node, once per removal.
	EventRemovedFromSpace
	// EventBackInSpace: a map has the node's section again after a
	// removal.
	EventBackInSpace
	// EventDNSUnprotected: a connected device's OS may resolve names
	// outside the node's resolver (Status.DNSUnprotected).
	EventDNSUnprotected
	// EventRouteTableNotEnforced: the OS routing table doesn't hold the
	// rules (dataplane.EventRouteTableNotEnforced).
	EventRouteTableNotEnforced
)

func (k EventKind) String() string {
	switch k {
	case EventConnected:
		return "connected"
	case EventRemovedFromSpace:
		return "removed_from_space"
	case EventBackInSpace:
		return "back_in_space"
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
	// MapVersion is the version of the map the node followed then.
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
