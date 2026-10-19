package dataplane

// EventKind is what happened to an engine.
type EventKind uint8

const (
	// EventRouteTableNotEnforced: putting the compiled rules into the OS
	// routing table failed (an Apply, SetRules or ReloadRules); the route
	// table keeps trying, Status.RouteTable says how it stands.
	EventRouteTableNotEnforced EventKind = iota + 1
)

func (k EventKind) String() string {
	switch k {
	case EventRouteTableNotEnforced:
		return "route_table_not_enforced"
	}
	return "unknown"
}

// Event is something that happened to an engine, as EngineConfig.Events
// hears it.
type Event struct {
	Kind EventKind
}

// note keeps ev for flushEvents. Called with e.mu held.
func (e *Engine) note(ev Event) {
	if e.cfg.Events != nil {
		e.pending = append(e.pending, ev)
	}
}

// flushEvents tells cfg.Events what was noted, with the engine unlocked,
// so it may read the engine's Status. Deferred first by the calls that
// note events.
func (e *Engine) flushEvents() {
	if e.cfg.Events == nil {
		return
	}
	e.mu.Lock()
	evs := e.pending
	e.pending = nil
	e.mu.Unlock()
	for _, ev := range evs {
		e.cfg.Events(ev)
	}
}
