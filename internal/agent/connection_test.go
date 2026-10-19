package agent

import (
	"errors"
	"testing"
)

var connStates = []connState{connDisconnected, connConnecting, connConnected, connRemoved, connRetrying}

// Every move between two states is allowed or refused as the lifecycle
// says; a refused one leaves the connection where it was.
func TestConnectionTransitions(t *testing.T) {
	type pair struct{ from, to connState }
	allowed := map[pair]bool{
		{connDisconnected, connConnecting}: true, // Connect
		{connDisconnected, connRemoved}:    true, // Connect while out of its space
		{connConnecting, connConnected}:    true, // started
		{connConnecting, connRetrying}:     true, // a start failed, retried
		{connConnecting, connDisconnected}: true, // a Connect's start failed
		{connConnected, connDisconnected}:  true, // Disconnect
		{connConnected, connRemoved}:       true, // removed from its space
		{connRemoved, connConnecting}:      true, // back in its space
		{connRemoved, connDisconnected}:    true, // Disconnect
		{connRetrying, connConnecting}:     true, // the retry, a newer map, Connect
		{connRetrying, connDisconnected}:   true, // Disconnect
		{connRetrying, connRemoved}:        true, // removed from its space
	}
	for _, from := range connStates {
		for _, to := range connStates {
			c := connection{state: from}
			err := c.move(to)
			switch {
			case allowed[pair{from, to}] && (err != nil || c.state != to):
				t.Errorf("%s → %s: %v, in %s", from, to, err, c.state)
			case !allowed[pair{from, to}] && (!errors.Is(err, errInvalidTransition) || c.state != from):
				t.Errorf("%s → %s: %v, in %s; want refused", from, to, err, c.state)
			}
		}
	}
}

// What each event does to the connection, by the state it comes in.
func TestConnectionLifecycle(t *testing.T) {
	type step struct {
		name string
		do   func(*connection) error
	}
	connect := step{"connect", func(c *connection) error { return c.connect(true) }}
	connectRemoved := step{"connect while removed", func(c *connection) error { return c.connect(false) }}
	start := step{"start", (*connection).start}
	started := step{"started", (*connection).started}
	failed := step{"start failed", (*connection).startFailed}
	disconnect := step{"disconnect", (*connection).disconnect}
	remove := step{"remove", (*connection).remove}
	for _, tc := range []struct {
		name  string
		from  connection
		steps []step
		want  connState
	}{
		{"connect and up", newConnection(false, false), []step{connect, started}, connConnected},
		{"a Connect's failed start is down again", newConnection(false, false), []step{connect, failed}, connDisconnected},
		{"a first start that fails is retried", newConnection(true, false), []step{failed}, connRetrying},
		{"a retry that fails is retried", connection{state: connRetrying}, []step{start, failed}, connRetrying},
		{"a Connect while retrying that fails is retried", connection{state: connRetrying}, []step{connect, failed}, connRetrying},
		{"connect while removed waits", newConnection(false, true), []step{connectRemoved}, connRemoved},
		{"back in space starts", newConnection(true, true), []step{start, started}, connConnected},
		{"back in space, a failed start is retried", newConnection(true, true), []step{start, failed}, connRetrying},
		{"removed while up", connection{state: connConnected}, []step{remove}, connRemoved},
		{"removed while retrying", connection{state: connRetrying}, []step{remove}, connRemoved},
		{"removed again", connection{state: connRemoved}, []step{remove}, connRemoved},
		{"removed while down stays down", connection{state: connDisconnected}, []step{remove}, connDisconnected},
		{"disconnect while removed", connection{state: connRemoved}, []step{disconnect}, connDisconnected},
		{"disconnect while retrying", connection{state: connRetrying}, []step{disconnect}, connDisconnected},
	} {
		c := tc.from
		for _, s := range tc.steps {
			if err := s.do(&c); err != nil {
				t.Errorf("%s: %s: %v", tc.name, s.name, err)
			}
		}
		if c.state != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, c.state, tc.want)
		}
	}

	// Moves the lifecycle has no place for are refused, in place.
	for _, tc := range []struct {
		from connState
		step step
	}{
		{connConnected, connect},
		{connRemoved, connect},
		{connRetrying, connectRemoved},
		{connConnecting, connect},
		{connDisconnected, start},
		{connConnected, start},
		{connConnecting, start},
		{connDisconnected, started},
		{connRemoved, started},
		{connRetrying, started},
		{connConnected, failed},
		{connDisconnected, failed},
		{connRetrying, failed},
		{connDisconnected, disconnect},
		{connConnecting, remove},
	} {
		c := connection{state: tc.from}
		if err := tc.step.do(&c); !errors.Is(err, errInvalidTransition) || c.state != tc.from {
			t.Errorf("%s while %s: %v, in %s; want refused", tc.step.name, tc.from, err, c.state)
		}
	}
}
