package agent

import (
	"errors"
	"testing"
)

// Every method from every state: the state it moves to, or refused, in
// place.
func TestConnectionLifecycle(t *testing.T) {
	const refused = connState(255)
	states := []connState{connDisconnected, connConnecting, connConnected, connRemoved, connRetrying}
	for _, tc := range []struct {
		method string
		do     func(*connection) error
		// to is by state, in the order of states.
		to [5]connState
	}{
		{"connect", func(c *connection) error { return c.connect(true) },
			[5]connState{connConnecting, refused, refused, refused, connConnecting}},
		{"connect out of its space", func(c *connection) error { return c.connect(false) },
			[5]connState{connRemoved, refused, refused, refused, refused}},
		{"resume", (*connection).resume,
			[5]connState{refused, refused, refused, connConnecting, connConnecting}},
		{"started", (*connection).started,
			[5]connState{refused, connConnected, refused, refused, refused}},
		{"start failed, retried", func(c *connection) error { return c.startFailed(true) },
			[5]connState{refused, connRetrying, refused, refused, refused}},
		{"start failed, down again", func(c *connection) error { return c.startFailed(false) },
			[5]connState{refused, connDisconnected, refused, refused, refused}},
		{"disconnect", (*connection).disconnect,
			[5]connState{refused, refused, connDisconnected, connDisconnected, connDisconnected}},
		{"remove", (*connection).remove,
			[5]connState{connDisconnected, refused, connRemoved, connRemoved, connRemoved}},
	} {
		for i, from := range states {
			c := connection{state: from}
			err := tc.do(&c)
			want := tc.to[i]
			switch {
			case want == refused && (!errors.Is(err, errInvalidTransition) || c.state != from || c.refused != 1):
				t.Errorf("%s while %s: %v, now %s; want refused in place", tc.method, from, err, c.state)
			case want != refused && (err != nil || c.state != want || c.refused != 0):
				t.Errorf("%s while %s: %v, now %s; want %s", tc.method, from, err, c.state, want)
			}
		}
	}
}

func TestANewConnection(t *testing.T) {
	for _, tc := range []struct {
		connect, removed bool
		want             connState
	}{
		{false, false, connDisconnected},
		{false, true, connDisconnected},
		{true, false, connConnecting},
		{true, true, connRemoved},
	} {
		if c := newConnection(tc.connect, tc.removed); c.state != tc.want {
			t.Errorf("connect %v, removed %v: %s, want %s", tc.connect, tc.removed, c.state, tc.want)
		}
	}
}
