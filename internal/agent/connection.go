package agent

import (
	"errors"
	"fmt"
	"slices"
)

// connState is where a device's connection stands.
type connState uint8

const (
	// connDisconnected: down on purpose; the space's maps are followed.
	connDisconnected connState = iota
	// connConnecting: meant to be up, its data plane starting.
	connConnecting
	// connConnected: its data plane is up.
	connConnected
	// connRemoved: meant to be up, but the map has no section for the
	// node; it starts once a map has one again.
	connRemoved
	// connRetrying: meant to be up, but its start failed; it starts again
	// when the retry is due, a newer map comes or a Connect asks.
	connRetrying
)

func (s connState) String() string {
	switch s {
	case connDisconnected:
		return "disconnected"
	case connConnecting:
		return "connecting"
	case connConnected:
		return "connected"
	case connRemoved:
		return "removed"
	case connRetrying:
		return "retrying"
	}
	return "unknown"
}

// errInvalidTransition is a connection asked to make a move its state
// can't make: a bug in what drives it.
var errInvalidTransition = errors.New("agent: invalid connection transition")

// connTransitions are the moves a connection can make, by the state it
// is in.
var connTransitions = map[connState][]connState{
	connDisconnected: {connConnecting, connRemoved},
	connConnecting:   {connConnected, connRetrying, connDisconnected},
	connConnected:    {connDisconnected, connRemoved},
	connRemoved:      {connConnecting, connDisconnected},
	connRetrying:     {connConnecting, connDisconnected, connRemoved},
}

// connection is a device's connection. Its methods are the only way it
// moves: each refuses a move its state can't make (errInvalidTransition)
// and leaves it where it was.
type connection struct {
	state connState
	// failTo is where a failed start leaves it: disconnected after a
	// Connect from disconnected (the Connect says why), retrying otherwise.
	failTo connState
}

// newConnection is a device's connection as the node starts: connecting
// when it is meant to be up (removed while its map has no section for
// it), else disconnected.
func newConnection(connect, removed bool) connection {
	switch {
	case !connect:
		return connection{state: connDisconnected}
	case removed:
		return connection{state: connRemoved}
	}
	return connection{state: connConnecting, failTo: connRetrying}
}

func (c *connection) move(to connState) error {
	if !slices.Contains(connTransitions[c.state], to) {
		return fmt.Errorf("%w: %s → %s", errInvalidTransition, c.state, to)
	}
	c.state = to
	return nil
}

// down is whether the device is disconnected on purpose.
func (c *connection) down() bool { return c.state == connDisconnected }

// connect is a Connect while the data plane isn't up: from disconnected it
// starts, or waits for a map that has the node when it is out of its
// space (inSpace false); from retrying it starts at once.
func (c *connection) connect(inSpace bool) error {
	from := c.state
	if from != connDisconnected && (from != connRetrying || !inSpace) {
		return fmt.Errorf("%w: connect while %s", errInvalidTransition, from)
	}
	to := connConnecting
	if !inSpace {
		to = connRemoved
	}
	if err := c.move(to); err != nil {
		return err
	}
	c.failTo = connRetrying
	if from == connDisconnected {
		c.failTo = connDisconnected
	}
	return nil
}

// start is a start nobody asked for: back in its space (removed), or a
// retry (retrying). Failing, it is retried.
func (c *connection) start() error {
	if c.state != connRemoved && c.state != connRetrying {
		return fmt.Errorf("%w: start while %s", errInvalidTransition, c.state)
	}
	if err := c.move(connConnecting); err != nil {
		return err
	}
	c.failTo = connRetrying
	return nil
}

// started is a start that brought the data plane up.
func (c *connection) started() error { return c.move(connConnected) }

// startFailed is a start that failed: disconnected again after a Connect
// from disconnected, retrying otherwise.
func (c *connection) startFailed() error {
	if c.state != connConnecting {
		return fmt.Errorf("%w: a start failed while %s", errInvalidTransition, c.state)
	}
	return c.move(c.failTo)
}

// disconnect is a Disconnect: the data plane goes down, from whatever
// state but disconnected.
func (c *connection) disconnect() error { return c.move(connDisconnected) }

// remove is the node removed from its space: a connection meant to be up
// waits for a map that has the node again; one already waiting, or
// disconnected, stays as it is.
func (c *connection) remove() error {
	if c.state == connRemoved || c.state == connDisconnected {
		return nil
	}
	return c.move(connRemoved)
}
