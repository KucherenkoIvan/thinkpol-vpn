package agent

import (
	"errors"
	"fmt"
	"log/slog"
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

// connection is a device's connection. Its methods are the only way it
// moves: each refuses a move its state can't make (errInvalidTransition)
// and leaves it where it was.
type connection struct {
	state connState
	// refused counts the moves refused.
	refused int
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
	return connection{state: connConnecting}
}

func (c *connection) refuse(move string) error {
	c.refused++
	return fmt.Errorf("%w: %s while %s", errInvalidTransition, move, c.state)
}

// disconnected is whether the device is down on purpose.
func (c *connection) disconnected() bool { return c.state == connDisconnected }

// connect is a Connect while the data plane isn't up: from disconnected it
// starts, or waits for a map that has the node when it is out of its
// space (inSpace false); from retrying it starts at once.
func (c *connection) connect(inSpace bool) error {
	switch {
	case c.state == connDisconnected && !inSpace:
		c.state = connRemoved
	case c.state == connDisconnected, c.state == connRetrying && inSpace:
		c.state = connConnecting
	default:
		return c.refuse("connect")
	}
	return nil
}

// resume starts a connection meant to be up that waited: back in its space
// (removed), or a retry (retrying).
func (c *connection) resume() error {
	switch c.state {
	case connRemoved, connRetrying:
		c.state = connConnecting
		return nil
	}
	return c.refuse("resume")
}

// started is a start that brought the data plane up.
func (c *connection) started() error {
	if c.state != connConnecting {
		return c.refuse("started")
	}
	c.state = connConnected
	return nil
}

// startFailed is a start that failed: retried (retrying), or down again
// (disconnected, a Connect from disconnected that says why).
func (c *connection) startFailed(retry bool) error {
	if c.state != connConnecting {
		return c.refuse("start failed")
	}
	c.state = connDisconnected
	if retry {
		c.state = connRetrying
	}
	return nil
}

// disconnect is a Disconnect, or the node stopping: the data plane goes
// down.
func (c *connection) disconnect() error {
	switch c.state {
	case connConnected, connRemoved, connRetrying:
		c.state = connDisconnected
		return nil
	}
	return c.refuse("disconnect")
}

// remove is the node removed from its space: a connection meant to be up
// waits for a map that has the node again; one already waiting, or
// disconnected, stays as it is.
func (c *connection) remove() error {
	switch c.state {
	case connConnected, connRetrying:
		c.state = connRemoved
	case connRemoved, connDisconnected:
	default:
		return c.refuse("remove")
	}
	return nil
}

// logRefused logs a move a connection refused: a bug, the connection
// stays where it was.
func logRefused(log *slog.Logger, err error) {
	if err != nil {
		log.Error("connection", "err", err)
	}
}
