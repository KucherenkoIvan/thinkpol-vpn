// Package censor is the lab's pluggable censor (PRD C4): a program in the
// lab router's container, censord, that nftables hands every forwarded
// packet to through an NFQUEUE, and that decides each packet's fate with
// switchable modules.
//
// A module is either passive, returning a verdict per packet or flow, or
// active, acting on its own (the prober). The engine tracks per-flow state,
// applies the verdicts through the queue, and writes every decision to a
// verdict log tests read. Modules register from init, like cmd/thinkpol's
// commands; a test picks them through the JSON config censord is started
// with. The NFQUEUE glue is in queue_linux.go: the censor never runs
// anywhere but inside a lab router.
package censor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Verdict is what the censor does with a packet.
type Verdict uint8

const (
	// Accept lets the packet through.
	Accept Verdict = iota
	// Drop discards it.
	Drop
	// Reset answers a TCP packet with an RST and discards it. On other
	// protocols the engine drops instead: only TCP has resets.
	Reset
	// Throttle holds the packet for Decision.Hold, then gives it the
	// Decision.Held verdict.
	Throttle
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "accept"
	case Drop:
		return "drop"
	case Reset:
		return "reset"
	case Throttle:
		return "throttle"
	}
	return "unknown"
}

// MarshalJSON is the verdict log's spelling: a verdict reads as its name.
func (v Verdict) MarshalJSON() ([]byte, error) {
	if v > Throttle {
		return nil, fmt.Errorf("censor: unknown verdict %d", uint8(v))
	}
	return []byte(`"` + v.String() + `"`), nil
}

// UnmarshalJSON reads what MarshalJSON wrote.
func (v *Verdict) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for want, name := range map[Verdict]string{Accept: "accept", Drop: "drop", Reset: "reset", Throttle: "throttle"} {
		if s == name {
			*v = want
			return nil
		}
	}
	return fmt.Errorf("censor: unknown verdict %q", s)
}

// Decision is what a passive module returns for one packet.
type Decision struct {
	Verdict Verdict
	// Flow pins the verdict to the flow: every later packet of it is
	// decided the same way without the modules seeing it again.
	Flow bool
	// Hold is Throttle's: how long the packet waits.
	Hold time.Duration
	// Held is Throttle's: what the packet becomes after the hold, Accept
	// or Drop.
	Held Verdict
	// Reason is a short cause, for the verdict log.
	Reason string
}

// Passive is a module that decides each packet it is shown: a blocklist, a
// fingerprint, a heuristic. Its Inspect runs for every packet until one of
// the modules decides; it must not keep Packet beyond the call without
// cloning what it needs, and per-flow state is its own business, keyed by
// FlowKey.
type Passive interface {
	// Name is the module's name in the config.
	Name() string
	Inspect(p *Packet, f *Flow) Decision
}

// Active is a module that acts on its own, given the flows the censor
// sees: the prober connects to servers and replays payloads. It flags
// flows whose verdict is then applied by the engine, like a passive
// module's flow verdict.
type Active interface {
	// Name is the module's name in the config.
	Name() string
	Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc)
}

// FlagFunc pins a verdict to a flow, later packets included. An Active
// module gets one bound to its own name, so the verdict log says who
// flagged.
type FlagFunc func(key FlowKey, verdict Verdict, reason string)
