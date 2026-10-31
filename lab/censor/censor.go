package censor

import (
	"context"
	"encoding/json"
	"fmt"
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
	// Throttle polices the flow to Decision.Rate: a packet over the rate
	// is dropped, the rest pass. Nothing is held.
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
	// Flow pins the verdict to the flow. A blocking verdict (Drop, Reset,
	// Throttle) is then the flow's: every later packet is decided the
	// same way without any module seeing it again. A pinned Accept is the
	// module's alone: it sees the flow no more, and the modules after it
	// still do.
	Flow bool
	// Rate and Burst are Throttle's: the bytes per second of payload the
	// flow may send, and how many it may send at once (both defaulted
	// when 0).
	Rate, Burst int
	// Tag marks the flow as suspect, with the reason: active modules get
	// a snapshot of it (FlowSnapshot.Tag), with its retained payload. A
	// module's tags of one flow after its first are ignored. Any verdict
	// may carry a tag.
	Tag string
	// Reason is a short cause, for the verdict log.
	Reason string
}

// Passive is a module that decides each packet it is shown: a blocklist, a
// fingerprint, a heuristic. Its Inspect runs, in config order, for every
// packet until a module gives a blocking verdict, and for every packet of
// a flow until a blocking verdict is pinned to it or the module pins
// Accept. It must not keep Packet or Flow's buffers beyond the call
// without cloning what it needs, and per-flow state is its own business,
// keyed by FlowKey.
type Passive interface {
	// Name is the module's name in the config.
	Name() string
	Inspect(p *Packet, f *Flow) Decision
}

// Active is a module that acts on its own, given the flows the censor
// sees and the flows passive modules tag: the prober connects to servers
// and replays payloads. It flags flows whose verdict is then pinned by
// the engine, like a passive module's blocking flow verdict.
//
// A module may be passive and active at once: built from RegisterPassive,
// a module that also implements Active is run as both, one value, so its
// halves share state.
type Active interface {
	// Name is the module's name in the config.
	Name() string
	Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc)
}

// FlagFunc pins a verdict to a flow from its next packet on. An Active
// module gets one bound to its own name, so the verdict log says who
// flagged. Of a flow's verdicts, the more severe wins (Drop and Reset over
// Throttle over Accept), so a flag never lifts a block, and an Accept flag
// changes nothing. A Throttle flag polices at the default rate.
type FlagFunc func(key FlowKey, verdict Verdict, reason string)
