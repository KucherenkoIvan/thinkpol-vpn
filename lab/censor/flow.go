package censor

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// FlowKey is one directional flow: everything from one socket to another.
// The replies are a flow of their own.
type FlowKey struct {
	Proto            Proto
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s %s:%d->%s:%d", k.Proto, k.Src, k.SrcPort, k.Dst, k.DstPort)
}

// Flow is the censor's state of one flow, given to the modules with every
// packet of it. Modules keep their own per-flow state, keyed by FlowKey.
type Flow struct {
	Key     FlowKey
	Started time.Time
	// Packets and Bytes count what the censor saw in this direction, the
	// triggering packet included.
	Packets uint64
	Bytes   uint64

	verdict *flowVerdict
}

type flowVerdict struct {
	verdict Verdict
	module  string
	reason  string
}

// The flow table is unbounded: a censor runs for one lab test, whose
// traffic is a few thousand flows at most.
type flowTable struct {
	mu    sync.Mutex
	flows map[FlowKey]*Flow
	// events is where new flows go to the active modules, nil without
	// them. A flow the channel has no room for is not published: an active
	// module that misses one still sees the later ones.
	events    chan *Flow
	unnoticed atomic.Uint64
}

func newFlowTable(active int) *flowTable {
	t := &flowTable{flows: map[FlowKey]*Flow{}}
	if active > 0 {
		t.events = make(chan *Flow, 256)
	}
	return t
}

// flow finds the flow of a packet, creating it and publishing it to the
// active modules when new.
func (t *flowTable) flow(key FlowKey, now time.Time, bytes uint64) *Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		f = &Flow{Key: key, Started: now}
		t.flows[key] = f
	}
	f.Packets++
	f.Bytes += bytes
	return f
}

// flag pins a verdict to a flow, whether or not it is running.
func (t *flowTable) flag(key FlowKey, v Verdict, module, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		f = &Flow{Key: key, Started: time.Now()}
		t.flows[key] = f
	}
	f.verdict = &flowVerdict{verdict: v, module: module, reason: reason}
}

// flagged is the verdict pinned to a flow, if any.
func (t *flowTable) flagged(key FlowKey) *flowVerdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flows[key].verdict
}

// publish hands a new flow to the active modules.
func (t *flowTable) publish(f *Flow) {
	if t.events == nil {
		return
	}
	select {
	case t.events <- f:
	default:
		t.unnoticed.Add(1)
	}
}

// Unnoticed is how many flows never reached the active modules.
func (t *flowTable) Unnoticed() uint64 { return t.unnoticed.Load() }

// flowEvents serves the active modules' flow channel. It closes when the
// censor stops.
func (t *flowTable) flowEvents() <-chan *Flow { return t.events }
