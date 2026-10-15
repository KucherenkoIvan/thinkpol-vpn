package censor

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
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

// ParseFlowKey reads what FlowKey.String wrote.
func ParseFlowKey(s string) (FlowKey, error) {
	proto, rest, ok := strings.Cut(s, " ")
	if !ok {
		return FlowKey{}, fmt.Errorf("flow %q", s)
	}
	left, right, ok := strings.Cut(rest, "->")
	if !ok {
		return FlowKey{}, fmt.Errorf("flow %q", s)
	}
	src, srcPort, err := parseHostPort(left)
	if err != nil {
		return FlowKey{}, fmt.Errorf("flow %q: %w", s, err)
	}
	dst, dstPort, err := parseHostPort(right)
	if err != nil {
		return FlowKey{}, fmt.Errorf("flow %q: %w", s, err)
	}
	var p Proto
	switch proto {
	case "tcp":
		p = ProtoTCP
	case "udp":
		p = ProtoUDP
	default:
		return FlowKey{}, fmt.Errorf("flow %q: protocol %q", s, proto)
	}
	return FlowKey{Proto: p, Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort}, nil
}

func parseHostPort(s string) (netip.Addr, uint16, error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ':' {
			continue
		}
		port, err := strconv.ParseUint(s[i+1:], 10, 16)
		if err != nil {
			continue
		}
		a, err := netip.ParseAddr(s[:i])
		if err != nil {
			continue
		}
		return a, uint16(port), nil
	}
	return netip.Addr{}, 0, fmt.Errorf("host:port %q", s)
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
	action Action
}

// FlowSnapshot is a copy of a flow handed to active modules so they never
// share the flow table's mutable Flow.
type FlowSnapshot struct {
	Key     FlowKey
	Started time.Time
	Packets uint64
	Bytes   uint64
}

// The flow table is unbounded: a censor runs for one lab test, whose
// traffic is a few thousand flows at most.
type flowTable struct {
	mu    sync.Mutex
	flows map[FlowKey]*Flow
	// events has one channel per active module. A flow the channel has no
	// room for is not published: an active module that misses one still
	// sees the later ones.
	events    []chan FlowSnapshot
	unnoticed atomic.Uint64
}

func newFlowTable(active int) *flowTable {
	t := &flowTable{flows: map[FlowKey]*Flow{}}
	for i := 0; i < active; i++ {
		t.events = append(t.events, make(chan FlowSnapshot, 256))
	}
	return t
}

// flow finds the flow of a packet, creating it when new.
func (t *flowTable) flow(key FlowKey, now time.Time, bytes uint64) (*Flow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	isNew := !ok
	if !ok {
		f = &Flow{Key: key, Started: now}
		t.flows[key] = f
	}
	f.Packets++
	f.Bytes += bytes
	return f, isNew
}

// flag pins an action to a flow, whether or not it is running.
func (t *flowTable) flag(key FlowKey, a Action) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		f = &Flow{Key: key, Started: time.Now()}
		t.flows[key] = f
	}
	f.verdict = &flowVerdict{action: a}
}

// flagged is the action pinned to a flow, if any.
func (t *flowTable) flagged(key FlowKey) *Action {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	if f == nil || f.verdict == nil {
		return nil
	}
	return &f.verdict.action
}

// publish hands a new flow to every active module.
func (t *flowTable) publish(f *Flow) {
	if len(t.events) == 0 {
		return
	}
	snap := FlowSnapshot{Key: f.Key, Started: f.Started, Packets: f.Packets, Bytes: f.Bytes}
	for _, ch := range t.events {
		ch <- snap
	}
}

// closeEvents closes every active module's channel.
func (t *flowTable) closeEvents() {
	for _, ch := range t.events {
		close(ch)
	}
}

// Unnoticed is how many flows never reached the active modules.
func (t *flowTable) Unnoticed() uint64 { return t.unnoticed.Load() }

// flowEvents returns the channel for active module i.
func (t *flowTable) flowEvents(i int) <-chan FlowSnapshot { return t.events[i] }
