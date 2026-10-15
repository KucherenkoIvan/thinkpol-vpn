package censor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Action is the engine's decision for one packet: what the queue adapter
// does with it.
type Action struct {
	Verdict Verdict
	// Hold and Held are Throttle's: how long the packet waits, and what
	// it becomes afterwards.
	Hold time.Duration
	Held Verdict
	// Module is the module that decided, "" for a plain accept.
	Module string
	Reason string
}

// Engine runs the passive modules over every packet and the active modules
// over every flow, and decides. Handle comes serially from the queue's
// callback; Flag comes from the active modules, so the flow table is
// guarded.
type Engine struct {
	passives []Passive
	flows    *flowTable
	log      *verdictLog
	stop     context.CancelFunc
}

// NewEngine builds the engine and starts the active modules. The verdicts
// go to verdicts, one JSONL LogEntry per decision, or nowhere when it is
// nil.
func NewEngine(passives []Passive, actives []Active, verdicts io.Writer) *Engine {
	e := &Engine{passives: passives, flows: newFlowTable(len(actives))}
	if verdicts != nil {
		e.log = &verdictLog{w: verdicts}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.stop = cancel
	for i, a := range actives {
		go a.Run(ctx, e.flows.flowEvents(i), e.flagFunc(a.Name()))
	}
	return e
}

// Shutdown stops the active modules and closes their flow channels.
func (e *Engine) Shutdown() {
	if e.stop != nil {
		e.stop()
	}
	e.flows.closeEvents()
}

// Handle decides one packet.
func (e *Engine) Handle(p *Packet) Action {
	f, isNew := e.flows.flow(FlowKey{p.Proto, p.Src, p.Dst, p.SrcPort, p.DstPort}, time.Now(), uint64(len(p.Payload)))
	if isNew {
		e.flows.publish(f)
	}
	if a := e.flows.flagged(f.Key); a != nil {
		return e.decide(*a, f)
	}
	for _, m := range e.passives {
		d := m.Inspect(p, f)
		if d.Verdict == Accept && !d.Flow {
			continue
		}
		a := actionOf(d)
		a.Module = m.Name()
		if d.Flow {
			e.flows.flag(f.Key, a)
		}
		return e.decide(a, f)
	}
	return e.decide(Action{Verdict: Accept}, f)
}

// flagFunc is a FlagFunc the named module flags flows with.
func (e *Engine) flagFunc(module string) FlagFunc {
	return func(key FlowKey, verdict Verdict, reason string) {
		a := Action{Verdict: verdict, Module: module, Reason: reason}
		e.flows.flag(key, a)
		e.logEntry(time.Now(), a, key.String(), 0, 0)
	}
}

// decide logs an action and normalizes what the queue adapter applies:
// Reset needs TCP, Throttle needs a hold and a sane Held.
func (e *Engine) decide(a Action, f *Flow) Action {
	switch {
	case a.Verdict == Reset && f.Key.Proto != ProtoTCP:
		a.Reason = fmt.Sprintf("%s (not TCP, dropping)", a.Reason)
		a.Verdict = Drop
	case a.Verdict == Throttle && a.Hold <= 0:
		a.Hold = 500 * time.Millisecond
	case a.Verdict == Throttle && a.Held != Accept && a.Held != Drop:
		a.Held = Accept
	}
	e.logEntry(time.Now(), a, f.Key.String(), f.Packets, f.Bytes)
	return a
}

// LogEntry is one line of the verdict log.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Flow    string    `json:"flow"`
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
	Module  string    `json:"module"`
	Verdict Verdict   `json:"verdict"`
	// HoldMS and Held are Throttle's.
	HoldMS int64   `json:"hold_ms,omitempty"`
	Held   Verdict `json:"held,omitempty"`
	Reason string  `json:"reason"`
}

func (e *Engine) logEntry(now time.Time, a Action, flow string, packets, bytes uint64) {
	if e.log == nil {
		return
	}
	e.log.write(LogEntry{
		Time: now, Flow: flow, Packets: packets, Bytes: bytes,
		Module: a.Module, Verdict: a.Verdict, Held: a.Held,
		HoldMS: a.Hold.Milliseconds(), Reason: a.Reason,
	})
}

// verdictLog writes the verdict entries as JSONL.
type verdictLog struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *verdictLog) write(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	enc := json.NewEncoder(l.w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(entry)
	if f, ok := l.w.(*os.File); ok {
		_ = f.Sync()
	}
}
