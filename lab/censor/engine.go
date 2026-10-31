package censor

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Action is the engine's decision for one packet: what the queue adapter
// does with it.
type Action struct {
	// Verdict is Accept, Drop or Reset: a throttled packet is accepted or
	// dropped by the flow's policer.
	Verdict Verdict
	// Throttled is set when the flow is throttled; Verdict says whether
	// this packet was within the rate.
	Throttled bool
	// Module is the module that decided, "" for a plain accept.
	Module string
	Reason string
}

// Engine runs the passive modules over every packet and the active modules
// over every flow, and decides. Handle comes serially from the queue's
// callback, which alone touches the flows; the active modules' flags come
// from their own goroutines and wait in the flow table for the flow's next
// packet.
type Engine struct {
	passives []Passive
	flows    *flowTable
	log      *verdictLog
	stop     context.CancelFunc
	now      func() time.Time
}

// NewEngine builds the engine and starts the active modules. The verdicts
// go to verdicts as JSONL LogEntry lines (see LogEntry for which), or
// nowhere when it is nil.
func NewEngine(passives []Passive, actives []Active, verdicts io.Writer) *Engine {
	e := &Engine{passives: passives, flows: newFlowTable(len(actives)), now: time.Now}
	if verdicts != nil {
		e.log = newVerdictLog(verdicts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.stop = cancel
	for i, a := range actives {
		go a.Run(ctx, e.flows.flowEvents(i), e.flagFunc(a.Name()))
	}
	return e
}

// Shutdown stops the active modules and closes their flow channels, then
// writes every flow's summary to the verdict log and flushes it. Call it
// once the queue no longer calls Handle; a Handle after it decides as
// before, publishes nothing and logs unbuffered.
func (e *Engine) Shutdown() {
	if e.stop != nil {
		e.stop()
	}
	e.flows.closeEvents()
	if e.log == nil || e.log.isClosed() {
		return
	}
	now := e.now()
	for _, f := range e.flows.flows {
		applied := map[string]uint64{}
		for v, n := range f.applied {
			applied[v.String()] = n
		}
		e.log.write(LogEntry{
			Time: now, Event: EventSummary, Flow: f.Key.String(), Packets: f.Packets, Bytes: f.Bytes,
			Module: f.logged.module, Verdict: f.logged.verdict, Applied: applied,
		})
	}
	e.log.close()
}

// Unnoticed is how many times a snapshot (a new flow, a tag) was not
// handed to an active module because the module's channel was full,
// summed over the modules.
func (e *Engine) Unnoticed() uint64 { return e.flows.unnoticed.Load() }

// Handle decides one packet.
//
// Composition: a flow's pinned blocking verdict decides it before any
// module looks; otherwise the passive modules that haven't pinned Accept
// on the flow see the packet in config order, and the first blocking
// verdict decides it (and, pinned, the flow). Accept, pinned or not, never
// ends the walk.
func (e *Engine) Handle(p *Packet) Action {
	now := e.now()
	f, isNew := e.flows.flow(FlowKey{p.Proto, p.Src, p.Dst, p.SrcPort, p.DstPort}, now)
	f.observe(p, now)
	if isNew && len(e.flows.events) > 0 {
		e.flows.publish(f.snapshot("", ""))
	}
	if r, ok := e.flows.takeFlag(f.Key); ok {
		e.pin(f, r)
		// flagFunc logged the flag: the flow's next entry is a change
		// from it.
		f.logged = ruleKey{r.verdict, r.module}
	}
	if f.pinned != nil {
		return e.apply(f, p, *f.pinned, now)
	}
	for i, m := range e.passives {
		if f.done != nil && f.done[i] {
			continue
		}
		d := m.Inspect(p, f)
		if d.Tag != "" {
			e.tag(f, m.Name(), d.Tag, now)
		}
		r := ruleOf(d, m.Name())
		if r.severity() == 0 {
			if d.Flow {
				if f.done == nil {
					f.done = make([]bool, len(e.passives))
				}
				f.done[i] = true
			}
			continue
		}
		if d.Flow {
			e.pin(f, r)
		}
		return e.apply(f, p, r, now)
	}
	return e.apply(f, p, rule{verdict: Accept}, now)
}

// pin makes r the flow's verdict unless a verdict as severe is pinned.
func (e *Engine) pin(f *Flow, r rule) {
	if r.severity() == 0 {
		return
	}
	if f.pinned == nil || r.severity() > f.pinned.severity() {
		f.pinned = &r
	}
}

// tag hands the flow to the active modules, once per tagging module.
func (e *Engine) tag(f *Flow, module, why string, now time.Time) {
	if f.tagged[module] {
		return
	}
	if f.tagged == nil {
		f.tagged = map[string]bool{}
	}
	f.tagged[module] = true
	e.flows.publish(f.snapshot(module, why))
	e.logEntry(LogEntry{
		Time: now, Event: EventTag, Flow: f.Key.String(), Packets: f.Packets, Bytes: f.Bytes,
		Module: module, Verdict: f.logged.verdict, Reason: why,
	})
}

// flagFunc is a FlagFunc the named module flags flows with.
func (e *Engine) flagFunc(module string) FlagFunc {
	return func(key FlowKey, verdict Verdict, reason string) {
		e.flows.flag(key, rule{verdict: verdict, module: module, why: reason})
		e.logEntry(LogEntry{Time: e.now(), Event: EventFlag, Flow: key.String(), Module: module, Verdict: verdict, Reason: reason})
	}
}

// apply turns a rule into the packet's action, counts it and logs the
// flow's decision when it changed: Reset needs TCP, Throttle asks the
// flow's policer.
func (e *Engine) apply(f *Flow, p *Packet, r rule, now time.Time) Action {
	a := Action{Verdict: r.verdict, Module: r.module, Reason: r.why}
	switch r.verdict {
	case Reset:
		if f.Key.Proto != ProtoTCP {
			a.Reason = fmt.Sprintf("%s (not TCP, dropping)", a.Reason)
			a.Verdict = Drop
		}
	case Throttle:
		if f.bucket == nil {
			f.bucket = newTokenBucket(r.rate, r.burst, now)
		}
		a.Throttled, a.Verdict = true, Drop
		if f.bucket.pass(len(p.Payload), now) {
			a.Verdict = Accept
		}
	}
	f.applied[a.Verdict]++
	logged := ruleKey{a.Verdict, a.Module}
	if a.Throttled {
		logged.verdict = Throttle
	}
	if f.Packets == 1 || logged != f.logged {
		f.logged = logged
		entry := LogEntry{
			Time: now, Event: EventDecision, Flow: f.Key.String(), Packets: f.Packets, Bytes: f.Bytes,
			Module: a.Module, Verdict: logged.verdict, Reason: a.Reason,
		}
		if a.Throttled {
			entry.Rate = f.bucket.rate
		}
		e.logEntry(entry)
	}
	return a
}

func (e *Engine) logEntry(entry LogEntry) {
	if e.log != nil {
		e.log.write(entry)
	}
}
