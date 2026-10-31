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
		e.summary(f, now)
	}
	e.log.close()
}

// summary logs a flow's totals.
func (e *Engine) summary(f *Flow, now time.Time) {
	applied := map[string]uint64{}
	for v, n := range f.applied {
		applied[v.String()] = n
	}
	e.logEntry(LogEntry{
		Time: now, Event: EventSummary, Flow: f.Key.String(), Packets: f.Packets, Bytes: f.Bytes,
		Module: f.last.module, Verdict: f.last.verdict, Applied: applied, Ignored: f.ignored,
	})
}

// Unnoticed is how many times a snapshot (a new flow, a tag) was not
// handed to an active module because the module's channel was full,
// summed over the modules.
func (e *Engine) Unnoticed() uint64 { return e.flows.unnoticed.Load() }

// Handle decides one packet.
//
// Composition: only Drop and Reset end the walk. A flow whose pinned
// verdict is one of them is decided before any module looks; otherwise
// the passive modules that haven't retired from the flow see the packet
// in config order, and the most severe verdict among a pinned Throttle
// and theirs decides it, the first module to give it winning a tie. A
// Throttle, pinned or not, never stops a later module from dropping or
// resetting the packet; Accept, pinned or not, never stops anything.
func (e *Engine) Handle(p *Packet) Action {
	now := e.now()
	f, isNew := e.flows.flow(FlowKey{p.Proto, p.Src, p.Dst, p.SrcPort, p.DstPort}, now)
	f, isNew = e.restart(f, isNew, p, now)
	if why := f.observe(p, now); why != "" {
		e.ignore(f, why, now)
	}
	if isNew && len(e.flows.events) > 0 {
		e.flows.publish(f.snapshot("", ""))
	}
	if isNew && f.reverse != nil && f.reverse.throttle != nil {
		e.pin(f, reverseThrottle(*f.reverse.throttle))
	}
	if r, ok := e.flows.takeFlag(f.Key); ok && e.pin(f, r) {
		// flagFunc logged the flag already.
		f.logged[ruleKey{r.verdict, r.module}] = true
	}
	best := rule{verdict: Accept}
	if f.pinned != nil {
		if f.pinned.severity() == 2 {
			return e.apply(f, p, *f.pinned, now)
		}
		best = *f.pinned
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
		if d.Flow {
			// A module that pinned its verdict has said all it will about
			// the flow.
			f.retire(i, len(e.passives))
			e.pin(f, r)
		}
		if r.severity() == 2 {
			return e.apply(f, p, r, now)
		}
		if r.severity() > best.severity() {
			best = r
		}
	}
	return e.apply(f, p, best, now)
}

// udpIdle is how long a UDP flow may go without a packet before the next
// one starts it over: Linux conntrack's timeout for a UDP flow with
// replies.
const udpIdle = 120 * time.Second

// restart starts a flow over when its addresses and ports carry a new
// connection, so a new connection's first bytes are read and judged, never
// an old one's state (a retired module, a pinned verdict, a stream) taken
// for its: a UDP flow idle past udpIdle; a TCP connection once the reply
// to a SYN with a new sequence number accepts it (a SYN-ACK acknowledging
// it), both directions. A SYN alone restarts nothing, since a receiver
// with the connection open ignores it. It returns the packet's flow and
// whether it is new.
func (e *Engine) restart(f *Flow, isNew bool, p *Packet, now time.Time) (*Flow, bool) {
	if p.BadChecksum {
		return f, isNew
	}
	switch {
	case f.Key.Proto == ProtoUDP:
		if !isNew && now.Sub(f.Last) > udpIdle {
			e.summary(f, now)
			return e.flows.fresh(f.Key, now), true
		}
	case p.Flags&(Syn|Ack) == Syn:
		if !isNew && f.Stream.newConnection(p.Seq) {
			f.offer, f.offered = p.Seq, true
		}
	case p.Flags&(Syn|Ack) == Syn|Ack:
		c := f.reverse
		if c == nil || !c.offered || p.Ack != c.offer+1 {
			break
		}
		e.summary(c, now)
		nc := e.flows.fresh(c.Key, now)
		nc.Stream.add(c.offer, Syn, nil)
		if len(e.flows.events) > 0 {
			e.flows.publish(nc.snapshot("", ""))
		}
		if !isNew {
			e.summary(f, now)
			f, isNew = e.flows.fresh(f.Key, now), true
		}
	}
	return f, isNew
}

// ignore counts a packet whose payload the flow kept out, and logs the
// first for each reason.
func (e *Engine) ignore(f *Flow, why string, now time.Time) {
	if f.ignored == nil {
		f.ignored = map[string]uint64{}
	}
	f.ignored[why]++
	if f.ignored[why] == 1 {
		e.logEntry(LogEntry{
			Time: now, Event: EventIgnore, Flow: f.Key.String(), Packets: f.Packets, Bytes: f.Bytes, Reason: why,
		})
	}
}

// pin makes r the flow's verdict unless a verdict as severe is pinned, and
// reports whether it did.
func (e *Engine) pin(f *Flow, r rule) bool {
	if r.severity() == 0 || f.pinned != nil && r.severity() <= f.pinned.severity() {
		return false
	}
	f.pinned = &r
	return true
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
		Module: module, Verdict: f.last.verdict, Reason: why,
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
// flow's decision the first time the flow gets that verdict from that
// module: Reset needs TCP, Throttle asks the flow's policer.
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
		if f.throttle == nil {
			// The connection is throttled, not one direction of it: the
			// replies are policed from their next packet on.
			f.throttle = &r
			if f.reverse != nil {
				e.pin(f.reverse, reverseThrottle(r))
			}
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
	f.last = logged
	if !f.logged[logged] {
		f.logged[logged] = true
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

// reverseThrottle is the rule a throttled flow pins on its reverse: the
// same module and rate, each direction with a bucket of its own.
func reverseThrottle(r rule) rule {
	r.why = fmt.Sprintf("the other direction is throttled: %s", r.why)
	return r
}

func (e *Engine) logEntry(entry LogEntry) {
	if e.log != nil {
		e.log.write(entry)
	}
}
