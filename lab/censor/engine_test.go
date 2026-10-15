package censor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestEngineAppliesModules runs the engine without a queue: modules in
// order, the first decision wins, Reset lands on TCP and drops elsewhere,
// and the verdict log says all of it.
func TestEngineAppliesModules(t *testing.T) {
	var logBuf bytes.Buffer
	blocked := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 1, 2, []byte("x"))
	free := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))

	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.0/24"]}`))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine([]Passive{m}, nil, &logBuf)
	if a := eng.Handle(blocked); a.Verdict != Drop || a.Module != "block-ip" {
		t.Errorf("blocked: %+v", a)
	}
	if a := eng.Handle(free); a.Verdict != Accept || a.Module != "" {
		t.Errorf("free: %+v", a)
	}

	mr, _ := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "reset"}`))
	eng = NewEngine([]Passive{mr}, nil, nil)
	if a := eng.Handle(blocked); a.Verdict != Drop || !strings.Contains(a.Reason, "not TCP") {
		t.Errorf("reset on udp: %+v", a)
	}
	if a := eng.Handle(&Packet{Src: blocked.Src, Dst: blocked.Dst, Proto: ProtoTCP, SrcPort: 1, DstPort: 2}); a.Verdict != Reset {
		t.Errorf("reset on tcp: %+v", a)
	}

	// The log has one JSONL line per decision.
	for _, want := range []string{
		`"flow":"udp 192.0.2.1:1->203.0.113.9:2"`, `"verdict":"drop"`, `"module":"block-ip"`, `"verdict":"accept"`,
	} {
		if !strings.Contains(logBuf.String(), want) {
			t.Errorf("verdict log misses %s:\n%s", want, logBuf.String())
		}
	}
}

// TestEngineThrottles checks the throttle decision the queue adapter
// applies: a hold and what the packet becomes after it.
func TestEngineThrottles(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "throttle"}`))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine([]Passive{m}, nil, nil)
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 1, 2, []byte("x"))
	a := eng.Handle(p)
	if a.Verdict != Throttle || a.Hold <= 0 || a.Held != Accept {
		t.Errorf("throttle: %+v", a)
	}
}

// TestEngineFlowVerdictSticks checks a module's flow verdict: later packets
// of the flow are decided without the modules seeing them again.
func TestEngineFlowVerdictSticks(t *testing.T) {
	counting := &countingModule{}
	eng := NewEngine([]Passive{counting}, nil, nil)

	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	if a := eng.Handle(p); a.Verdict != Drop {
		t.Errorf("first packet: %+v", a)
	}
	for i := 0; i < 3; i++ {
		if a := eng.Handle(p); a.Verdict != Drop || a.Module != "counting" {
			t.Errorf("packet %d: %+v", i, a)
		}
	}
	if counting.saw != 1 {
		t.Errorf("the module saw %d packets, want 1: the flow verdict did not stick", counting.saw)
	}
}

// TestEnginePinnedThrottle keeps Hold and Held on a pinned flow verdict.
func TestEnginePinnedThrottle(t *testing.T) {
	m := &throttlePinModule{hold: 2 * time.Second, held: Drop}
	eng := NewEngine([]Passive{m}, nil, nil)
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	a := eng.Handle(p)
	if a.Verdict != Throttle || a.Hold != 2*time.Second || a.Held != Drop {
		t.Fatalf("first: %+v", a)
	}
	a = eng.Handle(p)
	if a.Verdict != Throttle || a.Hold != 2*time.Second || a.Held != Drop {
		t.Errorf("pinned: %+v", a)
	}
}

// TestEngineActiveFlags checks an active module: it sees new flows and its
// flag decides the flow's later packets, logged under its own name.
func TestEngineActiveFlags(t *testing.T) {
	prober := &proberModule{ch: make(chan FlowSnapshot, 8)}
	eng := NewEngine(nil, []Active{prober}, nil)

	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	if a := eng.Handle(p); a.Verdict != Accept {
		t.Errorf("before the flag: %+v", a)
	}

	var snap FlowSnapshot
	select {
	case snap = <-prober.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no flow reached the active module")
	}
	if snap.Key.Src != p.Src || snap.Bytes != 1 || snap.Packets != 1 {
		t.Errorf("the flow the module saw: %+v", snap)
	}
	prober.flag(snap.Key, Drop, "looks fake")

	if a := eng.Handle(p); a.Verdict != Drop || a.Module != "prober" {
		t.Errorf("flagged flow: %+v", a)
	}
	eng.Shutdown()
}

// TestEngineActiveTwoModules gives each active module its own channel and
// every new flow.
func TestEngineActiveTwoModules(t *testing.T) {
	a1 := &proberModule{name: "one", ch: make(chan FlowSnapshot, 512)}
	a2 := &proberModule{name: "two", ch: make(chan FlowSnapshot, 512)}
	eng := NewEngine(nil, []Active{a1, a2}, nil)

	for i := 0; i < 3; i++ {
		p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), uint16(i+1), 2, []byte("x"))
		eng.Handle(p)
	}
	deadline := time.After(5 * time.Second)
	for _, m := range []*proberModule{a1, a2} {
		for i := 0; i < 3; i++ {
			select {
			case <-m.ch:
			case <-deadline:
				t.Fatalf("%s saw %d flows, want 3", m.name, i)
			}
		}
	}
	eng.Shutdown()
}

// TestEngineActiveNoStarve publishes a new flow while an active module is
// busy with a bulk of earlier flows.
func TestEngineActiveNoStarve(t *testing.T) {
	slow := &slowActive{ch: make(chan FlowSnapshot, 512)}
	eng := NewEngine(nil, []Active{slow}, nil)

	for i := 0; i < 300; i++ {
		p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), uint16(i+1), 2, []byte("x"))
		eng.Handle(p)
	}
	late := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.3"), 9, 2, []byte("late"))
	eng.Handle(late)

	deadline := time.After(5 * time.Second)
	gotLate := false
	for !gotLate {
		select {
		case s := <-slow.ch:
			if s.Key.Dst == late.Dst {
				gotLate = true
			}
		case <-deadline:
			t.Fatal("the late flow never reached the active module")
		}
	}
	eng.Shutdown()
}

type countingModule struct {
	saw int
}

func (m *countingModule) Name() string { return "counting" }

func (m *countingModule) Inspect(p *Packet, f *Flow) Decision {
	m.saw++
	return Decision{Verdict: Drop, Flow: true}
}

type throttlePinModule struct {
	hold time.Duration
	held Verdict
}

func (m *throttlePinModule) Name() string { return "throttle-pin" }

func (m *throttlePinModule) Inspect(p *Packet, f *Flow) Decision {
	return Decision{Verdict: Throttle, Flow: true, Hold: m.hold, Held: m.held}
}

type proberModule struct {
	name string
	ch   chan FlowSnapshot
	seen []FlowSnapshot
	flag FlagFunc
}

func (m *proberModule) Name() string {
	if m.name != "" {
		return m.name
	}
	return "prober"
}

func (m *proberModule) Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc) {
	m.flag = flag
	if m.ch == nil {
		m.ch = make(chan FlowSnapshot, 512)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			m.seen = append(m.seen, f)
			m.ch <- f
		}
	}
}

type slowActive struct {
	ch chan FlowSnapshot
}

func (m *slowActive) Name() string { return "slow" }

func (m *slowActive) Run(ctx context.Context, flows <-chan FlowSnapshot, _ FlagFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			m.ch <- f
			time.Sleep(time.Millisecond)
		}
	}
}

func TestBuildModules(t *testing.T) {
	if _, _, err := Build(Config{Modules: []ModuleConfig{{Name: "no-such-module"}}}); err == nil {
		t.Error("an unknown module built")
	}
	passives, actives, err := Build(Config{Modules: []ModuleConfig{
		{Name: "block-ip", Settings: json.RawMessage(`{"destinations": ["203.0.113.9"]}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(passives) != 1 || len(actives) != 0 || passives[0].Name() != "block-ip" {
		t.Errorf("built %d passives, %d actives", len(passives), len(actives))
	}
	if _, _, err := Build(Config{Modules: []ModuleConfig{
		{Name: "block-ip", Settings: json.RawMessage(`{}`)},
	}}); err == nil {
		t.Error("block-ip built without destinations")
	}
}

func TestParseFlowKey(t *testing.T) {
	k := FlowKey{
		Proto: ProtoTCP, Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.2"),
		SrcPort: 1, DstPort: 443,
	}
	got, err := ParseFlowKey(k.String())
	if err != nil || got != k {
		t.Errorf("round-trip: %v %+v", err, got)
	}
}
