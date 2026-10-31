package censor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
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
	eng.Shutdown() // flushes the log

	mr, _ := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "reset"}`))
	eng = NewEngine([]Passive{mr}, nil, nil)
	if a := eng.Handle(blocked); a.Verdict != Drop || !strings.Contains(a.Reason, "not TCP") {
		t.Errorf("reset on udp: %+v", a)
	}
	if a := eng.Handle(&Packet{Src: blocked.Src, Dst: blocked.Dst, Proto: ProtoTCP, SrcPort: 1, DstPort: 2}); a.Verdict != Reset {
		t.Errorf("reset on tcp: %+v", a)
	}

	// The log has the flows' decisions.
	for _, want := range []string{
		`"flow":"udp 192.0.2.1:1->203.0.113.9:2"`, `"verdict":"drop"`, `"module":"block-ip"`, `"verdict":"accept"`,
	} {
		if !strings.Contains(logBuf.String(), want) {
			t.Errorf("verdict log misses %s:\n%s", want, logBuf.String())
		}
	}
}

// TestEngineThrottlePolices checks a throttled flow is policed, not held:
// each packet is accepted or dropped at once, by a token bucket that
// refills at the rate.
func TestEngineThrottlePolices(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "throttle", "rate": 1000, "burst": 1000}`))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine([]Passive{m}, nil, nil)
	clock := time.Unix(1000, 0)
	eng.now = func() time.Time { return clock }
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 1, 2, make([]byte, 600))

	var got []Verdict
	for i := 0; i < 3; i++ {
		a := eng.Handle(p)
		if !a.Throttled || a.Module != "block-ip" {
			t.Fatalf("packet %d: %+v", i, a)
		}
		got = append(got, a.Verdict)
	}
	// 1000 tokens: 600 pass (400 left), 600 pass (-200), then empty.
	if want := []Verdict{Accept, Accept, Drop}; !slices.Equal(got, want) {
		t.Errorf("a burst of three: %v, want %v", got, want)
	}
	clock = clock.Add(100 * time.Millisecond) // +100 tokens: still -100
	if a := eng.Handle(p); a.Verdict != Drop {
		t.Errorf("before the debt is paid: %+v", a)
	}
	clock = clock.Add(time.Second)
	if a := eng.Handle(p); a.Verdict != Accept {
		t.Errorf("a second later: %+v", a)
	}
	empty := udpPacket(p.Src, p.Dst, 1, 2, nil)
	for i := 0; i < 3; i++ {
		if a := eng.Handle(empty); a.Verdict != Accept {
			t.Errorf("a packet without payload on an empty bucket: %+v", a)
		}
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

// TestEnginePinnedThrottle polices a pinned throttle at the module's rate.
func TestEnginePinnedThrottle(t *testing.T) {
	m := &throttlePinModule{rate: 100, burst: 100}
	eng := NewEngine([]Passive{m}, nil, nil)
	eng.now = func() time.Time { return time.Unix(1000, 0) }
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, make([]byte, 150))
	if a := eng.Handle(p); a.Verdict != Accept || !a.Throttled {
		t.Fatalf("first: %+v", a)
	}
	if a := eng.Handle(p); a.Verdict != Drop || !a.Throttled || a.Module != "throttle-pin" {
		t.Errorf("pinned, over the rate: %+v", a)
	}
	if m.saw != 1 {
		t.Errorf("the module saw %d packets of a pinned flow", m.saw)
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

// TestEngineSlowActiveNeverStalls checks that an active module which
// doesn't read its channel never stalls the queue's callback: Handle
// returns at once, the flows its channel had no room for are counted, and
// the module sees new flows again once it has room.
func TestEngineSlowActiveNeverStalls(t *testing.T) {
	stuck := &stuckActive{release: make(chan struct{}), got: make(chan FlowSnapshot, 1024)}
	eng := NewEngine(nil, []Active{stuck}, nil)
	defer eng.Shutdown()

	const flows = 300
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < flows; i++ {
			eng.Handle(udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), uint16(i+1), 2, []byte("x")))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle waited for an active module that doesn't read: the queue would stall")
	}
	missed := eng.Unnoticed()
	if missed == 0 || missed >= flows {
		t.Fatalf("unnoticed = %d, want the flows past the channel's room", missed)
	}

	close(stuck.release)
	for i := uint64(0); i < flows-missed; i++ {
		select {
		case <-stuck.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("the module got %d of the %d published flows", i, flows-missed)
		}
	}
	late := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.3"), 9, 2, []byte("late"))
	eng.Handle(late)
	select {
	case s := <-stuck.got:
		if s.Key.Dst != late.Dst {
			t.Errorf("got %v, want the late flow", s.Key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late flow never reached the module once it had room")
	}
}

// TestEngineHandleAfterShutdown: a packet the queue hands over while the
// engine shuts down must not send on a closed channel.
func TestEngineHandleAfterShutdown(t *testing.T) {
	eng := NewEngine(nil, []Active{&proberModule{}}, nil)
	eng.Shutdown()
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	if a := eng.Handle(p); a.Verdict != Accept {
		t.Errorf("after shutdown: %+v", a)
	}
	eng.Shutdown() // a second Shutdown is harmless too
}

// TestEngineThrottleDefaults: a throttle with no rate gets the default
// rate and burst.
func TestEngineThrottleDefaults(t *testing.T) {
	eng := NewEngine([]Passive{&throttlePinModule{}}, nil, nil)
	eng.Handle(udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x")))
	f := eng.flows.flows[FlowKey{ProtoUDP, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2}]
	if f == nil || f.bucket == nil || f.bucket.rate != defaultRate || f.bucket.burst != defaultBurst {
		t.Errorf("throttle without rate or burst: %+v", f)
	}
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
	rate, burst int
	saw         int
}

func (m *throttlePinModule) Name() string { return "throttle-pin" }

func (m *throttlePinModule) Inspect(p *Packet, f *Flow) Decision {
	m.saw++
	return Decision{Verdict: Throttle, Flow: true, Rate: m.rate, Burst: m.burst}
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

// stuckActive reads nothing until release is closed, then forwards every
// flow to got.
type stuckActive struct {
	release chan struct{}
	got     chan FlowSnapshot
}

func (m *stuckActive) Name() string { return "stuck" }

func (m *stuckActive) Run(ctx context.Context, flows <-chan FlowSnapshot, _ FlagFunc) {
	select {
	case <-ctx.Done():
		return
	case <-m.release:
	}
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			m.got <- f
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
