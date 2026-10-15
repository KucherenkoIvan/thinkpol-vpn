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

// TestEngineActiveFlags checks an active module: it sees new flows and its
// flag decides the flow's later packets, logged under its own name.
func TestEngineActiveFlags(t *testing.T) {
	prober := &proberModule{}
	eng := NewEngine(nil, []Active{prober}, nil)

	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	if a := eng.Handle(p); a.Verdict != Accept {
		t.Errorf("before the flag: %+v", a)
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(prober.seen) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(prober.seen) == 0 {
		t.Fatal("no flow reached the active module")
	}
	if f := prober.seen[0]; f.Key.Src != p.Src || f.Bytes != 1 || f.Packets != 1 {
		t.Errorf("the flow the module saw: %+v", f)
	}
	prober.flag(prober.seen[0].Key, Drop, "looks fake")

	if a := eng.Handle(p); a.Verdict != Drop || a.Module != "prober" {
		t.Errorf("flagged flow: %+v", a)
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

type proberModule struct {
	seen []*Flow
	flag FlagFunc
}

func (m *proberModule) Name() string { return "prober" }

func (m *proberModule) Run(ctx context.Context, flows <-chan *Flow, flag FlagFunc) {
	m.flag = flag
	for f := range flows {
		m.seen = append(m.seen, f)
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
