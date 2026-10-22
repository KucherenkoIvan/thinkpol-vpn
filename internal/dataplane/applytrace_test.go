package dataplane_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

func traceSteps(tr dataplane.ApplyTrace) []string {
	var out []string
	for _, s := range tr.Steps {
		name := string(s.Step)
		if s.Failed {
			name += "!"
		}
		out = append(out, name)
	}
	return out
}

// TestTheLastApplyIsTraced: every step of an Apply, in order, with its
// time; a failed one marked, and the trace failing where Status says.
func TestTheLastApplyIsTraced(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	rt := &fakeRouteTable{}
	a.routes = rt
	s.start(t, net)
	before := time.Now()
	a.start(t, net)

	tr, ok := a.engine.LastApply()
	if !ok {
		t.Fatal("no trace after an Apply")
	}
	want := []string{"section", "rules", "route_table_shrink", "removals", "devices", "router", "route_table"}
	if got := traceSteps(tr); !slices.Equal(got, want) || tr.Failed != "" {
		t.Fatalf("steps %q, failed %q; want %q", got, tr.Failed, want)
	}
	var sum time.Duration
	for _, st := range tr.Steps {
		if st.Took < 0 {
			t.Errorf("step %+v", st)
		}
		sum += st.Took
	}
	if tr.Started.Before(before) || tr.Took < sum || tr.Took > time.Since(before) {
		t.Errorf("started %v (test at %v), took %v, its steps %v", tr.Started, before, tr.Took, sum)
	}

	// The route table refuses the final set: the trace fails there.
	rt.mu.Lock()
	rt.failing = 1
	rt.mu.Unlock()
	if err := a.engine.Apply(context.Background(), a.section); err == nil {
		t.Fatal("Apply with the route table failing")
	}
	tr, _ = a.engine.LastApply()
	if got := traceSteps(tr); !slices.Equal(got, []string{"section", "rules", "route_table_shrink", "removals", "devices", "router", "route_table!"}) ||
		tr.Failed != dataplane.StepRouteTable || a.engine.Status().LastApplyError != tr.Failed {
		t.Fatalf("a failed route table: steps %q, failed %q", got, tr.Failed)
	}

	// A section that can't run here: revocations, then the failure.
	broken := a.section
	broken.Node.IPv4 = netip.Addr{}
	if err := a.engine.Apply(context.Background(), broken); err == nil {
		t.Fatal("applied a section without an IPv4 address")
	}
	tr, _ = a.engine.LastApply()
	if got := traceSteps(tr); !slices.Equal(got, []string{"section!", "removals"}) || tr.Failed != dataplane.StepSection {
		t.Fatalf("a section that can't run: steps %q, failed %q", got, tr.Failed)
	}

	// A copy: the caller can't change the engine's.
	tr.Steps[0].Step = "changed"
	if again, _ := a.engine.LastApply(); again.Steps[0].Step != dataplane.StepSection {
		t.Fatal("the trace is shared with the caller")
	}
}

// TestNoTraceBeforeTheFirstApply: an engine that never applied has no
// trace; one without a route table traces no route table's steps.
func TestNoTraceBeforeTheFirstApply(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	_, s, _ := m0()
	reg, err := transport.NewRegistry(net)
	if err != nil {
		t.Fatal(err)
	}
	e, err := dataplane.NewEngine(dataplane.EngineConfig{ID: s.id, Space: testSpace, WireGuardKey: s.key, Registry: reg, TUN: tuntest.NewChannelTUN().TUN(), Path: fastPaths})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if tr, ok := e.LastApply(); ok || len(tr.Steps) != 0 {
		t.Fatalf("before any Apply: %+v, %v", tr, ok)
	}
	if err := e.Apply(context.Background(), s.section); err != nil {
		t.Fatal(err)
	}
	tr, ok := e.LastApply()
	if got := traceSteps(tr); !ok || !slices.Equal(got, []string{"section", "rules", "removals", "devices", "router"}) {
		t.Fatalf("without a route table: %q, %v", got, ok)
	}
}
