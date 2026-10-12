package dataplane_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// A server that allows egress, run where its network stack forwards
// (EngineConfig.Forward: a worker), writes its peers' internet traffic to
// its TUN; here its stack answers for the internet. Egress off, or the
// engine not asked to forward (a server run as a device), and the same
// traffic is dropped as not the node's own.
func TestAnExitForwardsItsPeersInternetTraffic(t *testing.T) {
	internet4, internet6 := netip.MustParseAddr("192.0.2.80"), netip.MustParseAddr("2001:db8::80")
	for _, tc := range []struct {
		name            string
		egress, forward bool
	}{
		{"egress on", true, true},
		{"egress off", false, true},
		{"not forwarding", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			net := memory.NewNetwork(memory.Datagram)
			a, s, b := m0()
			withChain(t, a, s, "default -> chain:nl")
			exitServer(s, tc.egress)
			s.forward = tc.forward
			for _, nd := range []*node{s, a, b} {
				nd.start(t, net)
			}
			ping(t, a, s.v4) // the session is up
			exit := tc.egress && tc.forward
			if st := s.engine.Status(); st.Exit != exit {
				t.Fatalf("status Exit %v, want %v", st.Exit, exit)
			}
			for _, dst := range []netip.Addr{internet4, internet6} {
				if got := tryPing(a, dst, time.Second); got != exit {
					t.Errorf("ping %s through the exit: answered %v, want %v", dst, got, exit)
				}
			}
			if !exit && s.engine.Status().Router.NotLocal == 0 {
				t.Error("the exit dropped nothing as not its own")
			}
		})
	}
}

// Turning egress off under a running exit stops the forwarding at once.
func TestEgressOffStopsForwarding(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	withChain(t, a, s, "default -> chain:nl")
	exitServer(s, true)
	s.forward = true
	for _, nd := range []*node{s, a} {
		nd.start(t, net)
	}
	internet := netip.MustParseAddr("192.0.2.80")
	ping(t, a, internet)
	s.section.Node.AllowEgress = false
	s.apply(t)
	if s.engine.Status().Exit {
		t.Fatal("still an exit with egress off")
	}
	if tryPing(a, internet, time.Second) {
		t.Fatal("the exit forwarded with egress off")
	}
}

// exitServer makes s a server that devices dial, with egress as given.
func exitServer(s *node, egress bool) {
	n := &s.section.Node
	n.Kind, n.AllowIngress, n.AllowEgress = netmap.NodeServer, true, egress
}
