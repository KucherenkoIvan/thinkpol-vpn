package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var fastPaths = path.Options{
	ProbeInterval: 30 * time.Millisecond,
	DeadAfter:     150 * time.Millisecond,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
}

// runningNode is RunDataPlane on a virtual TUN, with a stack that answers
// pings and collects replies.
type runningNode struct {
	ch      *tuntest.ChannelTUN
	replies chan packettest.Packet
	maps    chan []byte
	log     *logring.Ring
	stop    context.CancelFunc
	done    chan error
}

func startNode(t *testing.T, reg *transport.Registry, keys NodeKeys, m *netmap.Map) *runningNode {
	t.Helper()
	n := &runningNode{
		ch: tuntest.NewChannelTUN(), replies: make(chan packettest.Packet, 64),
		maps: make(chan []byte, 1), log: logring.New(1 << 20), done: make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	go n.stack(ctx)
	go func() {
		n.done <- RunDataPlane(ctx, DataPlane{
			Keys: keys, Map: m, Maps: n.maps, Registry: reg, Inbound: DirectInbound(reg),
			Log:        slog.New(slog.NewTextHandler(n.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
			newTUN:     func(string) (wgtun.Device, netcfg.Configurator, error) { return n.ch.TUN(), nil, nil },
			path:       fastPaths,
			retryAfter: 50 * time.Millisecond,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-n.done:
		case <-time.After(10 * time.Second):
			t.Error("the data plane didn't stop")
		}
		if t.Failed() {
			t.Logf("log:\n%s", n.log)
		}
	})
	return n
}

func (n *runningNode) stack(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-n.ch.Inbound:
			if reply, ok := packettest.Reply(b); ok {
				select {
				case n.ch.Outbound <- reply:
				case <-ctx.Done():
					return
				}
				continue
			}
			if p, ok := packettest.Parse(b); ok {
				select {
				case n.replies <- p:
				default:
				}
			}
		}
	}
}

// ping sends pings from src to dst until one is answered.
func (n *runningNode) ping(t *testing.T, src, dst netip.Addr) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for seq := uint16(1); ; seq++ {
		select {
		case n.ch.Outbound <- packettest.Echo(src, dst, 7, seq, []byte("ping")):
		case <-deadline:
			t.Fatalf("no reply from %v", dst)
		}
		for wait := true; wait; {
			select {
			case p := <-n.replies:
				if p.Src == dst && packettest.IsEchoReply(p, 7, seq) {
					return
				}
			case <-tick.C:
				wait = false
			case <-deadline:
				t.Fatalf("no reply from %v", dst)
			}
		}
	}
}

func TestDataPlaneRunsAndFollowsTheMap(t *testing.T) {
	s := newTestSpace(t)
	net := memory.NewNetwork(memory.Datagram)
	reg, err := transport.NewRegistry(net)
	if err != nil {
		t.Fatal(err)
	}
	a := startNode(t, reg, s.a, s.verified(t, 1))
	b := startNode(t, reg, s.b, s.verified(t, 1))
	a4, a6 := overlay(1)
	b4, b6 := overlay(2)
	b.ping(t, b4, a4)
	b.ping(t, b6, a6)
	a.ping(t, a4, b4)

	// Version 2 moves a's listener: a closes the old one and opens the new
	// one, b dials the new address.
	old := s.listen
	s.listen = netip.MustParseAddrPort("192.0.2.1:4600")
	v2 := s.build(t, 2)
	a.maps <- v2
	b.maps <- v2
	eventually(t, func() bool { return strings.Contains(a.log.String(), `msg="map applied" version=2`) })
	eventually(t, func() bool { return canListen(net, old) })
	b.ping(t, b4, a4)
	if canListen(net, s.listen) {
		t.Fatal("a doesn't listen on its new address")
	}

	// Older, tampered and unopenable maps leave the node on version 2.
	a.maps <- s.build(t, 1)
	eventually(t, func() bool { return strings.Contains(a.log.String(), "map not newer") })
	bad := s.build(t, 3)
	bad[len(bad)-1] ^= 1
	a.maps <- bad
	eventually(t, func() bool { return strings.Contains(a.log.String(), "bad signature") })
	a.ping(t, a4, b4)

	// Stopping undoes it all: the listener goes.
	a.stop()
	if err := <-a.done; err != nil {
		t.Fatal(err)
	}
	a.done <- nil // for the cleanup
	if !canListen(net, s.listen) {
		t.Fatal("a's listener outlived the data plane")
	}
}

func TestDataPlaneRefusesAMapWithoutTheNode(t *testing.T) {
	s := newTestSpace(t)
	reg, err := transport.NewRegistry(memory.NewNetwork(memory.Datagram))
	if err != nil {
		t.Fatal(err)
	}
	stranger := NodeKeys{ID: netmap.NodeID{9}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey()}
	created := false
	err = RunDataPlane(context.Background(), DataPlane{
		Keys: stranger, Map: s.verified(t, 1), Registry: reg, Inbound: DirectInbound(reg),
		newTUN: func(string) (wgtun.Device, netcfg.Configurator, error) {
			created = true
			return tuntest.NewChannelTUN().TUN(), nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "no section for this node's key") {
		t.Fatalf("got %v", err)
	}
	if created {
		t.Fatal("a TUN was created for a map the node isn't in")
	}
}

func canListen(net *memory.Network, at netip.AddrPort) bool {
	l, err := net.Listen(context.Background(), transport.ListenConfig{Address: at.String(), Peers: transport.NewPeerTable()})
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
	}
}
