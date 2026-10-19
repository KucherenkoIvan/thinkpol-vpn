package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// fastPaths are path timings six times faster than the defaults. A link
// is dead after a second without proof: a busy machine can hold a probe up
// for hundreds of milliseconds, and a link closed for that drops what is
// sent meanwhile, a WireGuard handshake included, which is only retried
// after WireGuard's 5 s.
var fastPaths = path.Options{
	ProbeInterval: 300 * time.Millisecond,
	DeadAfter:     time.Second,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
}

const testRetry = 300 * time.Millisecond

// runningNode is RunDataPlane on virtual TUNs (a fresh one each time the
// data plane starts), with a stack that answers pings and collects
// replies.
type runningNode struct {
	ch      atomic.Pointer[tuntest.ChannelTUN]
	tuns    atomic.Int32
	replies chan packettest.Packet
	maps    chan []byte
	log     *logring.Ring
	ctx     context.Context
	stop    context.CancelFunc
	done    chan error
	// ifc, if set, is the configurator each TUN gets.
	ifc netcfg.Configurator
	// conn is the connection RunDataPlane made (onConn), read once it
	// returned.
	conn *connection
}

func newRunningNode() *runningNode {
	n := &runningNode{replies: make(chan packettest.Packet, 64), maps: make(chan []byte, 1), log: logring.New(1 << 20), done: make(chan error, 1)}
	n.ctx, n.stop = context.WithCancel(context.Background())
	return n
}

// virtualTUN is the Host's NewTUN on virtual TUNs: a fresh one each
// start, the stack answering pings and collecting replies. Receiving
// from fail makes the start fail.
func (n *runningNode) virtualTUN(fail <-chan struct{}) func(string, int) (wgtun.Device, error) {
	return func(string, int) (wgtun.Device, error) {
		select {
		case <-fail:
			return nil, errors.New("no TUN today")
		default:
		}
		ch := tuntest.NewChannelTUN()
		n.ch.Store(ch)
		n.tuns.Add(1)
		go n.stack(ch)
		return ch.TUN(), nil
	}
}

func (n *runningNode) dataPlane(reg *transport.Registry, keys NodeKeys, m *netmap.Map) DataPlane {
	h := testHost()
	h.NewConfigurator = func(netcfg.Owner) (netcfg.Configurator, error) { return n.ifc, nil }
	h.NewTUN = n.virtualTUN(nil)
	h.Transports = func(bool) (*transport.Registry, error) { return reg, nil }
	return DataPlane{
		Keys: keys, Map: m, Maps: n.maps, Registry: reg, Inbound: DirectInbound(reg),
		Log:        slog.New(slog.NewTextHandler(n.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Host:       h,
		path:       fastPaths,
		retryAfter: testRetry,
		onConn:     func(c *connection) { n.conn = c },
	}
}

// noRefusals fails t if the data plane's connection refused a move; call
// it once RunDataPlane returned.
func (n *runningNode) noRefusals(t *testing.T) {
	t.Helper()
	if n.conn == nil {
		t.Error("RunDataPlane made no connection")
	} else if n.conn.refused != 0 {
		t.Errorf("the connection refused %d moves", n.conn.refused)
	}
}

func startNode(t *testing.T, reg *transport.Registry, keys NodeKeys, m *netmap.Map) *runningNode {
	t.Helper()
	n := newRunningNode()
	n.run(t, n.dataPlane(reg, keys, m))
	return n
}

func (n *runningNode) run(t *testing.T, dp DataPlane) {
	go func() { n.done <- RunDataPlane(n.ctx, dp) }()
	t.Cleanup(func() {
		n.stop()
		select {
		case <-n.done:
			n.noRefusals(t)
		case <-time.After(10 * time.Second):
			t.Error("the data plane didn't stop")
		}
		if t.Failed() {
			t.Logf("log:\n%s", n.log)
		}
	})
}

func (n *runningNode) stack(ch *tuntest.ChannelTUN) {
	for {
		select {
		case <-n.ctx.Done():
			return
		case b := <-ch.Inbound:
			if reply, ok := packettest.Reply(b); ok {
				select {
				case ch.Outbound <- reply:
				case <-n.ctx.Done():
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

// answered reports whether a ping from src to dst is answered within
// timeout.
func (n *runningNode) answered(src, dst netip.Addr, timeout time.Duration) bool {
	deadline := time.After(timeout)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for seq := uint16(1); ; seq++ {
		var out chan []byte // nil until the data plane made a TUN
		if ch := n.ch.Load(); ch != nil {
			out = ch.Outbound
		}
		select {
		case out <- packettest.Echo(src, dst, 7, seq, []byte("ping")):
		case <-tick.C:
			continue
		case <-deadline:
			return false
		}
		for wait := true; wait; {
			select {
			case p := <-n.replies:
				if p.Src == dst && packettest.IsEchoReply(p, 7, seq) {
					return true
				}
			case <-tick.C:
				wait = false
			case <-deadline:
				return false
			}
		}
	}
}

func (n *runningNode) ping(t *testing.T, src, dst netip.Addr) {
	t.Helper()
	if !n.answered(src, dst, 10*time.Second) {
		t.Fatalf("no reply from %v", dst)
	}
}

func (n *runningNode) waitLog(t *testing.T, pattern string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	eventually(t, func() bool { return re.MatchString(n.log.String()) })
}

// logMatches reports whether log has a line matching pattern.
func logMatches(log, pattern string) bool {
	return regexp.MustCompile(pattern).MatchString(log)
}

func memoryRegistry(t *testing.T) (*memory.Network, *transport.Registry) {
	t.Helper()
	net := memory.NewNetwork(memory.Datagram)
	reg, err := transport.NewRegistry(net)
	if err != nil {
		t.Fatal(err)
	}
	return net, reg
}

func TestDataPlaneRunsAndFollowsTheMap(t *testing.T) {
	s := newTestSpace(t)
	net, reg := memoryRegistry(t)
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
	a.waitLog(t, `msg="map applied" .*version=2`)
	eventually(t, func() bool { return canListen(net, old) })
	b.ping(t, b4, a4)
	if canListen(net, s.listen) {
		t.Fatal("a doesn't listen on its new address")
	}

	// Older and tampered maps leave the node on version 2.
	a.maps <- s.build(t, 1)
	a.waitLog(t, "map not newer")
	bad := s.build(t, 3)
	bad[len(bad)-1] ^= 1
	a.maps <- bad
	a.waitLog(t, "bad signature")
	a.ping(t, a4, b4)

	// A closed Maps channel only means no more maps.
	close(a.maps)
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

// A node removed from its space stops its data plane and stays idle; a
// later map that has it again brings it back.
func TestDataPlaneStopsWhileRemoved(t *testing.T) {
	s := newTestSpace(t)
	net, reg := memoryRegistry(t)
	a := startNode(t, reg, s.a, s.verified(t, 1))
	b := startNode(t, reg, s.b, s.verified(t, 1))
	a4, _ := overlay(1)
	b4, _ := overlay(2)
	b.ping(t, b4, a4)

	without := s.buildWithout(t, 2, s.a)
	a.maps <- without
	b.maps <- without
	a.waitLog(t, "removed from space")
	eventually(t, func() bool { return canListen(net, s.listen) })
	b.waitLog(t, `msg="map applied" .*version=2`)
	// Taken, so an older map with the node doesn't bring it back.
	a.maps <- s.build(t, 1)
	a.waitLog(t, "map not newer")
	if a.tuns.Load() != 1 {
		t.Fatal("a restarted on an older map")
	}
	// Removed once, said once.
	a.maps <- s.buildWithout(t, 3, s.a)
	// A map not newer than 3 is refused only once 3 was taken.
	eventually(t, func() bool {
		select {
		case a.maps <- s.build(t, 2):
		default:
		}
		return strings.Count(a.log.String(), "map not newer") >= 2
	})
	if c := strings.Count(a.log.String(), "removed from space"); c != 1 {
		t.Fatalf("%d removal messages", c)
	}

	v4 := s.build(t, 4)
	a.maps <- v4
	b.maps <- v4
	a.waitLog(t, "back in space")
	a.waitLog(t, `msg="map applied" .*version=4`)
	b.ping(t, b4, a4)
	if a.tuns.Load() != 2 {
		t.Fatalf("%d TUNs, want the data plane started twice", a.tuns.Load())
	}
}

// failingConfigurator fails Apply while failing is set; it blocks Apply
// until ctx ends while blocking is set.
type failingConfigurator struct {
	failing, blocking atomic.Bool
	applies           atomic.Int32
}

func (c *failingConfigurator) Apply(ctx context.Context, _ netcfg.Config) error {
	c.applies.Add(1)
	if c.blocking.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if c.failing.Load() {
		return errors.New("the kernel said no")
	}
	return nil
}

func (c *failingConfigurator) DefaultRoute(context.Context, netcfg.Family) (netcfg.Route, error) {
	return netcfg.Route{}, netcfg.ErrNoDefaultRoute
}

func (c *failingConfigurator) Survey(context.Context) (netcfg.Survey, error) {
	return netcfg.Survey{}, errors.ErrUnsupported
}

func (c *failingConfigurator) Watch(context.Context) (<-chan struct{}, error) {
	return nil, errors.ErrUnsupported
}

func (c *failingConfigurator) Close() error { return nil }

func TestAFailedApplyIsRetried(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	ifc := &failingConfigurator{}
	n := newRunningNode()
	n.ifc = ifc
	n.run(t, n.dataPlane(reg, s.a, s.verified(t, 1)))
	n.waitLog(t, `msg="map applied" .*version=1`)

	ifc.failing.Store(true)
	n.maps <- s.build(t, 2)
	n.waitLog(t, `applying the map failed, retrying`)
	failedAt := time.Now()
	ifc.failing.Store(false)
	n.waitLog(t, `msg="map applied" .*version=2`)
	// Retried on the data plane's own retryAfter, not the default: a few
	// testRetry on an idle machine, and still far below RetryAfter on one
	// busy with other tests.
	if since := time.Since(failedAt); since > RetryAfter/2 {
		t.Fatalf("retried after %v", since)
	}
}

func TestAShutdownDuringTheFirstApplyIsNoFailure(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	ifc := &failingConfigurator{}
	ifc.blocking.Store(true)
	n := newRunningNode()
	n.ifc = ifc
	go func() { n.done <- RunDataPlane(n.ctx, n.dataPlane(reg, s.a, s.verified(t, 1))) }()
	eventually(t, func() bool { return ifc.applies.Load() > 0 })
	n.stop()
	if err := <-n.done; err != nil {
		t.Fatalf("got %v", err)
	}
	// Its own connection (a worker's), down with it.
	n.noRefusals(t)
	if n.conn.state != connDisconnected {
		t.Errorf("connection %s after a shutdown during the first start", n.conn.state)
	}
}

// flakyInbound is a's memory listener, opened through Open so the test
// can kill it under the data plane.
type flakyInbound struct {
	net    *memory.Network
	at     string
	mu     sync.Mutex
	opened []time.Time
	last   transport.Listener
}

func (f *flakyInbound) Listeners(netmap.Section) []Listener {
	return []Listener{{Key: "flaky", Transport: memory.Name, Open: func(ctx context.Context, peers transport.Peers) (transport.Listener, error) {
		l, err := f.net.Listen(ctx, transport.ListenConfig{Address: f.at, Peers: peers})
		if err == nil {
			f.mu.Lock()
			f.opened = append(f.opened, time.Now())
			f.last = l
			f.mu.Unlock()
		}
		return l, err
	}}}
}

func (*flakyInbound) Changed() <-chan struct{} { return nil }

func (f *flakyInbound) opens() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.opened...)
}

// A listener whose Serve ends on its own is opened again after
// RetryAfter, not before, and not lost.
func TestAStoppedListenerIsReopenedAfterRetryAfter(t *testing.T) {
	s := newTestSpace(t)
	net, reg := memoryRegistry(t)
	in := &flakyInbound{net: net, at: s.listen.String()}
	a := newRunningNode()
	dp := a.dataPlane(reg, s.a, s.verified(t, 1))
	dp.Inbound = in
	a.run(t, dp)
	b := startNode(t, reg, s.b, s.verified(t, 1))
	a4, _ := overlay(1)
	b4, _ := overlay(2)
	b.ping(t, b4, a4)

	in.mu.Lock()
	killed := time.Now()
	_ = in.last.Close()
	in.mu.Unlock()
	a.waitLog(t, "listener stopped, reopening")
	eventually(t, func() bool { return len(in.opens()) == 2 })
	if gap := in.opens()[1].Sub(killed); gap < testRetry {
		t.Fatalf("reopened %v after it stopped, before RetryAfter (%v)", gap, testRetry)
	}
	b.ping(t, b4, a4)
	time.Sleep(3 * testRetry)
	if n := len(in.opens()); n != 2 {
		t.Fatalf("opened %d times", n)
	}
}

func TestDataPlaneRefusesAMapWithoutTheNode(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	stranger := NodeKeys{ID: netmap.NodeID{9}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey()}
	created := false
	h := testHost()
	h.NewTUN = func(string, int) (wgtun.Device, error) {
		created = true
		return tuntest.NewChannelTUN().TUN(), nil
	}
	err := RunDataPlane(context.Background(), DataPlane{
		Keys: stranger, Map: s.verified(t, 1), Registry: reg, Inbound: DirectInbound(reg), Host: h,
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

// A start that fails before the route table is taken over (no TUN, no
// route table) removes what a crashed run left, which would otherwise
// keep traffic blocked while the node retries.
func TestAFailedStartClearsACrashedRunsRouteTable(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	n := newRunningNode()
	dp := n.dataPlane(reg, s.a, s.verified(t, 1))
	dp.RouteTable = true
	var cleared atomic.Int32
	dp.Host.ClearConfig = func(netcfg.Owner) error { cleared.Add(1); return nil }
	dp.Host.NewTUN = func(string, int) (wgtun.Device, error) { return nil, errors.New("no TUN today") }
	dp.Host.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { panic("not reached") }
	if err := RunDataPlane(n.ctx, dp); err == nil {
		t.Fatal("RunDataPlane started without a TUN")
	}
	n.noRefusals(t)
	if n.conn.state != connDisconnected {
		t.Errorf("connection %s after a failed first start", n.conn.state)
	}
	if cleared.Load() == 0 {
		t.Error("the failed start left a previous run's route table")
	}
}
