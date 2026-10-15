package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// fakeSystem records what a node asks of the OS resolver configuration.
type fakeSystem struct {
	mu       sync.Mutex
	set      []dns.SystemConfig
	restored int
	// failSets fails that many Sets; problem is what Problem says.
	failSets int
	problem  error
}

func (f *fakeSystem) Set(c dns.SystemConfig) (dns.System, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSets > 0 {
		f.failSets--
		return nil, errors.New("no resolver configuration today")
	}
	f.set = append(f.set, c)
	return f, nil
}

func (f *fakeSystem) Restore() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restored++
	return nil
}

func (f *fakeSystem) Update(c dns.SystemConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = append(f.set, c)
	return nil
}

func (f *fakeSystem) Problem() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.problem
}

func (f *fakeSystem) counts() (set, restored int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.set), f.restored
}

// A connected device's OS resolves through the node's resolver, on its
// overlay addresses; disconnecting or stopping puts the OS's own
// configuration back.
func TestADevicePointsTheSystemAtItsResolverWhileConnected(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{}
	var asked [][]netip.Addr
	b := startDevice(t, s, reg, true, func(c *Config, dp *DataPlane) {
		if c != nil {
			c.DNS = true
			return
		}
		dp.systemDNS = sys.Set
		dp.systemUpstreams = func(exclude []netip.Addr) ([]netip.Addr, error) {
			asked = append(asked, exclude)
			return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
		}
		dp.dnsPort = 5353
	})
	b4, b6 := overlay(2)
	b.connection(t, Connected)
	eventually(t, func() bool { n, _ := sys.counts(); return n == 1 })
	sys.mu.Lock()
	got := sys.set[0]
	sys.mu.Unlock()
	// The TUN by its own name (the virtual TUNs name themselves, like a
	// macOS utun), not the one asked for.
	if !strings.HasPrefix(got.Interface, "loopbackTun") || !slices.Equal(got.Servers, []netip.Addr{b4, b6}) {
		t.Errorf("the system was pointed at %+v", got)
	}
	if len(asked) != 1 || !slices.Contains(asked[0], b4) {
		t.Errorf("the system's upstreams were asked for %v: without the node's own addresses", asked)
	}

	// Another map that changes nothing the OS needs leaves it alone.
	b.maps <- s.build(t, 2)
	b.waitLog(t, `msg="map applied" .*version=2`)
	if n, r := sys.counts(); n != 1 || r != 0 {
		t.Errorf("after a map: set %d, restored %d", n, r)
	}

	ctx := context.Background()
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if n, r := sys.counts(); n != 1 || r != 1 {
		t.Errorf("after Disconnect: set %d, restored %d", n, r)
	}
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := sys.counts(); n != 2 {
		t.Errorf("after Connect: set %d", n)
	}
	b.stop()
	if err := <-b.done; err != nil {
		t.Fatal(err)
	}
	b.done <- nil
	if n, r := sys.counts(); n != 2 || r != 2 {
		t.Errorf("after stopping: set %d, restored %d", n, r)
	}
}

func TestParseUpstreams(t *testing.T) {
	got, err := ParseUpstreams(" 192.0.2.53, [2001:db8::53]:5353,::ffff:192.0.2.1 ,")
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8::53]:5353"), netip.MustParseAddrPort("192.0.2.1:53"),
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%v, %v", got, err)
	}
	for _, bad := range []string{"resolver.example", "192.0.2.53:0", "fe80::1%eth0", "192.0.2.53:x"} {
		if _, err := ParseUpstreams(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// A worker can't reach the host's loopback from its namespace, nor read
// its resolver configuration: the supervisor passes the host's resolvers
// but loopback ones.
func TestWorkersGetTheHostsResolversButLoopback(t *testing.T) {
	s := &serverSpaces{dns: true, log: slog.New(slog.DiscardHandler), systemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("::1")}, nil
	}}
	if got := s.workerUpstreams(); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}) {
		t.Errorf("host's: %v", got)
	}
	s.dnsUpstreams = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}
	if got := s.workerUpstreams(); !slices.Equal(got, s.dnsUpstreams) {
		t.Errorf("configured: %v", got)
	}
	s.dns = false
	s.dnsUpstreams = nil
	if got := s.workerUpstreams(); got != nil {
		t.Errorf("without DNS: %v", got)
	}
}

// A device whose OS can't be pointed at its resolver stays connected, says
// DNS isn't protected (and Connect says why), and keeps trying.
func TestUnprotectedDNSIsReportedAndRetried(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{failSets: 1}
	b := startDevice(t, s, reg, false, func(c *Config, dp *DataPlane) {
		if c != nil {
			c.DNS = true
			return
		}
		dp.systemDNS = sys.Set
		dp.systemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, nil }
		dp.dnsPort = 5353
	})
	err := b.node.Connect(context.Background())
	if !errors.Is(err, ErrDNSUnprotected) {
		t.Fatalf("Connect: %v, want ErrDNSUnprotected", err)
	}
	st := b.connection(t, Connected)
	if !st.DNSUnprotected || !slices.Contains(st.Health().Problems, ProblemDNSUnprotected) {
		t.Errorf("status %+v, health %+v", st, st.Health())
	}
	// The retry points it.
	eventually(t, func() bool { n, _ := sys.counts(); return n == 1 })
	eventually(t, func() bool { return !b.node.Status().DNSUnprotected })
	if err := b.node.Connect(context.Background()); err != nil {
		t.Errorf("Connect once protected: %v", err)
	}

	// The configuration itself can say names may go elsewhere.
	sys.mu.Lock()
	sys.problem = dns.ErrUnprotected
	sys.mu.Unlock()
	if st := b.node.Status(); !st.DNSUnprotected {
		t.Errorf("a problem the system reports isn't in the status")
	}
}

// wantsTable records what the engine enforces in the OS routing table.
type wantsTable struct {
	mu    sync.Mutex
	wants []routetable.Want
}

func (w *wantsTable) Enforce(_ context.Context, want routetable.Want) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wants = append(w.wants, want)
	return nil
}
func (w *wantsTable) Status() routetable.Status { return routetable.Status{Enforced: true} }
func (w *wantsTable) Close() error              { return nil }

func (w *wantsTable) upstreams() []netip.AddrPort {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.wants) == 0 {
		return nil
	}
	return w.wants[len(w.wants)-1].Upstreams
}

// In route-table mode the resolver's direct upstreams reach the route
// table (macOS keeps them reachable from the physical interface), and
// follow the system's own resolvers when they change.
func TestTheDirectUpstreamsReachTheRouteTable(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{}
	table := &wantsTable{}
	b := startDevice(t, s, reg, true, func(c *Config, dp *DataPlane) {
		if c != nil {
			c.DNS = true
			return
		}
		dp.RouteTable = true
		dp.newRoutes = func(*slog.Logger, routetable.Guard) (dataplane.RouteTable, error) { return table, nil }
		dp.clearNetwork = func() error { return nil }
		dp.systemDNS = sys.Set
		dp.systemUpstreams = func([]netip.Addr) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
		}
		dp.dnsPort = 5353
	})
	b.connection(t, Connected)
	eventually(t, func() bool {
		return slices.Equal(table.upstreams(), []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")})
	})
	eventually(t, func() bool { n, _ := sys.counts(); return n == 1 })
	sys.mu.Lock()
	tell := sys.set[0].Upstreams
	sys.mu.Unlock()
	b4, _ := overlay(2)
	tell([]netip.Addr{netip.MustParseAddr("198.51.100.53"), b4}) // a new network's, and the node's own
	if got := table.upstreams(); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}) {
		t.Errorf("after the system's resolvers changed: %v", got)
	}
}

// A configured upstream reaches the route table with its port: the
// leak guard on macOS exempts DNS to it on that port only.
func TestAConfiguredUpstreamReachesTheRouteTableWithItsPort(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	table := &wantsTable{}
	up := netip.MustParseAddrPort("[2001:db8::53]:5353")
	b := startDevice(t, s, reg, true, func(c *Config, dp *DataPlane) {
		if c != nil {
			c.DNS = true
			return
		}
		dp.RouteTable = true
		dp.newRoutes = func(*slog.Logger, routetable.Guard) (dataplane.RouteTable, error) { return table, nil }
		dp.clearNetwork = func() error { return nil }
		dp.systemDNS = (&fakeSystem{}).Set
		dp.DNSUpstreams = []netip.AddrPort{up}
		dp.dnsPort = 5353
	})
	b.connection(t, Connected)
	eventually(t, func() bool { return slices.Equal(table.upstreams(), []netip.AddrPort{up}) })
}
