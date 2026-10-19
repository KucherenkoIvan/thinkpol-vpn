package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
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
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func(exclude []netip.Addr) ([]netip.Addr, error) {
				asked = append(asked, exclude)
				return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
			}
		},
		dataPlane: func(dp *DataPlane) {
			dp.dnsPort = 5353
		},
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
	if got.Upstreams == nil || got.UpstreamsUnknown {
		t.Errorf("the system's upstreams were read, but the configuration says unknown or follows nothing")
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

// With no -dns-upstream an exit's resolver asks the default public
// resolvers: both families, port 53, every one passing the worker's
// egress; with -dns-upstream, the configured ones.
func TestAWorkerResolvesThroughTheDefaultPublicUpstreams(t *testing.T) {
	s := &serverSpaces{dns: true, follow: mapFollower{log: slog.New(slog.DiscardHandler)}}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("9.9.9.9:53"),
		netip.MustParseAddrPort("[2620:fe::fe]:53"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	}
	if got := s.workerUpstreams(); !slices.Equal(got, want) {
		t.Fatalf("defaults: %v, want %v", got, want)
	}
	var v4, v6 bool
	for _, a := range s.workerUpstreams() {
		if a.Port() != dns.Port {
			t.Errorf("%v: not port %d", a, dns.Port)
		}
		if a.Addr().Is4() {
			v4 = true
		} else if !a.Addr().Is4In6() {
			v6 = true
		}
		if supervisor.EgressRefused(a.Addr(), nil) {
			t.Errorf("default %v refused by the egress", a)
		}
	}
	if !v4 || !v6 {
		t.Errorf("both families: %v", s.workerUpstreams())
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

// An exit whose every upstream the worker's egress refuses resolves
// nothing rather than asking the host's resolvers: only a worker may
// not fall back to those. The log says so without pointing at
// -dns-upstream, which was set and refused (workerUpstreams refused
// every one and logged each).
func TestAWorkerWithEveryUpstreamRefusedHasNone(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	s := &serverSpaces{dns: true, report: &report{mode: ModeServer},
		dnsUpstreams: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.53:53"), netip.MustParseAddrPort("169.254.169.254:53")}}
	s.log = log
	ups := s.workerUpstreams()
	if ups != nil {
		t.Fatalf("all refused, kept: %v", ups)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 2 {
		t.Fatalf("status: %d", st.DNSUpstreamsRefused)
	}

	// a is a server node serving through a worker: its resolver never
	// asks the host's resolvers, not even with no upstream of its own.
	// The resolver is built the way serveSpace builds one, from the
	// worker config's DNSUpstreams (workerUpstreams' result).
	sp := newTestSpace(t)
	section, err := openSection(sp.verified(t, 1), sp.a)
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	r := &runner{dp: DataPlane{DNS: true, DNSUpstreams: ups, Forward: true, Log: log,
		Host: Host{SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) { asked = true; return nil, nil }},
	}, follow: mapFollower{section: section}}
	if res := r.newResolver(); res == nil {
		t.Fatal("no resolver")
	}
	if asked {
		t.Error("a worker's resolver asked for the host's resolvers")
	}
	if len(r.upstreams) != 0 {
		t.Errorf("upstreams %v", r.upstreams)
	}
	if !strings.Contains(buf.String(), "no upstream to ask") {
		t.Errorf("the resolver doesn't say it has no upstream:\n%s", buf.String())
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "no upstream to ask") && strings.Contains(line, "-dns-upstream") {
			t.Errorf("the no-upstream line points at -dns-upstream: %s", line)
		}
	}
}

// A server's section run in device mode (no worker) is not an exit's
// worker: with no -dns-upstream its resolver falls back to the host's
// resolvers, as a device's does.
func TestAServerSectionInDeviceModeFallsBackToTheSystemResolvers(t *testing.T) {
	sp := newTestSpace(t)
	section, err := openSection(sp.verified(t, 1), sp.a)
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	r := &runner{dp: DataPlane{DNS: true, Log: slog.New(slog.DiscardHandler),
		Host: Host{SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
			asked = true
			return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
		}},
	}, follow: mapFollower{section: section}}
	if res := r.newResolver(); res == nil {
		t.Fatal("no resolver")
	}
	if !asked {
		t.Error("a server's section in device mode didn't fall back to the host's resolvers")
	}
	if len(r.upstreams) != 1 || r.upstreams[0] != netip.MustParseAddrPort("192.0.2.53:53") {
		t.Errorf("upstreams %v", r.upstreams)
	}
}

// An upstream the worker's egress refuses is not configured for the
// resolver: it is named in the log, counted in the status and the health,
// and -egress-allowed opens it. The log says each refused address once
// per change of the refused set, not on every apply.
func TestAnUpstreamTheEgressRefusesIsReportedNotSilentlyDropped(t *testing.T) {
	var buf bytes.Buffer
	private := netip.MustParseAddrPort("192.168.1.53:53")
	metadata := netip.MustParseAddrPort("169.254.169.254:53")
	public := netip.MustParseAddrPort("9.9.9.9:53")
	s := &serverSpaces{dns: true, report: &report{mode: ModeServer},
		dnsUpstreams: []netip.AddrPort{private, public, metadata}}
	s.log = slog.New(slog.NewTextHandler(&buf, nil))
	if got := s.workerUpstreams(); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	for _, a := range []string{"192.168.1.53:53", "169.254.169.254:53"} {
		if !strings.Contains(buf.String(), a) {
			t.Errorf("the log doesn't name the refused upstream %s:\n%s", a, buf.String())
		}
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 2 {
		t.Fatalf("status: %d", st.DNSUpstreamsRefused)
	} else if h := st.Health(); h.Level != HealthDegraded || !slices.Contains(h.Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("health %+v", h)
	}

	// The same inputs again log nothing: the warning is once per change
	// of the refused set, not on every apply.
	before := buf.String()
	if got := s.workerUpstreams(); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	if n := strings.Count(buf.String(), "192.168.1.53:53"); n != 1 {
		t.Errorf("the refused upstream was logged %d times, want once", n)
	}

	// A change of the refused set logs the refused ones again.
	s.egressAllowed = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	if got := s.workerUpstreams(); !slices.Equal(got, []netip.AddrPort{private, public}) {
		t.Fatalf("with -egress-allowed kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 1 {
		t.Fatalf("with -egress-allowed status: %d", st.DNSUpstreamsRefused)
	}
	if got := buf.String(); got == before {
		t.Errorf("the changed refused set was not logged again:\n%s", got)
	}
	if n := strings.Count(buf.String(), "169.254.169.254:53"); n != 2 {
		t.Errorf("169.254.169.254:53 logged %d times, want 2", n)
	}
	if n := strings.Count(buf.String(), "192.168.1.53:53"); n != 1 {
		t.Errorf("the no-longer-refused upstream was logged %d times, want once", n)
	}

	// Nothing refused clears the problem.
	s.dnsUpstreams = []netip.AddrPort{public}
	if got := s.workerUpstreams(); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 0 || slices.Contains(st.Health().Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("after clearing: %d, %v", st.DNSUpstreamsRefused, st.Health())
	}
}

// A device whose OS can't be pointed at its resolver stays connected, says
// DNS isn't protected (and Connect says why), and keeps trying.
func TestUnprotectedDNSIsReportedAndRetried(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	// Failing twice: told once, when it starts.
	sys := &fakeSystem{failSets: 2}
	b := startDevice(t, s, reg, false, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, nil }
		},
		dataPlane: func(dp *DataPlane) {
			dp.dnsPort = 5353
		},
	})
	err := b.node.Connect(context.Background())
	if !errors.Is(err, ErrDNSUnprotected) {
		t.Fatalf("Connect: %v, want ErrDNSUnprotected", err)
	}
	st := b.connection(t, Connected)
	if !st.DNSUnprotected || !slices.Contains(st.Health().Problems, ProblemDNSUnprotected) {
		t.Errorf("status %+v, health %+v", st, st.Health())
	}
	b.events.are(t, Event{EventConnected, 1}, Event{EventDNSUnprotected, 1})
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

// A device that couldn't read the system's resolvers before pointing the
// OS at its resolver says so to the OS configuration, which tells it the
// first good read.
func TestAFailedFirstReadOfTheSystemsResolversIsPassedOn(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{}
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, errors.New("the store is unreadable") }
		},
		dataPlane: func(dp *DataPlane) {
			dp.dnsPort = 5353
		},
	})
	b.connection(t, Connected)
	eventually(t, func() bool { n, _ := sys.counts(); return n == 1 })
	sys.mu.Lock()
	first := sys.set[0]
	sys.mu.Unlock()
	if !first.UpstreamsUnknown || first.Upstreams == nil {
		t.Fatalf("the failed read isn't passed on: unknown %v", first.UpstreamsUnknown)
	}
	b.waitLog(t, `level=WARN msg="DNS: the system's resolvers are unknown`)
	first.Upstreams([]netip.Addr{netip.MustParseAddr("192.0.2.53")})
	b.waitLog(t, `msg="DNS: the system's own resolvers changed".* upstreams=1`)
}

// A system whose direct upstreams may be stale is degraded, not
// unprotected: the status says staleness, health with it, and Connect
// still succeeds.
func TestStaleUpstreamsAreDegradedNotUnprotected(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{}
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, nil }
		},
		dataPlane: func(dp *DataPlane) {
			dp.dnsPort = 5353
		},
	})
	b.connection(t, Connected)
	if err := b.node.Connect(context.Background()); err != nil {
		t.Fatalf("Connect while protected: %v", err)
	}
	sys.mu.Lock()
	sys.problem = fmt.Errorf("%w: reading the primary service's DNS servers failed at the last check", dns.ErrUpstreamsStale)
	sys.mu.Unlock()
	if st := b.node.Status(); st.DNSUnprotected || !st.DNSUpstreamsStale || !slices.Contains(st.Health().Problems, ProblemDNSUpstreamsStale) {
		t.Errorf("status %+v, health %+v", st, st.Health())
	}
	if err := b.node.Connect(context.Background()); err != nil {
		t.Errorf("Connect with stale upstreams: %v", err)
	}
	sys.mu.Lock()
	sys.problem = nil
	sys.mu.Unlock()
	if st := b.node.Status(); st.DNSUpstreamsStale || slices.Contains(st.Health().Problems, ProblemDNSUpstreamsStale) {
		t.Errorf("stale stays in the status after a good read: %+v", st.Health())
	}
}

// A problem a System doesn't tag is unprotected, not protected: a
// future System's new kind of trouble fails closed.
func TestAnUntaggedProblemIsUnprotected(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{}
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, nil }
		},
		dataPlane: func(dp *DataPlane) {
			dp.dnsPort = 5353
		},
	})
	b.connection(t, Connected)
	sys.mu.Lock()
	sys.problem = errors.New("the store is unreadable")
	sys.mu.Unlock()
	if err := b.node.Connect(context.Background()); !errors.Is(err, ErrDNSUnprotected) {
		t.Errorf("Connect with an untagged problem: %v", err)
	}
	if st := b.node.Status(); !st.DNSUnprotected || st.DNSUpstreamsStale || !slices.Contains(st.Health().Problems, ProblemDNSUnprotected) {
		t.Errorf("status %+v, health %+v", st, st.Health())
	}
}

// wantsTable records what reaches the host's route table: the engine's
// wants with the resolver's direct upstreams.
type wantsTable struct {
	mu    sync.Mutex
	wants []routetable.Want
	// failing fails that many Enforces.
	failing int
}

func (w *wantsTable) Enforce(_ context.Context, want routetable.Want) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wants = append(w.wants, want)
	if w.failing > 0 {
		w.failing--
		return errors.New("the routing table is busy")
	}
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
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { return table, nil }
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
			}
		},
		dataPlane: func(dp *DataPlane) {
			dp.RouteTable = true
			dp.dnsPort = 5353
		},
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
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS, c.DNSUpstream = true, up.String()
			p.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { return table, nil }
			p.SetSystemDNS = (&fakeSystem{}).Set
		},
		dataPlane: func(dp *DataPlane) {
			dp.RouteTable = true
			dp.dnsPort = 5353
		},
	})
	b.connection(t, Connected)
	eventually(t, func() bool { return slices.Equal(table.upstreams(), []netip.AddrPort{up}) })
}
