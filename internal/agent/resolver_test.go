package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
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
	b.applied(t, 2)
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
// resolvers: both families, IPv4 first, port 53, every one passing the
// worker's egress; with -dns-upstream, the configured ones. The uplink
// here carries neither family, so the static order stands.
func TestAWorkerResolvesThroughTheDefaultPublicUpstreams(t *testing.T) {
	s := &serverSpaces{dns: true, follow: mapFollower{log: slog.New(slog.DiscardHandler)}}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("9.9.9.9:53"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("[2620:fe::fe]:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	}
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, want) {
		t.Fatalf("defaults: %v, want %v", got, want)
	}
	s.dnsUpstreams = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, s.dnsUpstreams) {
		t.Errorf("configured: %v", got)
	}
	s.dns = false
	s.dnsUpstreams = nil
	if got := s.workerUpstreams(supervisor.EgressInfo{}); got != nil {
		t.Errorf("without DNS: %v", got)
	}
}

// The defaults are ordered for the uplink: when it carries exactly one
// family, that family's upstreams come first, so a single-family exit
// doesn't wait out a dead family's timeout ahead of a working upstream;
// with both or neither, the static order stands.
func TestTheDefaultUpstreamsFollowTheUplinkFamily(t *testing.T) {
	v4 := []netip.AddrPort{
		netip.MustParseAddrPort("9.9.9.9:53"), netip.MustParseAddrPort("1.1.1.1:53"),
	}
	v6 := []netip.AddrPort{
		netip.MustParseAddrPort("[2620:fe::fe]:53"), netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	}
	static := append(slices.Clone(v4), v6...)
	for _, tc := range []struct {
		name   string
		egress supervisor.EgressInfo
		want   []netip.AddrPort
	}{
		{"both families", supervisor.EgressInfo{Uplink: "eth0", IPv4: true, IPv6: true}, static},
		{"ipv4 only", supervisor.EgressInfo{Uplink: "eth0", IPv4: true}, append(slices.Clone(v4), v6...)},
		{"ipv6 only", supervisor.EgressInfo{Uplink: "eth0", IPv6: true}, append(slices.Clone(v6), v4...)},
		{"no uplink", supervisor.EgressInfo{Err: "no default route"}, static},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &serverSpaces{dns: true, follow: mapFollower{log: slog.New(slog.DiscardHandler)}}
			if got := s.workerUpstreams(tc.egress); !slices.Equal(got, tc.want) {
				t.Fatalf("%s: %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// exitSpaces is a serverSpaces of an exit (a server whose section allows
// egress) with ups as its configured upstreams; its log goes to the
// returned buffer.
func exitSpaces(t *testing.T, ups ...netip.AddrPort) (*serverSpaces, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	s := &serverSpaces{dns: true, report: &report{mode: ModeServer}, dnsUpstreams: ups}
	s.follow.section.Node.Kind = netmap.NodeServer
	s.follow.section.Node.AllowEgress = true
	s.log = slog.New(slog.NewTextHandler(&buf, nil))
	return s, &buf
}

// An exit whose every upstream the worker's egress refuses resolves
// nothing rather than asking the host's resolvers: only a worker may
// not fall back to those. The log says so without pointing at
// -dns-upstream, which was set and refused.
func TestAWorkerWithEveryUpstreamRefusedHasNone(t *testing.T) {
	s, buf := exitSpaces(t, netip.MustParseAddrPort("192.168.1.53:53"), netip.MustParseAddrPort("169.254.169.254:53"))
	ups := s.workerUpstreams(supervisor.EgressInfo{})
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
	section.Node.AllowEgress = true // an exit's worker: the resolver warns
	// A worker has no Device: the host's resolvers aren't there to ask.
	r := &runner{dp: DataPlane{DNS: true, DNSUpstreams: ups, Forward: true, Log: s.log},
		follow: mapFollower{section: section}}
	if res := r.newResolver(); res == nil {
		t.Fatal("no resolver")
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
		Device: &DeviceHost{SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
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

// An upstream the worker's egress refuses is not asked: it is named in
// the log, counted in the status and the health, and -egress-allowed
// opens it. The log says each refused address once per change of the
// refused set, not on every apply.
func TestAnUpstreamTheEgressRefusesIsNotAskedAndNamed(t *testing.T) {
	private := netip.MustParseAddrPort("192.168.1.53:53")
	metadata := netip.MustParseAddrPort("169.254.169.254:53")
	// Azure's resolver, a metadata service EgressNotWorthAllowing names
	// and the likeliest host resolver on a cloud.
	azure := netip.MustParseAddrPort("168.63.129.16:53")
	// The mapped form of a metadata address is refused like its own.
	mappedMetadata := netip.MustParseAddrPort("[::ffff:169.254.169.254]:53")
	public := netip.MustParseAddrPort("9.9.9.9:53")
	s, buf := exitSpaces(t, private, public, metadata, azure, mappedMetadata)
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	for _, a := range []string{"192.168.1.53:53", "169.254.169.254:53", "[::ffff:169.254.169.254]:53", "168.63.129.16:53"} {
		if !strings.Contains(buf.String(), a) {
			t.Errorf("the log doesn't name the refused upstream %s:\n%s", a, buf.String())
		}
	}
	// The hint suggests -egress-allowed for a private upstream, never
	// for a metadata one, mapped form included.
	for _, l := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(l, "refuses the upstream") {
			continue
		}
		if strings.Contains(l, "169.254.169.254") || strings.Contains(l, "168.63.129.16") {
			if strings.Contains(l, "egress-allowed") {
				t.Errorf("the hint suggests opening a metadata address: %s", l)
			}
		} else if !strings.Contains(l, "hint=\"-dns-upstream or -egress-allowed\"") {
			t.Errorf("the hint for a private upstream doesn't name -egress-allowed: %s", l)
		}
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 4 {
		t.Fatalf("status: %d", st.DNSUpstreamsRefused)
	} else if h := st.Health(); h.Level != HealthDegraded || !slices.Contains(h.Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("health %+v", h)
	}

	// The same inputs again log nothing: the warning is once per change
	// of the refused set, not on every apply.
	before := buf.String()
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	if n := strings.Count(buf.String(), "192.168.1.53:53"); n != 1 {
		t.Errorf("the refused upstream was logged %d times, want once", n)
	}

	// A change of the refused set logs the refused ones again.
	s.egressAllowed = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{private, public}) {
		t.Fatalf("with -egress-allowed kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 3 {
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
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{public}) {
		t.Fatalf("kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 0 || slices.Contains(st.Health().Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("after clearing: %d, %v", st.DNSUpstreamsRefused, st.Health())
	}
}

// A server whose section allows no egress is not an exit, and neither is
// a device's that allows it: no device asks their resolvers, so refused
// upstreams are neither counted in health nor logged, though the
// resolver still gets none of them.
func TestAServerWithoutEgressReportsNoRefusedUpstreams(t *testing.T) {
	var buf bytes.Buffer
	s := &serverSpaces{dns: true, report: &report{mode: ModeServer},
		dnsUpstreams: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.53:53"), netip.MustParseAddrPort("9.9.9.9:53")}}
	s.log = slog.New(slog.NewTextHandler(&buf, nil))
	s.follow.section.Node.Kind = netmap.NodeServer
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("9.9.9.9:53")}) {
		t.Fatalf("kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 0 || slices.Contains(st.Health().Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("a non-exit's status says refused upstreams: %+v", st.Health())
	}
	if strings.Contains(buf.String(), "refuses the upstream") {
		t.Errorf("a non-exit reported a refused upstream:\n%s", buf.String())
	}

	// A device's AllowEgress doesn't make its worker an exit's either.
	s.follow.section.Node.Kind = netmap.NodeDevice
	s.follow.section.Node.AllowEgress = true
	if got := s.workerUpstreams(supervisor.EgressInfo{}); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("9.9.9.9:53")}) {
		t.Fatalf("a device's kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 0 || slices.Contains(st.Health().Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("a device's status says refused upstreams: %+v", st.Health())
	}
	if strings.Contains(buf.String(), "refuses the upstream") {
		t.Errorf("a device's resolver reported a refused upstream:\n%s", buf.String())
	}
}

// An exit that stops allowing egress reports nothing further: the count
// is cleared and the logged set forgotten, so egress allowed again warns
// about the same refused set from scratch.
func TestAnExitLosingEgressReportsNothingFurther(t *testing.T) {
	s, buf := exitSpaces(t, netip.MustParseAddrPort("192.168.1.53:53"))
	if got := s.workerUpstreams(supervisor.EgressInfo{}); got != nil {
		t.Fatalf("the exit kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 1 {
		t.Fatalf("the exit's status: %d", st.DNSUpstreamsRefused)
	}

	s.follow.section.Node.AllowEgress = false
	if got := s.workerUpstreams(supervisor.EgressInfo{}); got != nil {
		t.Fatalf("the non-exit kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 0 || slices.Contains(st.Health().Problems, ProblemDNSUpstreamRefused) {
		t.Fatalf("the non-exit's status says refused upstreams: %+v", st.Health())
	}

	s.follow.section.Node.AllowEgress = true
	if got := s.workerUpstreams(supervisor.EgressInfo{}); got != nil {
		t.Fatalf("an exit again kept: %v", got)
	}
	if st := s.report.status(); st.DNSUpstreamsRefused != 1 {
		t.Fatalf("an exit again's status: %d", st.DNSUpstreamsRefused)
	}
	if n := strings.Count(buf.String(), "refuses the upstream"); n != 2 {
		t.Errorf("the refused upstream was logged %d times, want twice", n)
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
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

	// The configuration itself can say names may go elsewhere: told once
	// the status says so (here, as the next map is taken).
	sys.mu.Lock()
	sys.problem = dns.ErrUnprotected
	sys.mu.Unlock()
	if st := b.node.Status(); !st.DNSUnprotected {
		t.Errorf("a problem the system reports isn't in the status")
	}
	b.maps <- s.build(t, 2)
	b.events.are(t, Event{EventConnected, 1}, Event{EventDNSUnprotected, 1}, Event{EventDNSUnprotected, 2})
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
	})
	b.connection(t, Connected)
	eventually(t, func() bool { n, _ := sys.counts(); return n == 1 })
	sys.mu.Lock()
	first := sys.set[0]
	sys.mu.Unlock()
	if !first.UpstreamsUnknown || first.Upstreams == nil {
		t.Fatalf("the failed read isn't passed on: unknown %v", first.UpstreamsUnknown)
	}
	// Warned before the OS was pointed at the resolver; the upstreams
	// told are taken at once.
	if !logMatches(b.log.String(), `level=WARN msg="DNS: the system's resolvers are unknown`) {
		t.Error("the failed read isn't warned about")
	}
	first.Upstreams([]netip.Addr{netip.MustParseAddr("192.0.2.53")})
	if !logMatches(b.log.String(), `msg="DNS: the system's own resolvers changed".* upstreams=1`) {
		t.Error("the upstreams the OS configuration told aren't taken")
	}
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
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
	// failing fails that many Enforces; the status says the last one
	// failed, as routetable's does. broken is the table failing to put
	// the routes back on its own, and recovering, whatever Enforce did;
	// nextBroken, if set, becomes broken once the next Enforce is done.
	failing    int
	failed     bool
	broken     bool
	nextBroken *bool
	closes     int
}

func (w *wantsTable) Enforce(_ context.Context, want routetable.Want) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wants = append(w.wants, want)
	if w.nextBroken != nil {
		w.broken, w.nextBroken = *w.nextBroken, nil
	}
	w.failed = w.failing > 0
	if w.failing > 0 {
		w.failing--
		return errors.New("the routing table is busy")
	}
	return nil
}

func (w *wantsTable) Status() routetable.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.broken:
		return routetable.Status{Error: routetable.ErrorReapply}
	case w.failed:
		return routetable.Status{Error: routetable.ErrorApply}
	}
	return routetable.Status{Enforced: true}
}

func (w *wantsTable) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closes++
	return nil
}

// breakAtNextEnforce has the table fail to put the routes back on its
// own (or recover) once the next Enforce is done: before the runner's
// publish that follows it.
func (w *wantsTable) breakAtNextEnforce(broken bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nextBroken = &broken
}

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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
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
		tuning: func(t *tuning) { t.dnsPort = 5353 },
	})
	b.connection(t, Connected)
	eventually(t, func() bool { return slices.Equal(table.upstreams(), []netip.AddrPort{up}) })
}

// testUpstream is a fake resolver on 127.0.0.1 that answers every A
// question with one address and counts what it was asked.
type testUpstream struct {
	pc      *net.UDPConn
	address netip.AddrPort
	answer  netip.Addr

	mu    sync.Mutex
	asked int
}

func startTestUpstream(t *testing.T, answer netip.Addr) *testUpstream {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &testUpstream{
		pc:      pc,
		address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(pc.LocalAddr().(*net.UDPAddr).Port)),
		answer:  answer,
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = pc.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := new(mdns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			u.mu.Lock()
			u.asked++
			u.mu.Unlock()
			m := new(mdns.Msg)
			m.SetReply(q)
			a := u.answer.As4()
			m.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300}, A: a[:]}}
			if b, err := m.Pack(); err == nil {
				_, _ = pc.WriteToUDP(b, from)
			}
		}
	}()
	return u
}

func (u *testUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.asked
}

// nilInbound lists no listeners and never changes: a runner loop that
// serves none.
type nilInbound struct{}

func (nilInbound) Listeners(netmap.Section) []Listener { return nil }
func (nilInbound) Changed() <-chan struct{}            { return nil }

// freePort finds a port free for UDP and TCP on 127.0.0.1.
func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = l.Close()
		if err == nil {
			_ = pc.Close()
			return uint16(port)
		}
	}
	t.Fatal("no free port")
	return 0
}

// The running resolver asks the latest upstreams a later config delivers
// (a real query goes to the new one), and a resolver started after the
// data plane stopped (a removal, then a return) starts from the latest
// too, without a delivery of its own.
func TestTheResolverAsksTheLatestUpstreams(t *testing.T) {
	x := startTestUpstream(t, netip.MustParseAddr("192.0.2.10"))
	y := startTestUpstream(t, netip.MustParseAddr("192.0.2.11"))
	s := newTestSpace(t)
	section, err := openSection(s.verified(t, 1), s.a)
	if err != nil {
		t.Fatal(err)
	}
	logs := logring.New(1 << 20)
	// Unbuffered: a send returns once the loop took it, and a second
	// one once the loop is done with the first.
	changed := make(chan []netip.AddrPort)
	r := &runner{
		dp: DataPlane{DNS: true, DNSUpstreams: []netip.AddrPort{x.address}, tuning: tuning{dnsPort: freePort(t)}, dnsUpstreams: changed,
			Log: slog.New(slog.NewTextHandler(logs, nil)), Inbound: nilInbound{}, conn: &connection{}},
		follow: mapFollower{cur: s.verified(t, 1), section: section},
	}
	r.resolver = r.newResolver()
	r.resolver.Update(dns.Config{Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Clients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	looped := make(chan struct{})
	go func() { defer close(looped); _ = r.loop(ctx) }()

	// The resolver asks the first config's upstream.
	if a := askTheResolver(t, r.dp.tuning.dnsPort); a != x.answer {
		t.Fatalf("the resolver's answer came from %v, want the first config's %v", a, x.answer)
	}

	// A later config's list is delivered by the loop and asked at once.
	changed <- []netip.AddrPort{y.address}
	changed <- []netip.AddrPort{y.address}
	if a := askTheResolver(t, r.dp.tuning.dnsPort); a != y.answer {
		t.Fatalf("after the change the resolver's answer came from %v, want the later config's %v", a, y.answer)
	}
	if n := x.count(); n != 1 {
		t.Errorf("the old upstream was asked %d times, want once", n)
	}

	// The next start's newResolver reads the latest list, with nothing
	// delivered meanwhile.
	cancel()
	<-looped
	_ = r.resolver.Close()
	r.resolver = nil
	r.dp.tuning.dnsPort = freePort(t)
	res := r.newResolver()
	res.Update(dns.Config{Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Clients: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if !slices.Equal(r.upstreams, []netip.AddrPort{y.address}) {
		t.Fatalf("the restarted resolver starts from %v", r.upstreams)
	}
	if a := askTheResolver(t, r.dp.tuning.dnsPort); a != y.answer {
		t.Fatalf("the restarted resolver's answer came from %v, want the later config's %v", a, y.answer)
	}
	if n := x.count(); n != 1 {
		t.Errorf("the old upstream was asked %d times, want once", n)
	}
}

// askTheResolver asks the resolver on 127.0.0.1:port for a name outside
// the overlay, and returns the address its answer names.
func askTheResolver(t *testing.T, port uint16) netip.Addr {
	t.Helper()
	m := new(mdns.Msg)
	m.SetQuestion("name.example.", mdns.TypeA)
	c := &mdns.Client{Net: "udp", UDPSize: 1232, Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("the resolver answered %+v", resp.Answer)
	}
	a, ok := netip.AddrFromSlice(resp.Answer[0].(*mdns.A).A)
	if !ok {
		t.Fatalf("the resolver answered %v", resp.Answer[0])
	}
	return a
}
