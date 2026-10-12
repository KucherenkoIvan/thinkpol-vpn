package dns

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// upstream is a fake resolver on loopback: it answers every A question
// with addr (and a big answer for "big." names, TC over UDP for "tc."
// names) and records what it was asked.
type upstream struct {
	addr netip.Addr
	port uint16
	fail bool

	mu    sync.Mutex
	asked []*dns.Msg
}

func startUpstream(t *testing.T, answer string) *upstream {
	t.Helper()
	u := &upstream{addr: netip.MustParseAddr(answer)}
	port := freePort(t)
	u.port = port
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		u.mu.Lock()
		u.asked = append(u.asked, r.Copy())
		fail := u.fail
		u.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		if fail {
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		_, udp := w.LocalAddr().(*net.UDPAddr)
		switch {
		case q.Name == "tc.example." && udp:
			m.Truncated = true
		case q.Name == "nx.example.":
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			n := 1
			if q.Name == "big.example." || q.Name == "tc.example." {
				n = 100
			}
			for i := range n {
				a := u.addr.As4()
				a[3] += byte(i)
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: a[:]})
			}
		}
		if udp {
			size := dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
			m.Truncate(size)
		}
		_ = w.WriteMsg(m)
	})
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), Net: network, Handler: h}
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ListenAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return u
}

func (u *upstream) setFailing() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.fail = true
}

func (u *upstream) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), u.port)
}

func (u *upstream) names() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []string
	for _, m := range u.asked {
		out = append(out, m.Question[0].Name)
	}
	return out
}

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

var (
	loopback   = netip.MustParseAddr("127.0.0.1")
	laptop4    = netip.MustParseAddr("100.64.0.2")
	laptop6    = netip.MustParseAddr("fd12:3456:789a::2")
	overlayNet = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd12:3456:789a::/48")}
)

type fixture struct {
	srv            *Server
	domestic, exit *upstream
	port           uint16
	cfg            Config
}

// newFixture serves on loopback: "direct." names go to the domestic
// upstream, "blocked." names nowhere, everything else through the "tunnel"
// to the exit's resolver (also on loopback).
func newFixture(t *testing.T, o Options) *fixture {
	t.Helper()
	f := &fixture{domestic: startUpstream(t, "198.51.100.1"), exit: startUpstream(t, "203.0.113.1"), port: freePort(t)}
	o.Upstreams = append(o.Upstreams, f.domestic.addrPort())
	o.Port, o.TunnelPort = f.port, f.exit.port
	f.srv = New(o)
	t.Cleanup(func() { _ = f.srv.Close() })
	f.cfg = Config{
		Listen:  []netip.Addr{loopback},
		Clients: []netip.Prefix{netip.PrefixFrom(loopback, 32)},
		Zone:    "home.internal",
		Names:   map[string][]netip.Addr{"laptop": {laptop4, laptop6}, "server-1": {netip.MustParseAddr("100.64.0.1")}},
		Overlay: overlayNet,
		Route:   f.route,
	}
	f.srv.Update(f.cfg)
	return f
}

func (f *fixture) route(name string) Route {
	switch {
	case name == "direct.example" || len(name) > 7 && name[len(name)-7:] == ".direct":
		return Route{Kind: RouteDirect}
	case name == "blocked.example":
		return Route{Kind: RouteBlock}
	}
	return Route{Kind: RouteTunnel, Via: []netip.Addr{loopback}}
}

func (f *fixture) ask(t *testing.T, network, name string, qtype uint16, edit ...func(*dns.Msg)) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	for _, e := range edit {
		e(m)
	}
	c := &dns.Client{Net: network, Timeout: 5 * time.Second}
	r, _, err := c.Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.port))))
	if err != nil {
		t.Fatalf("%s %s: %v", network, name, err)
	}
	return r
}

func answers(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			out = append(out, rr.A.String())
		case *dns.AAAA:
			out = append(out, rr.AAAA.String())
		case *dns.PTR:
			out = append(out, rr.Ptr)
		}
	}
	return out
}

func TestOverlayNamesAreAnsweredAndNeverForwarded(t *testing.T) {
	f := newFixture(t, Options{})
	for _, network := range []string{"udp", "tcp"} {
		if r := f.ask(t, network, "laptop.home.internal.", dns.TypeA); r.Rcode != dns.RcodeSuccess || !slices.Equal(answers(r), []string{"100.64.0.2"}) {
			t.Errorf("%s A: %v %v", network, dns.RcodeToString[r.Rcode], answers(r))
		}
	}
	if r := f.ask(t, "udp", "LAPTOP.Home.Internal.", dns.TypeAAAA); !slices.Equal(answers(r), []string{"fd12:3456:789a::2"}) {
		t.Errorf("AAAA, any case: %v", answers(r))
	}
	if r := f.ask(t, "udp", "server-1.home.internal.", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("a name without IPv6: %v %v", dns.RcodeToString[r.Rcode], answers(r))
	}
	for _, name := range []string{"phone.home.internal.", "laptop.other.internal.", "a.laptop.home.internal.", "internal.", "router.internal."} {
		if r := f.ask(t, "udp", name, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s: %v, want NXDOMAIN", name, dns.RcodeToString[r.Rcode])
		}
	}
	if r := f.ask(t, "udp", "2.0.64.100.in-addr.arpa.", dns.TypePTR); !slices.Equal(answers(r), []string{"laptop.home.internal."}) {
		t.Errorf("PTR: %v", answers(r))
	}
	if r := f.ask(t, "udp", "9.0.64.100.in-addr.arpa.", dns.TypePTR); r.Rcode != dns.RcodeNameError {
		t.Errorf("PTR of an unknown overlay address: %v", dns.RcodeToString[r.Rcode])
	}
	name, _ := dns.ReverseAddr(laptop6.String())
	if r := f.ask(t, "udp", name, dns.TypePTR); !slices.Equal(answers(r), []string{"laptop.home.internal."}) {
		t.Errorf("PTR v6: %v", answers(r))
	}
	if got := append(f.domestic.names(), f.exit.names()...); len(got) != 0 {
		t.Errorf("forwarded: %v", got)
	}
	if c := f.srv.Counters(); c.Overlay != 12 || c.Direct+c.Tunnel != 0 {
		t.Errorf("counters %+v", c)
	}
}

func TestNamesGoWhereTheirRouteSays(t *testing.T) {
	f := newFixture(t, Options{})
	if r := f.ask(t, "udp", "direct.example.", dns.TypeA); !slices.Equal(answers(r), []string{"198.51.100.1"}) {
		t.Errorf("direct: %v", answers(r))
	}
	if r := f.ask(t, "udp", "foreign.example.", dns.TypeA); !slices.Equal(answers(r), []string{"203.0.113.1"}) {
		t.Errorf("tunnel: %v", answers(r))
	}
	if r := f.ask(t, "udp", "blocked.example.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("blocked: %v", dns.RcodeToString[r.Rcode])
	}
	if r := f.ask(t, "udp", "nx.example.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("an upstream's NXDOMAIN: %v", dns.RcodeToString[r.Rcode])
	}
	if got := f.domestic.names(); !slices.Equal(got, []string{"direct.example."}) {
		t.Errorf("the domestic upstream was asked %v", got)
	}
	if got := f.exit.names(); !slices.Equal(got, []string{"foreign.example.", "nx.example."}) {
		t.Errorf("the exit was asked %v", got)
	}
}

// A cached answer is served only for the route it came by: once the rules
// send a name another way, it is asked there.
func TestCachedAnswersStayWithTheirRoute(t *testing.T) {
	f := newFixture(t, Options{})
	for range 3 {
		if r := f.ask(t, "udp", "foreign.example.", dns.TypeA); !slices.Equal(answers(r), []string{"203.0.113.1"}) {
			t.Fatalf("tunnel: %v", answers(r))
		}
	}
	if n := len(f.exit.names()); n != 1 {
		t.Errorf("the exit was asked %d times, want 1 (cached)", n)
	}
	if c := f.srv.Counters(); c.CacheHits != 2 {
		t.Errorf("cache hits %d", c.CacheHits)
	}
	cfg := f.cfg
	cfg.Route = func(string) Route { return Route{Kind: RouteDirect} }
	f.srv.Update(cfg)
	if r := f.ask(t, "udp", "foreign.example.", dns.TypeA); !slices.Equal(answers(r), []string{"198.51.100.1"}) {
		t.Errorf("after the rules changed: %v", answers(r))
	}
	cfg.Route = f.route
	f.srv.Update(cfg)
	if r := f.ask(t, "udp", "foreign.example.", dns.TypeA); !slices.Equal(answers(r), []string{"203.0.113.1"}) {
		t.Errorf("and back: %v", answers(r))
	}
}

func TestOnlyClientsMayAsk(t *testing.T) {
	f := newFixture(t, Options{})
	cfg := f.cfg
	cfg.Clients = overlayNet
	f.srv.Update(cfg)
	for _, name := range []string{"foreign.example.", "laptop.home.internal."} {
		if r := f.ask(t, "udp", name, dns.TypeA); r.Rcode != dns.RcodeRefused {
			t.Errorf("%s from outside the clients: %v", name, dns.RcodeToString[r.Rcode])
		}
	}
	if got := f.exit.names(); len(got) != 0 {
		t.Errorf("forwarded %v", got)
	}
}

func TestClientsEDNSOptionsStayHome(t *testing.T) {
	f := newFixture(t, Options{})
	r := f.ask(t, "udp", "foreign.example.", dns.TypeA, func(m *dns.Msg) {
		m.SetEdns0(4096, true)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option,
			&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)},
			&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"})
	})
	if r.IsEdns0() == nil || !r.IsEdns0().Do() {
		t.Error("the client spoke EDNS with DO: so should the answer")
	}
	f.exit.mu.Lock()
	defer f.exit.mu.Unlock()
	opt := f.exit.asked[0].IsEdns0()
	if opt == nil || len(opt.Option) != 0 || !opt.Do() {
		t.Errorf("forwarded OPT %v", opt)
	}
}

func TestFailingUpstreamsAreSkipped(t *testing.T) {
	broken := startUpstream(t, "192.0.2.1")
	broken.setFailing()
	f := newFixture(t, Options{Upstreams: []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1"), // nothing there
		broken.addrPort(),
	}, Timeout: 300 * time.Millisecond})
	if r := f.ask(t, "udp", "direct.example.", dns.TypeA); !slices.Equal(answers(r), []string{"198.51.100.1"}) {
		t.Errorf("answer %v %v", dns.RcodeToString[r.Rcode], answers(r))
	}
	if got := broken.names(); len(got) != 1 {
		t.Errorf("the broken upstream was asked %v", got)
	}
	f.domestic.setFailing()
	if r := f.ask(t, "udp", "a.direct.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("no upstream answering: %v", dns.RcodeToString[r.Rcode])
	}
	if c := f.srv.Counters(); c.Failed != 1 {
		t.Errorf("failed %d", c.Failed)
	}
}

func TestLargeAnswersFitTheClient(t *testing.T) {
	f := newFixture(t, Options{})
	// Truncated over UDP by the upstream: asked again over TCP.
	if r := f.ask(t, "tcp", "tc.example.", dns.TypeA); len(r.Answer) != 100 {
		t.Errorf("over TCP: %d answers", len(r.Answer))
	}
	r := f.ask(t, "udp", "big.example.", dns.TypeA)
	r.Compress = true // as it was sent
	if !r.Truncated || r.Len() > dns.MinMsgSize {
		t.Errorf("a client without EDNS got %d bytes, truncated %v", r.Len(), r.Truncated)
	}
	r = f.ask(t, "udp", "big.example.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(4096, false) })
	r.Compress = true
	if r.Len() > upstreamUDPSize {
		t.Errorf("an EDNS client got %d bytes", r.Len())
	}
	if r := f.ask(t, "tcp", "big.example.", dns.TypeA); r.Truncated || len(r.Answer) != 100 {
		t.Errorf("over TCP: %d answers, truncated %v", len(r.Answer), r.Truncated)
	}
}

func TestListenersFollowTheConfig(t *testing.T) {
	f := newFixture(t, Options{})
	cfg := f.cfg
	cfg.Listen = nil
	f.srv.Update(cfg)
	c := &dns.Client{Net: "tcp", Timeout: 500 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("laptop.home.internal.", dns.TypeA)
	if _, _, err := c.Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.port)))); err == nil {
		t.Error("still answering without addresses to listen on")
	}
	f.srv.Update(f.cfg)
	if r := f.ask(t, "tcp", "laptop.home.internal.", dns.TypeA); len(r.Answer) != 1 {
		t.Errorf("listening again: %v", answers(r))
	}
}

func TestCacheIsBounded(t *testing.T) {
	c := newCache(2)
	now := time.Now()
	msg := func(name string, ttl uint32) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.Response = true
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)}}
		return m
	}
	key := func(name string) cacheKey { return cacheKey{name: name, qtype: dns.TypeA, route: "1"} }
	c.put(key("a"), msg("a.", 60), now)
	c.put(key("b"), msg("b.", 60), now)
	c.get(key("a"), now) // a is now the most recent
	c.put(key("c"), msg("c.", 60), now)
	if _, ok := c.get(key("b"), now); ok {
		t.Error("the least recently used entry stayed")
	}
	m, ok := c.get(key("a"), now.Add(20*time.Second))
	if !ok || m.Answer[0].Header().Ttl != 40 {
		t.Errorf("aged TTL: %v %v", ok, m)
	}
	if _, ok := c.get(key("a"), now.Add(time.Minute)); ok {
		t.Error("an expired answer was served")
	}
	c.put(key("z"), msg("z.", 0), now)
	if _, ok := c.get(key("z"), now); ok {
		t.Error("a TTL of 0 was cached")
	}
}

func TestReversePrefix(t *testing.T) {
	for name, want := range map[string]string{
		"2.0.64.100.in-addr.arpa": "100.64.0.2/32",
		"64.100.in-addr.arpa":     "100.64.0.0/16",
		"in-addr.arpa":            "0.0.0.0/0",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa": "fd12:3456:789a::1/128",
		"d.f.ip6.arpa": "fd00::/8",
	} {
		p, full, ok := reversePrefix(dns.SplitDomainName(name))
		if !ok || p.String() != want || full != (p.IsSingleIP()) {
			t.Errorf("%s: %v %v %v", name, p, full, ok)
		}
	}
	for _, name := range []string{"1.0.0.0.0.64.100.in-addr.arpa", "256.0.64.100.in-addr.arpa", "02.0.64.100.in-addr.arpa", "x.ip6.arpa", "example.com", "arpa"} {
		if _, _, ok := reversePrefix(dns.SplitDomainName(name)); ok {
			t.Errorf("%s parsed", name)
		}
	}
}

// Names a search list makes of overlay names, and names a resolver can't
// match the rules against, never leave.
func TestNoInternalOrEscapedNameIsForwarded(t *testing.T) {
	f := newFixture(t, Options{})
	for _, name := range []string{"x.lab.internal.example.com.", "internal.direct.", "a.internal.b.c."} {
		if r := f.ask(t, "udp", name, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s: %v, want NXDOMAIN", name, dns.RcodeToString[r.Rcode])
		}
	}
	if r := f.ask(t, "udp", `evil\.direct.example.`, dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Errorf("an escaped dot: %v", dns.RcodeToString[r.Rcode])
	}
	if got := append(f.domestic.names(), f.exit.names()...); len(got) != 0 {
		t.Errorf("forwarded: %v", got)
	}
}

// A reverse name goes where its address goes; one under the overlay, or
// covering part of it, is answered here.
func TestReverseNamesFollowTheirAddress(t *testing.T) {
	f := newFixture(t, Options{})
	cfg := f.cfg
	cfg.RouteAddr = func(a netip.Addr) Route {
		if a == netip.MustParseAddr("192.0.2.1") {
			return Route{Kind: RouteDirect}
		}
		return Route{Kind: RouteTunnel, Via: []netip.Addr{loopback}}
	}
	f.srv.Update(cfg)
	f.ask(t, "udp", "1.2.0.192.in-addr.arpa.", dns.TypePTR)
	f.ask(t, "udp", "9.2.0.192.in-addr.arpa.", dns.TypePTR)
	for _, name := range []string{"64.100.in-addr.arpa.", "100.in-addr.arpa.", "a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa."} {
		if r := f.ask(t, "udp", name, dns.TypeSOA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s: %v", name, dns.RcodeToString[r.Rcode])
		}
	}
	if r := f.ask(t, "udp", "2.0.192.in-addr.arpa.", dns.TypeSOA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("a reverse zone outside the overlay: %v", dns.RcodeToString[r.Rcode])
	}
	if got := f.domestic.names(); !slices.Equal(got, []string{"1.2.0.192.in-addr.arpa."}) {
		t.Errorf("domestic asked %v", got)
	}
	if got := f.exit.names(); !slices.Equal(got, []string{"9.2.0.192.in-addr.arpa."}) {
		t.Errorf("exit asked %v", got)
	}
}

func TestUpstreamsCanChange(t *testing.T) {
	f := newFixture(t, Options{})
	other := startUpstream(t, "192.0.2.77")
	if r := f.ask(t, "udp", "direct.example.", dns.TypeA); !slices.Equal(answers(r), []string{"198.51.100.1"}) {
		t.Fatalf("before: %v", answers(r))
	}
	f.srv.SetUpstreams([]netip.AddrPort{other.addrPort()})
	if r := f.ask(t, "udp", "direct.example.", dns.TypeA); !slices.Equal(answers(r), []string{"192.0.2.77"}) {
		t.Errorf("after: %v (a cached answer of the old upstream?)", answers(r))
	}
}

func TestOneClientCantTakeEveryQuery(t *testing.T) {
	s := New(Options{})
	a, b := netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")
	for range maxPerClient {
		if !s.takeClient(a) {
			t.Fatal("refused below the limit")
		}
	}
	if s.takeClient(a) {
		t.Error("over the limit")
	}
	if !s.takeClient(b) {
		t.Error("another client refused")
	}
	s.releaseClient(a)
	if !s.takeClient(a) {
		t.Error("refused after a release")
	}
}
