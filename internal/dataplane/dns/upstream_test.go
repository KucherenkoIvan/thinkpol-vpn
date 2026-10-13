package dns

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// handUpstream is a resolver on loopback whose UDP side is written by
// hand, so a test decides which datagrams go back and from where. Over
// TCP it answers every A question with tcpAnswer.
type handUpstream struct {
	srv                netip.AddrPort
	udpAsked, tcpAsked atomic.Int32
}

func startHandUpstream(t *testing.T, onUDP func(pc *net.UDPConn, from netip.AddrPort, q *dns.Msg), tcpAnswer string) *handUpstream {
	t.Helper()
	port := freePort(t)
	u := &handUpstream{srv: netip.AddrPortFrom(loopback, port)}
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(u.srv))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = pc.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			u.udpAsked.Add(1)
			onUDP(pc, from, q)
		}
	}()
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		u.tcpAsked.Add(1)
		_ = w.WriteMsg(answerA(q, tcpAnswer))
	})
	srv := &dns.Server{Addr: u.srv.String(), Net: "tcp", Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return u
}

func answerA(q *dns.Msg, addr string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	a := netip.MustParseAddr(addr).As4()
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: a[:]}}
	return m
}

// send packs m and sends it; a datagram that can't go (the asker gone
// already) is simply lost, as it would be on the wire.
func send(pc *net.UDPConn, to netip.AddrPort, m *dns.Msg) {
	if b, err := m.Pack(); err == nil {
		_, _ = pc.WriteToUDPAddrPort(b, to)
	}
}

func askUpstream(t *testing.T, u *handUpstream) []string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.SetEdns0(upstreamUDPSize, false)
	r, err := exchangeWith(m, u.srv, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return answers(r)
}

func TestTheAskedServersAnswerIsAccepted(t *testing.T) {
	u := startHandUpstream(t, func(pc *net.UDPConn, from netip.AddrPort, q *dns.Msg) {
		send(pc, from, answerA(q, "198.51.100.7"))
	}, "192.0.2.99")
	if got := askUpstream(t, u); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("answer %v", got)
	}
	if u.udpAsked.Load() != 1 || u.tcpAsked.Load() != 0 {
		t.Errorf("asked %d times over UDP, %d over TCP", u.udpAsked.Load(), u.tcpAsked.Load())
	}
}

// A spoofer that sees the query answers first, with the right ID and
// question, from another port: the answer is not taken, and as it never
// reaches the query's socket it doesn't count as a guess either.
func TestASpoofedAnswerFromAnotherSourceIsIgnored(t *testing.T) {
	spoofer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spoofer.Close() })
	u := startHandUpstream(t, func(pc *net.UDPConn, from netip.AddrPort, q *dns.Msg) {
		send(spoofer, from, answerA(q, "203.0.113.66"))
		time.Sleep(100 * time.Millisecond)
		send(pc, from, answerA(q, "198.51.100.7"))
	}, "192.0.2.99")
	if got := askUpstream(t, u); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("answer %v, want the server's", got)
	}
	if u.tcpAsked.Load() != 0 {
		t.Errorf("asked again over TCP")
	}
}

// From the server's own address and port, anything that isn't the answer
// (a wrong ID: a guess; a wrong question; garbage) sends the query over
// TCP, and what came over UDP is never used.
func TestWhatDoesntAnswerTheQueryGoesOverTCP(t *testing.T) {
	for name, wrong := range map[string]func(q *dns.Msg) []byte{
		"id": func(q *dns.Msg) []byte {
			m := answerA(q, "203.0.113.66")
			m.Id++
			b, _ := m.Pack()
			return b
		},
		"question": func(q *dns.Msg) []byte {
			m := answerA(q, "203.0.113.66")
			m.Question[0].Name = "elsewhere.example."
			b, _ := m.Pack()
			return b
		},
		"not a response": func(q *dns.Msg) []byte {
			m := answerA(q, "203.0.113.66")
			m.Response = false
			b, _ := m.Pack()
			return b
		},
		"garbage": func(*dns.Msg) []byte { return []byte{1, 2, 3} },
		"too big": func(q *dns.Msg) []byte {
			m := answerA(q, "203.0.113.66")
			for i := range 200 {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{strconv.Itoa(i)}})
			}
			b, _ := m.Pack()
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			u := startHandUpstream(t, func(pc *net.UDPConn, from netip.AddrPort, q *dns.Msg) {
				_, _ = pc.WriteToUDPAddrPort(wrong(q), from)
				time.Sleep(50 * time.Millisecond)
				send(pc, from, answerA(q, "203.0.113.67"))
			}, "198.51.100.7")
			if got := askUpstream(t, u); !slices.Equal(got, []string{"198.51.100.7"}) {
				t.Errorf("answer %v, want the TCP one", got)
			}
			if u.tcpAsked.Load() != 1 {
				t.Errorf("asked %d times over TCP", u.tcpAsked.Load())
			}
		})
	}
}

func TestATruncatedAnswerGoesOverTCP(t *testing.T) {
	u := startHandUpstream(t, func(pc *net.UDPConn, from netip.AddrPort, q *dns.Msg) {
		m := answerA(q, "203.0.113.66")
		m.Answer, m.Truncated = nil, true
		send(pc, from, m)
	}, "198.51.100.7")
	if got := askUpstream(t, u); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("answer %v, want the TCP one", got)
	}
}

// linkLocal is a link-local IPv6 address of this host's that answers
// itself, with its zone as a number (as resolved writes one): fe80::1 on
// macOS's loopback, an interface's own address elsewhere.
func linkLocal(t *testing.T) (netip.Addr, string) {
	t.Helper()
	ifcs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is6() || !p.Addr().IsLinkLocalUnicast() {
				continue
			}
			pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(p.Addr().WithZone(ifc.Name), 0)))
			if err != nil {
				continue
			}
			_ = pc.Close()
			return p.Addr(), ifc.Name
		}
	}
	t.Skip("no link-local IPv6 address here")
	return netip.Addr{}, ""
}

// A link-local upstream written with a numeric zone is answered: the
// reply comes back with the zone's name, which is the same server.
func TestALinkLocalUpstreamWithANumericZoneIsAnswered(t *testing.T) {
	addr, name := linkLocal(t)
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr.WithZone(name), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) == nil {
				send(pc, from, answerA(q, "198.51.100.7"))
			}
		}
	}()
	srv := netip.AddrPortFrom(addr.WithZone(strconv.Itoa(ifc.Index)), pc.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	r, err := exchangeWith(m, srv, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("%v: %v", srv, err)
	}
	if got := answers(r); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("answer %v", got)
	}
}
