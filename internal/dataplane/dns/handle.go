package dns

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// overlayTTL is the TTL of overlay names' answers: they change only with
// the map.
const overlayTTL = 30

// upstreamUDPSize is the EDNS buffer size asked of upstreams (the DNS
// flag day's).
const upstreamUDPSize = 1232

func (s *Server) serveDNS(w dns.ResponseWriter, req *dns.Msg) {
	s.n.queries.Add(1)
	src := addrOf(w.RemoteAddr())
	resp := s.answer(s.config(), src, req)
	_, udp := w.LocalAddr().(*net.UDPAddr)
	fit(resp, req, udp)
	_ = w.WriteMsg(resp)
}

func addrOf(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func (s *Server) answer(cfg *Config, src netip.Addr, req *dns.Msg) *dns.Msg {
	if !slices.ContainsFunc(cfg.Clients, func(p netip.Prefix) bool { return p.Contains(src) }) {
		s.n.refused.Add(1)
		return reply(req, dns.RcodeRefused)
	}
	if req.Response || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		s.n.refused.Add(1)
		return reply(req, dns.RcodeNotImplemented)
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	// A label with an escaped dot (or anything escaped) would match the
	// rules as a different name than the one asked: refused.
	if strings.ContainsRune(name, '\\') {
		s.n.refused.Add(1)
		return reply(req, dns.RcodeRefused)
	}
	labels := dns.SplitDomainName(name)
	name = strings.Join(labels, ".")
	// Anything with an `internal` label is the overlay's or a search-list
	// retry of an overlay name: never forwarded.
	if slices.Contains(labels, "internal") {
		s.n.overlay.Add(1)
		if labels[len(labels)-1] != "internal" {
			m := reply(req, dns.RcodeNameError)
			m.Authoritative = true
			return m
		}
		return overlayAnswer(cfg, req, name, q.Qtype)
	}

	route := Route{Kind: RouteDirect}
	if p, full, ok := reversePrefix(labels); ok {
		// Reverse names go where the address goes; the overlay's (and any
		// covering part of it) are answered here.
		switch {
		case slices.ContainsFunc(cfg.Overlay, p.Overlaps):
			s.n.overlay.Add(1)
			if !full {
				m := reply(req, dns.RcodeNameError)
				m.Authoritative = true
				return m
			}
			return reverseAnswer(cfg, req, p.Addr(), q.Qtype)
		case cfg.RouteAddr == nil:
		case full:
			route = cfg.RouteAddr(p.Addr())
		default:
			route = Route{Kind: RouteBlock} // a reverse zone, not an address: no rule says where
		}
	} else if cfg.Route != nil {
		route = cfg.Route(name)
	}
	var servers []netip.AddrPort
	var control func(string, string, syscall.RawConn) error
	switch route.Kind {
	case RouteDirect:
		s.n.direct.Add(1)
		servers, control = *s.upstreams.Load(), s.opts.Control
	case RouteTunnel:
		s.n.tunnel.Add(1)
		for _, a := range route.Via {
			servers = append(servers, netip.AddrPortFrom(a, s.opts.TunnelPort))
		}
		control = s.opts.TunnelControl
	default:
		s.n.blocked.Add(1)
		return reply(req, dns.RcodeServerFailure)
	}

	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	key := cacheKey{name: name, qtype: q.Qtype, qclass: q.Qclass, do: do, cd: req.CheckingDisabled, route: routeKey(route)}
	if m, ok := s.cache.get(key, time.Now()); ok {
		s.n.cacheHits.Add(1)
		return m
	}

	if !s.takeClient(src) {
		s.n.failed.Add(1)
		return reply(req, dns.RcodeServerFailure)
	}
	defer s.releaseClient(src)
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.n.failed.Add(1)
		return reply(req, dns.RcodeServerFailure)
	}
	out := new(dns.Msg)
	out.Id = dns.Id()
	out.RecursionDesired = true
	out.CheckingDisabled = req.CheckingDisabled
	out.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: q.Qtype, Qclass: q.Qclass}}
	// Only our own EDNS record: none of the client's options (its subnet,
	// cookies) travel upstream.
	out.SetEdns0(upstreamUDPSize, do)
	resp := s.exchange(out, servers, control)
	if resp == nil || resp.Rcode == dns.RcodeServerFailure {
		s.n.failed.Add(1)
		return reply(req, dns.RcodeServerFailure)
	}
	s.cache.put(key, resp, time.Now())
	return resp
}

// exchange asks each server in turn until one answers with something
// other than a failure, over UDP, and over TCP when the answer is
// truncated. Nil if none answered.
func (s *Server) exchange(m *dns.Msg, servers []netip.AddrPort, control func(string, string, syscall.RawConn) error) *dns.Msg {
	var last *dns.Msg
	for _, srv := range servers {
		c := &dns.Client{Net: "udp", Timeout: s.opts.Timeout, UDPSize: upstreamUDPSize, Dialer: &net.Dialer{Timeout: s.opts.Timeout, Control: control}}
		r, _, err := c.Exchange(m, srv.String())
		if err == nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.Exchange(m, srv.String())
		}
		if err != nil {
			continue
		}
		if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
			last = r
			continue
		}
		return r
	}
	if last != nil {
		last = last.Copy()
		last.Rcode = dns.RcodeServerFailure
	}
	return last
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	return m
}

// fit makes resp the answer to req: its id and question as the client
// wrote them, EDNS only if the client spoke it, and over UDP no larger
// than the client takes.
func fit(resp, req *dns.Msg, udp bool) {
	resp.Id = req.Id
	resp.Compress = true
	resp.Response = true
	resp.RecursionDesired = req.RecursionDesired
	resp.Question = req.Question
	reqOpt := req.IsEdns0()
	resp.Extra = slices.DeleteFunc(resp.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeOPT })
	if reqOpt != nil {
		opt := new(dns.OPT)
		opt.Hdr.Name, opt.Hdr.Rrtype = ".", dns.TypeOPT
		opt.SetUDPSize(upstreamUDPSize)
		opt.SetDo(reqOpt.Do())
		resp.Extra = append(resp.Extra, opt)
	}
	if !udp {
		return
	}
	size := dns.MinMsgSize
	if reqOpt != nil {
		size = max(dns.MinMsgSize, min(int(reqOpt.UDPSize()), upstreamUDPSize))
	}
	resp.Truncate(size)
}

func overlayAnswer(cfg *Config, req *dns.Msg, name string, qtype uint16) *dns.Msg {
	m := reply(req, dns.RcodeSuccess)
	m.Authoritative = true
	if cfg.Zone == "" {
		m.Rcode = dns.RcodeNameError
		return m
	}
	if name == cfg.Zone {
		return m
	}
	label, ok := strings.CutSuffix(name, "."+cfg.Zone)
	addrs, known := cfg.Names[label]
	if !ok || !known {
		m.Rcode = dns.RcodeNameError
		return m
	}
	for _, a := range addrs {
		hdr := dns.RR_Header{Name: req.Question[0].Name, Class: dns.ClassINET, Ttl: overlayTTL}
		switch {
		case a.Is4() && (qtype == dns.TypeA || qtype == dns.TypeANY):
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: a.AsSlice()})
		case a.Is6() && (qtype == dns.TypeAAAA || qtype == dns.TypeANY):
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()})
		}
	}
	return m
}

func reverseAnswer(cfg *Config, req *dns.Msg, a netip.Addr, qtype uint16) *dns.Msg {
	m := reply(req, dns.RcodeNameError)
	m.Authoritative = true
	if cfg.Zone == "" {
		return m
	}
	for label, addrs := range cfg.Names {
		if !slices.Contains(addrs, a) {
			continue
		}
		m.Rcode = dns.RcodeSuccess
		if qtype == dns.TypePTR || qtype == dns.TypeANY {
			hdr := dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: overlayTTL}
			m.Answer = append(m.Answer, &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(label + "." + cfg.Zone)})
		}
		break
	}
	return m
}

// reversePrefix reads a reverse name (labels of in-addr.arpa or
// ip6.arpa, lowercase) as the prefix it stands for, and whether that is a
// whole address. Not ok for any other name.
func reversePrefix(labels []string) (p netip.Prefix, full, ok bool) {
	n := len(labels)
	switch {
	case n >= 2 && labels[n-1] == "arpa" && labels[n-2] == "in-addr":
		octets := labels[:n-2]
		if len(octets) > 4 {
			return p, false, false
		}
		var b [4]byte
		for i, o := range octets {
			v, err := strconv.ParseUint(o, 10, 8)
			if err != nil || len(o) > 1 && o[0] == '0' {
				return p, false, false
			}
			b[len(octets)-1-i] = byte(v)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(octets)), len(octets) == 4, true
	case n >= 2 && labels[n-1] == "arpa" && labels[n-2] == "ip6":
		nibbles := labels[:n-2]
		if len(nibbles) > 32 {
			return p, false, false
		}
		var b [16]byte
		for i, nb := range nibbles {
			v, err := strconv.ParseUint(nb, 16, 4)
			if err != nil || len(nb) != 1 {
				return p, false, false
			}
			j := len(nibbles) - 1 - i
			b[j/2] |= byte(v) << (4 * (1 - j%2))
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), 4*len(nibbles)), len(nibbles) == 32, true
	}
	return p, false, false
}

func routeKey(r Route) string {
	if r.Kind != RouteTunnel {
		return strconv.Itoa(int(r.Kind))
	}
	var b strings.Builder
	b.WriteString("t")
	for _, a := range r.Via {
		b.WriteString(" " + a.String())
	}
	return b.String()
}
