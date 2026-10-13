package dns

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// errNotAnAnswer is a datagram from the server asked that doesn't answer
// the query (another ID or question, garbage, too big): someone may be
// guessing at the query to answer it first, so the query is asked again
// over TCP.
var errNotAnAnswer = errors.New("dns: a datagram from the upstream that doesn't answer the query")

// exchangeWith asks one server: over UDP, and over TCP when the UDP
// answer is truncated or the query's socket got something that isn't its
// answer. Each try has an ID of its own.
func exchangeWith(m *dns.Msg, srv netip.AddrPort, control func(string, string, syscall.RawConn) error, timeout time.Duration) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = dns.Id()
	r, err := exchangeUDP(q, srv, control, timeout)
	if errors.Is(err, errNotAnAnswer) || err == nil && r.Truncated {
		q.Id = dns.Id()
		c := &dns.Client{Net: "tcp", Timeout: timeout, Dialer: &net.Dialer{Timeout: timeout, Control: control}}
		r, _, err = c.Exchange(q, srv.String())
		if err == nil && !isAnswerTo(r, q) {
			err = errNotAnAnswer
		}
	}
	return r, err
}

// exchangeUDP sends q to srv from a socket of its own, connected to srv,
// and reads the answer from it. A connected socket only receives what
// comes from srv's address and port (the kernel drops the rest), and its
// source port is the kernel's pick from the ephemeral range, fresh for
// each query; the source check below says the same thing again.
func exchangeUDP(q *dns.Msg, srv netip.AddrPort, control func(string, string, syscall.RawConn) error, timeout time.Duration) (*dns.Msg, error) {
	out, err := q.Pack()
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout, Control: control}
	nc, err := d.Dial("udp", srv.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = nc.Close() }()
	c, ok := nc.(*net.UDPConn)
	if !ok {
		return nil, errors.New("dns: not a UDP socket")
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	// One byte more than we asked the server to keep to: a bigger
	// datagram doesn't fit and is no answer.
	buf := make([]byte, upstreamUDPSize+1)
	// Without the zone: a link-local server written with a numeric zone
	// (fe80::1%2, as resolved writes it) comes back named (%eth0).
	want := noZone(srv)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if isMessageSize(err) {
			// Windows: a datagram bigger than buf (the socket is
			// connected, so it came from srv).
			return nil, errNotAnAnswer
		}
		if err != nil {
			return nil, err
		}
		if noZone(from) != want {
			continue
		}
		r := new(dns.Msg)
		if n > upstreamUDPSize || r.Unpack(buf[:n]) != nil {
			return nil, errNotAnAnswer
		}
		// The ID and question check, and the window it leaves. The
		// socket is fresh and connected, so an attacker off the path to
		// srv must spoof srv's address and port and hit our source port
		// (the kernel's ephemeral pick: about 15 bits on Linux) to reach
		// it at all; the first datagram that does with a wrong ID or
		// question ends the UDP try and the query goes over TCP. So a
		// flood buys one ID guess per query, at 1 in 65536 (the ID is
		// crypto/rand), and it must land before srv's answer. An
		// attacker on the path sees port and ID and can still answer
		// first: plain DNS has no defense against that, only DoT or
		// DNSSEC validation would. A tunnel-bound query is asked
		// inside the tunnel, so that is a direct query's exposure.
		if !isAnswerTo(r, q) {
			return nil, errNotAnAnswer
		}
		return r, nil
	}
}

func noZone(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap().WithZone(""), a.Port())
}

// isAnswerTo reports whether r is a response to q: same ID, opcode and
// question. Only a failure may leave the question out (some servers do);
// an answer or a name error must carry it.
func isAnswerTo(r, q *dns.Msg) bool {
	if !r.Response || r.Id != q.Id || r.Opcode != q.Opcode {
		return false
	}
	if len(r.Question) == 0 {
		return r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError
	}
	a, b := r.Question[0], q.Question[0]
	return len(r.Question) == 1 && strings.EqualFold(a.Name, b.Name) && a.Qtype == b.Qtype && a.Qclass == b.Qclass
}
