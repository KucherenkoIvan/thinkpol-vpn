package censor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

func init() {
	RegisterPassive("prober", newProber)
}

// prober is the active prober (Alice et al., "How China Detects and
// Blocks Shadowsocks", IMC 2020; Frolov et al., "Detecting Probe-resistant
// Proxies", NDSS 2020): given a suspect TCP connection, it connects to the
// connection's server from the censor, as a client of its own, and
// compares how the server answers with how the reference, the real site
// an entry pretends to be, answers the same bytes. Each server, by address
// and port, is probed once; a server found out is blocked, every
// connection to or from it, from then on.
//
// Suspects are the flows the modules named in suspects tag (the passive
// fully-encrypted module by default) and, with destinations set, every TCP
// connection to one of them once its client has sent data (the prober's
// own passive half tags those). A UDP suspect is flagged Accept, "not
// probed": the prober probes TCP servers.
//
// Probes, each on a connection of its own, each sent to the server and the
// reference alike:
//
//   - replay: the bytes the suspect connection's client sent first (the
//     censor's retained prefix);
//   - random: random bytes of 3, 16, 49, 221 and 1000 bytes, the same for
//     every server;
//   - a TLS handshake of the censor's own, crypto/tls with the reference's
//     server name and ALPN h2 and http/1.1, only when the suspect's
//     ClientHello named the reference: the server hello's JA3S, JA4S,
//     extensions in order and ALPN (negotiated, which TLS 1.3 encrypts)
//     against the reference's.
//
// A reaction is what came back (nothing, an echo of the probe, a TLS
// alert or handshake, an HTTP response, other bytes) and how the
// connection ended (closed, reset, or still open after the timeout:
// closing after N bytes shows as an end that changes with the probe's
// length). A server is flagged when a reaction differs from the
// reference's, its TLS handshake differs, or it shows the upstream tell.
//
// The upstream tell: an entry that relays what it doesn't recognize to the
// real site (REALITY does, on every connection) opens a connection of its
// own to the site for each probe. The censor sees it only from a vantage
// on the entry's uplink: in the lab, the camouflage target sits behind the
// router (lab.Upstream) and the entry's connection to it crosses the
// censor. A new connection from the probed address to a reference address
// starting during a probe, or within upstreamGrace after it, counts for
// that probe; every probe counted, at least two, is the tell.
type prober struct {
	refName string
	refs    []netip.AddrPort
	dests   []netip.Prefix
	// suspects are the modules whose tags make a flow suspect.
	suspects map[string]bool
	timeout  time.Duration
	block    blocking
	random   [][]byte
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	blocked  blockedServers
	grace    time.Duration // upstreamGrace; tests shorten it

	mu      sync.Mutex
	servers map[netip.AddrPort]*probedServer
	// upstream holds the recent connections to a reference address the
	// censor saw, for the upstream tell.
	upstream []upstreamConn
}

// probedServer is one server's probing: once done, its verdict, and
// meanwhile the suspect flows waiting for it.
type probedServer struct {
	done    bool
	verdict Verdict
	why     string
	waiting []FlowKey
}

type upstreamConn struct {
	src netip.Addr
	at  time.Time
}

// randomProbeSizes are the random probes' lengths: below a TLS record
// header, and around lengths the Great Firewall's Shadowsocks probes used.
var randomProbeSizes = []int{3, 16, 49, 221, 1000}

// upstreamGrace is how long after a probe ends an upstream connection
// still counts for it, and how long the prober waits between probes.
const upstreamGrace = 500 * time.Millisecond

// upstreamKeep is how long the prober remembers a connection to the
// reference: longer than a probe.
const upstreamKeep = time.Minute

// newProber builds the module from its settings:
//
//	{"reference": {"name": "camouflage.example.net",
//	               "addresses": ["198.51.100.10:443", "[2001:db8::10]:443"]},
//	 "destinations": ["192.0.2.0/24"], "suspects": ["fully-encrypted"],
//	 "timeout": "2s"}
//
// with blockSettings' verdict (drop by default), rate and burst. The
// reference is required; destinations are optional; suspects default to
// fully-encrypted; timeout is how long a probe waits for the server to
// answer or close (2 s by default).
func newProber(settings json.RawMessage) (Passive, error) {
	var s struct {
		Reference struct {
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
		} `json:"reference"`
		Destinations []string `json:"destinations"`
		Suspects     []string `json:"suspects"`
		Timeout      string   `json:"timeout"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	m := &prober{refName: s.Reference.Name, suspects: map[string]bool{}, servers: map[netip.AddrPort]*probedServer{}, grace: upstreamGrace}
	for _, a := range s.Reference.Addresses {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			return nil, fmt.Errorf("reference address %q: %w", a, err)
		}
		m.refs = append(m.refs, ap)
	}
	if len(m.refs) == 0 || m.refName == "" {
		return nil, errors.New("reference: want a name and at least one address")
	}
	if len(s.Destinations) > 0 {
		var err error
		if m.dests, err = parsePrefixes("destination", s.Destinations); err != nil {
			return nil, err
		}
	}
	if s.Suspects == nil {
		s.Suspects = []string{"fully-encrypted"}
	}
	for _, n := range s.Suspects {
		m.suspects[n] = true
	}
	var err error
	if m.timeout, err = parseTimeout(s.Timeout, 2*time.Second); err != nil {
		return nil, err
	}
	if m.block, err = s.parse(Drop); err != nil {
		return nil, err
	}
	for _, n := range randomProbeSizes {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		m.random = append(m.random, b)
	}
	d := &net.Dialer{Timeout: m.timeout}
	m.dial = d.DialContext
	return m, nil
}

func (m *prober) Name() string { return "prober" }

func (m *prober) Inspect(_ *Packet, f *Flow) Decision {
	if why, ok := m.blocked.of(f.Key); ok {
		return m.block.decide(why)
	}
	if len(m.dests) == 0 || f.Stream == nil || !f.Initiator() || !contains(m.dests, f.Key.Dst) || len(f.Stream.Prefix()) == 0 {
		return Decision{Verdict: Accept}
	}
	return Decision{Verdict: Accept, Tag: "a connection to a listed destination sent data"}
}

func (m *prober) Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			switch {
			case f.Tagger == "":
				m.noteUpstream(f)
			case f.Tagger == m.Name() || m.suspects[f.Tagger]:
				m.suspect(ctx, f, flag)
			}
		}
	}
}

// noteUpstream remembers a new connection to a reference address.
func (m *prober) noteUpstream(f FlowSnapshot) {
	if f.Key.Proto != ProtoTCP || !m.isReference(netip.AddrPortFrom(f.Key.Dst, f.Key.DstPort)) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := m.upstream[:0]
	for _, u := range m.upstream {
		if f.Started.Sub(u.at) < upstreamKeep {
			keep = append(keep, u)
		}
	}
	m.upstream = append(keep, upstreamConn{src: f.Key.Src, at: f.Started})
}

func (m *prober) isReference(a netip.AddrPort) bool {
	for _, r := range m.refs {
		if r == a {
			return true
		}
	}
	return false
}

// sawUpstream reports a connection from src to the reference starting
// within [from, to].
func (m *prober) sawUpstream(src netip.Addr, from, to time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.upstream {
		if u.src == src && !u.at.Before(from) && !u.at.After(to) {
			return true
		}
	}
	return false
}

// suspect probes the flow's server, once per server: a flow of a server
// probed already gets its verdict, one being probed waits for it.
func (m *prober) suspect(ctx context.Context, f FlowSnapshot, flag FlagFunc) {
	if f.Key.Proto != ProtoTCP {
		flag(f.Key, Accept, "not probed: the prober probes TCP servers")
		return
	}
	server := netip.AddrPortFrom(f.Key.Dst, f.Key.DstPort)
	if m.isReference(server) {
		return
	}
	m.mu.Lock()
	s, ok := m.servers[server]
	switch {
	case ok && s.done:
		m.mu.Unlock()
		m.flagConn(flag, f.Key, s.verdict, s.why)
		return
	case ok:
		s.waiting = append(s.waiting, f.Key)
		m.mu.Unlock()
		return
	}
	s = &probedServer{waiting: []FlowKey{f.Key}}
	m.servers[server] = s
	m.mu.Unlock()
	go func() {
		verdict, why := m.examine(ctx, server, f.Payload)
		if ctx.Err() != nil {
			return
		}
		if verdict != Accept {
			m.blocked.add(server, why)
		}
		m.mu.Lock()
		s.done, s.verdict, s.why = true, verdict, why
		waiting := s.waiting
		s.waiting = nil
		m.mu.Unlock()
		for _, k := range waiting {
			m.flagConn(flag, k, verdict, why)
		}
	}()
}

// flagConn flags a suspect connection with its server's verdict: a block
// both ways, an Accept on the suspect flow alone (for the verdict log).
func (m *prober) flagConn(flag FlagFunc, k FlowKey, v Verdict, why string) {
	flag(k, v, why)
	if v != Accept {
		flag(k.Reverse(), v, why)
	}
}

// examine probes server and the reference, and returns the server's
// verdict and why, which lists every probe either way.
func (m *prober) examine(ctx context.Context, server netip.AddrPort, first []byte) (Verdict, string) {
	ref := m.referenceFor(server.Addr())
	type probe struct {
		name    string
		payload []byte
	}
	var probes []probe
	if len(first) > 0 {
		probes = append(probes, probe{"replay", first})
	}
	for _, b := range m.random {
		probes = append(probes, probe{fmt.Sprintf("random %d", len(b)), b})
	}
	var diffs, report []string
	upstream := 0
	counted := func(from time.Time) {
		end := time.Now()
		sleep(ctx, m.grace)
		if m.sawUpstream(server.Addr(), from, end.Add(m.grace)) {
			upstream++
		}
	}
	for _, p := range probes {
		start := time.Now()
		var got, want reaction
		both(func() { got = m.react(ctx, server, p.payload) }, func() { want = m.react(ctx, ref, p.payload) })
		counted(start)
		if ctx.Err() != nil {
			return Accept, "stopped"
		}
		report = append(report, fmt.Sprintf("%s: %s", p.name, got))
		if !got.like(want) {
			diffs = append(diffs, fmt.Sprintf("%s: the server %s, the reference %s", p.name, got, want))
		}
	}
	total := len(probes)
	if name, err := clientHelloServerName(first); err == nil && canonicalName(name) == canonicalName(m.refName) {
		start := time.Now()
		var got, want handshakeResult
		both(func() { got = m.handshake(ctx, server) }, func() { want = m.handshake(ctx, ref) })
		counted(start)
		total++
		report = append(report, fmt.Sprintf("TLS: the server %s; the reference %s", got, want))
		if d := got.differences(want); len(d) > 0 {
			diffs = append(diffs, "TLS: "+strings.Join(d, "; "))
		}
	} else {
		report = append(report, "TLS: not compared, the connection doesn't name the reference")
	}
	if total >= 2 && upstream == total {
		diffs = append(diffs, fmt.Sprintf("upstream tell: a connection from %s to the reference during every probe (%d of %d)", server.Addr(), upstream, total))
	} else {
		report = append(report, fmt.Sprintf("connections to the reference during %d of %d probes", upstream, total))
	}
	if len(diffs) == 0 {
		return Accept, fmt.Sprintf("server %s answers like the reference %s: %s", server, ref, strings.Join(report, "; "))
	}
	return m.block.verdict, fmt.Sprintf("server %s unlike the reference %s: %s", server, ref, strings.Join(diffs, "; "))
}

// referenceFor picks a reference address of addr's family, if any.
func (m *prober) referenceFor(addr netip.Addr) netip.AddrPort {
	for _, r := range m.refs {
		if r.Addr().Is4() == addr.Is4() {
			return r
		}
	}
	return m.refs[0]
}

// both runs a and b at once and returns when both have.
func both(a, b func()) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a()
	}()
	b()
	wg.Wait()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// reaction is how a server answered one probe.
type reaction struct {
	// answer is the kind of bytes it sent back (see answerKind), end how
	// the connection ended: "closed", "reset", "open" (the probe's
	// timeout passed), or "no connection".
	answer, end string
	// read counts the bytes answered; first is when the first came, from
	// the dial on. Neither is compared: they are for the report.
	read  int
	first time.Duration
}

func (r reaction) like(o reaction) bool { return r.answer == o.answer && r.end == o.end }

func (r reaction) String() string {
	if r.read == 0 {
		return fmt.Sprintf("answered nothing, %s", r.end)
	}
	return fmt.Sprintf("answered %s (%d bytes, first after %s), %s", r.answer, r.read, r.first.Round(time.Millisecond/10), r.end)
}

// react sends one probe on a connection of its own and watches the
// answer until the server closes or resets it, or the timeout passes.
func (m *prober) react(ctx context.Context, addr netip.AddrPort, payload []byte) reaction {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	start := time.Now()
	c, err := m.dial(ctx, "tcp", addr.String())
	if err != nil {
		return reaction{answer: "nothing", end: "no connection"}
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	var r reaction
	if _, err := c.Write(payload); err != nil {
		r.end = connEnd(err)
	}
	var answer []byte
	buf := make([]byte, 4096)
	for r.end == "" {
		n, err := c.Read(buf)
		if n > 0 && r.read == 0 {
			r.first = time.Since(start)
		}
		r.read += n
		answer = append(answer, buf[:min(n, 64-min(64, len(answer)))]...)
		if err != nil {
			r.end = connEnd(err)
		}
	}
	r.answer = answerKind(answer, payload)
	return r
}

// connEnd names how a connection ended from the error that ended it.
func connEnd(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF):
		return "closed"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "open"
	}
	return "failed: " + err.Error()
}

// answerKind classifies the first bytes a server answered a probe with.
func answerKind(answer, probe []byte) string {
	switch {
	case len(answer) == 0:
		return "nothing"
	case len(answer) <= len(probe) && bytes.Equal(answer, probe[:len(answer)]):
		return "an echo"
	case len(answer) >= 2 && answer[0] == 0x15 && answer[1] == 3:
		return "a TLS alert"
	case len(answer) >= 2 && answer[0] == tlsHandshake && answer[1] == 3:
		return "a TLS handshake"
	case bytes.HasPrefix(answer, []byte("HTTP/")):
		return "an HTTP response"
	}
	return "other bytes"
}

// handshakeResult is the censor's own TLS handshake with a server.
type handshakeResult struct {
	hello    serverHello
	helloErr error
	// alpn is the protocol negotiated, read after the handshake: TLS 1.3
	// sends it encrypted.
	alpn string
	err  error
}

func (h handshakeResult) String() string {
	if h.helloErr != nil {
		return fmt.Sprintf("no ServerHello (%v)", h.helloErr)
	}
	s := fmt.Sprintf("%s, negotiated ALPN %q", h.hello, h.alpn)
	if h.err != nil {
		s += fmt.Sprintf(", handshake failed: %v", h.err)
	}
	return s
}

func (h handshakeResult) differences(want handshakeResult) []string {
	switch {
	case (h.helloErr == nil) != (want.helloErr == nil):
		return []string{fmt.Sprintf("the server %s, the reference %s", h, want)}
	case h.helloErr != nil:
		return nil
	}
	d := h.hello.differences(want.hello)
	if h.alpn != want.alpn {
		d = append(d, fmt.Sprintf("negotiated ALPN %q, the reference's %q", h.alpn, want.alpn))
	}
	if (h.err == nil) != (want.err == nil) {
		d = append(d, fmt.Sprintf("handshake error %v, the reference's %v", h.err, want.err))
	}
	return d
}

// handshake runs a TLS handshake of the censor's own with addr, naming
// the reference, and reads the server's hello from the bytes it sent.
func (m *prober) handshake(ctx context.Context, addr netip.AddrPort) handshakeResult {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	c, err := m.dial(ctx, "tcp", addr.String())
	if err != nil {
		return handshakeResult{helloErr: err}
	}
	defer func() { _ = c.Close() }()
	rec := &recordingConn{Conn: c}
	tc := tls.Client(rec, &tls.Config{
		ServerName: m.refName,
		NextProtos: []string{"h2", "http/1.1"},
		// The censor compares servers, it doesn't trust them.
		InsecureSkipVerify: true, //nolint:gosec // see above
		MinVersion:         tls.VersionTLS12,
	})
	err = tc.HandshakeContext(ctx)
	h := handshakeResult{err: err, alpn: tc.ConnectionState().NegotiatedProtocol}
	h.hello, h.helloErr = serverHelloOf(rec.read)
	return h
}

// recordingConn keeps the first retainBytes a connection read.
type recordingConn struct {
	net.Conn
	read []byte
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if room := retainBytes - len(c.read); room > 0 {
		c.read = append(c.read, b[:min(n, room)]...)
	}
	return n, err
}
