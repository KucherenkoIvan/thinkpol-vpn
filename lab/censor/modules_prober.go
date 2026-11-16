package censor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
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
// connection to one of them once its client has sent data. The prober's
// own passive half tags each, and the active half probes only what it
// tagged: a suspect module has to let the flow through (fully-encrypted's
// tagOnly), and the prober sees its tag on the same packet when it comes
// after it in the config, on the flow's next packet otherwise. A TCP
// suspect is tagged once its client's first bytes are settled: a whole
// ClientHello (one with a post-quantum key share spans two segments),
// bytes that can't start one, or retainBytes of one still unfinished, so
// the replay probe and the TLS comparison have the whole hello. A UDP
// suspect is flagged Accept, "not probed": the prober probes TCP servers;
// so is a suspect connection to the reference itself.
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
// that probe; every probe counted, at least two, is the tell. The servers
// of one address are probed one at a time, so another service of the
// entry's that connects to the site isn't counted for this one's probes.
// A connection to the site an entry's real clients cause during a probe
// would still be, so the prober compares rates: the host's connections to
// the site during its probes, per second of probing, against those that
// started outside any probe of the host, per second, over the time the
// prober has watched (since it started, at most upstreamKeep). When the
// rate outside is at least half the rate during the probes, over a
// baseline at least as long as the probing, the probes didn't clearly
// cause the connections, and the tell is unattributable, reported as such
// and never flagged; a shorter baseline leaves the tell standing, and its
// verdict says the baseline was short. Addresses the hosts setting names as
// one host (at least two addresses each) count as one address for all of
// it: an entry probed over IPv6 that dials an IPv4-only site from its IPv4
// address shows the tell, as it does to a censor that knows both
// addresses are one machine. With upstreamTell "report" the tell is
// reported in the verdict and doesn't flag the server.
type prober struct {
	refName string
	refs    []netip.AddrPort
	dests   []netip.Prefix
	// suspects are the modules whose tags make a flow suspect.
	suspects []string
	// reportTell: the upstream tell is reported, not flagged.
	reportTell bool
	timeout    time.Duration
	block      blocking
	random     [][]byte
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	blocked    blockedServers
	grace      time.Duration // upstreamGrace; tests shorten it

	mu      sync.Mutex
	servers map[netip.AddrPort]*probedServer
	// probing serializes the probing of the servers of one host, so one's
	// upstream connections are never counted for another's probes.
	probing map[netip.Addr]*sync.Mutex
	// hostOf maps each address the hosts setting lists to its host's first
	// address; any other address is a host of its own.
	hostOf map[netip.Addr]netip.Addr
	// upstream holds the recent connections to a reference address the
	// censor saw, for the upstream tell; windows holds each host's recent
	// probes, from start to grace after the end, for its baseline;
	// started is when the prober began watching.
	upstream []upstreamConn
	windows  map[netip.Addr][]probeWindow
	started  time.Time
}

// probeWindow is when a probe's upstream connections count for it.
type probeWindow struct{ from, to time.Time }

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
// still counts for it.
const upstreamGrace = 500 * time.Millisecond

// upstreamKeep is how long the prober remembers a connection to the
// reference and a probe's window: longer than a host's probing, and the
// longest baseline the upstream tell compares with.
const upstreamKeep = time.Minute

// newProber builds the module from its settings:
//
//	{"reference": {"name": "camouflage.example.net",
//	               "addresses": ["198.51.100.10:443", "[2001:db8::10]:443"]},
//	 "destinations": ["192.0.2.0/24"], "suspects": ["fully-encrypted"],
//	 "timeout": "2s", "upstreamTell": "flag",
//	 "hosts": [["192.0.2.9", "2001:db8::9"]]}
//
// with blockSettings' verdict (drop by default), rate and burst. The
// reference is required; destinations are optional; suspects default to
// fully-encrypted; timeout is how long a probe waits for the server to
// answer or close (2 s by default); upstreamTell is "flag" (the default:
// the tell alone flags a server) or "report" (the verdict says so, and
// only the probes' answers flag it); hosts lists the addresses that are one
// machine, each address in one host at most.
func newProber(settings json.RawMessage) (Passive, error) {
	var s struct {
		Reference struct {
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
		} `json:"reference"`
		Destinations []string   `json:"destinations"`
		Suspects     []string   `json:"suspects"`
		Timeout      string     `json:"timeout"`
		UpstreamTell string     `json:"upstreamTell"`
		Hosts        [][]string `json:"hosts"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	m := &prober{refName: s.Reference.Name, suspects: s.Suspects, servers: map[netip.AddrPort]*probedServer{},
		probing: map[netip.Addr]*sync.Mutex{}, hostOf: map[netip.Addr]netip.Addr{}, windows: map[netip.Addr][]probeWindow{}, grace: upstreamGrace}
	for _, host := range s.Hosts {
		if len(host) < 2 {
			return nil, fmt.Errorf("host %q: want at least two addresses, one host's", host)
		}
		for _, a := range host {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, fmt.Errorf("host address %q: %w", a, err)
			}
			if _, dup := m.hostOf[addr]; dup {
				return nil, fmt.Errorf("host address %s: listed twice", addr)
			}
			m.hostOf[addr] = netip.MustParseAddr(host[0])
		}
	}
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
	if m.suspects == nil {
		m.suspects = []string{"fully-encrypted"}
	}
	switch s.UpstreamTell {
	case "", "flag":
	case "report":
		m.reportTell = true
	default:
		return nil, fmt.Errorf("upstreamTell %q: want flag or report", s.UpstreamTell)
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
	if f.TaggedBy(m.Name()) {
		return Decision{Verdict: Accept}
	}
	why := m.suspicion(f)
	if why == "" || f.Stream != nil && !helloSettled(f.Stream.Prefix()) {
		return Decision{Verdict: Accept}
	}
	return Decision{Verdict: Accept, Tag: why}
}

// suspicion says why a flow is suspect, "" when it isn't.
func (m *prober) suspicion(f *Flow) string {
	for _, n := range m.suspects {
		if f.TaggedBy(n) {
			return "tagged by " + n
		}
	}
	if len(m.dests) > 0 && f.Stream != nil && f.Initiator() && contains(m.dests, f.Key.Dst) && len(f.Stream.Prefix()) > 0 {
		return "a connection to a listed destination sent data"
	}
	return ""
}

// helloSettled says whether a client's first bytes are all the prober
// waits for: a whole ClientHello, bytes that can't start one, or
// retainBytes of one still unfinished.
func helloSettled(b []byte) bool {
	if len(b) >= retainBytes {
		return true
	}
	if len(b) < tlsRecordHeader {
		return len(b) > 0 && b[0] != tlsHandshake || len(b) > 1 && b[1] != 3 || len(b) > 2 && b[2] > 4
	}
	_, err := clientHelloServerName(b)
	return !errors.Is(err, errIncomplete)
}

func (m *prober) Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc) {
	m.mu.Lock()
	if m.started.IsZero() { // tests may start the baseline earlier
		m.started = time.Now()
	}
	m.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			switch f.Tagger {
			case "":
				m.noteUpstream(f)
			case m.Name():
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

// host is the host addr is an address of, by its first address.
func (m *prober) host(addr netip.Addr) netip.Addr {
	if h, ok := m.hostOf[addr]; ok {
		return h
	}
	return addr
}

// sawUpstream counts the connections from src's host to the reference
// starting within [from, to].
func (m *prober) sawUpstream(src netip.Addr, from, to time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, u := range m.upstream {
		if m.host(u.src) == m.host(src) && !u.at.Before(from) && !u.at.After(to) {
			n++
		}
	}
	return n
}

// probed notes a probe of a server of src's host, its connections
// counting from from to to.
func (m *prober) probed(src netip.Addr, from, to time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.host(src)
	keep := m.windows[h][:0]
	for _, w := range m.windows[h] {
		if to.Sub(w.to) < upstreamKeep {
			keep = append(keep, w)
		}
	}
	m.windows[h] = append(keep, probeWindow{from, to})
}

// baseline counts the connections from src's host to the reference that
// started outside every probe of the host, since the prober started (at
// most upstreamKeep before now), and how long that was.
func (m *prober) baseline(src netip.Addr, now time.Time) (int, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.host(src)
	from := m.started
	if now.Sub(from) > upstreamKeep {
		from = now.Add(-upstreamKeep)
	}
	outside := now.Sub(from)
	for _, w := range m.windows[h] {
		lo, hi := w.from, w.to
		if lo.Before(from) {
			lo = from
		}
		if hi.After(now) {
			hi = now
		}
		if hi.After(lo) {
			outside -= hi.Sub(lo)
		}
	}
	n := 0
	for _, u := range m.upstream {
		if m.host(u.src) != h || u.at.Before(from) || u.at.After(now) {
			continue
		}
		if !slices.ContainsFunc(m.windows[h], func(w probeWindow) bool { return !u.at.Before(w.from) && !u.at.After(w.to) }) {
			n++
		}
	}
	return n, max(outside, 0)
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
		flag(f.Key, Accept, "not probed: the reference itself")
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
	host, ok := m.probing[m.host(server.Addr())]
	if !ok {
		host = &sync.Mutex{}
		m.probing[m.host(server.Addr())] = host
	}
	m.mu.Unlock()
	go func() {
		host.Lock()
		verdict, why := m.examine(ctx, server, f.Payload)
		host.Unlock()
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
	var tally upstreamTally
	// counted credits the probe that started at from with its connections
	// to the reference, those starting by grace after it ended.
	counted := func(from time.Time) {
		end := time.Now().Add(m.grace)
		sleep(ctx, m.grace)
		n := m.sawUpstream(server.Addr(), from, end)
		if n > 0 {
			tally.probes++
		}
		tally.during += n
		tally.probing += end.Sub(from)
		m.probed(server.Addr(), from, end)
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
	tally.total = len(probes)
	name, err := clientHelloServerName(first)
	if err == nil && canonicalName(name) == canonicalName(m.refName) {
		start := time.Now()
		var got, want handshakeResult
		both(func() { got = m.handshake(ctx, server) }, func() { want = m.handshake(ctx, ref) })
		counted(start)
		tally.total++
		report = append(report, fmt.Sprintf("TLS: the server %s; the reference %s", got, want))
		if d := got.differences(want); len(d) > 0 {
			diffs = append(diffs, "TLS: "+strings.Join(d, "; "))
		}
	} else {
		report = append(report, "TLS: not compared, "+notCompared(name, err, len(first)))
	}
	tally.between, tally.outside = m.baseline(server.Addr(), time.Now())
	if r, d := m.upstreamTell(server.Addr(), tally); d != "" {
		diffs = append(diffs, d)
	} else {
		report = append(report, r)
	}
	if len(diffs) == 0 {
		return Accept, fmt.Sprintf("server %s answers like the reference %s: %s", server, ref, strings.Join(report, "; "))
	}
	return m.block.verdict, fmt.Sprintf("server %s unlike the reference %s: %s", server, ref, strings.Join(diffs, "; "))
}

// notCompared says why a suspect whose first bytes (kept of them) named
// name, or failed to with err, gets no TLS comparison.
func notCompared(name string, err error, kept int) string {
	switch {
	case err == nil:
		return fmt.Sprintf("the ClientHello names %q, not the reference", name)
	case errors.Is(err, errIncomplete):
		return fmt.Sprintf("the ClientHello is incomplete in the %d bytes kept", kept)
	case errors.Is(err, errHelloTooLong):
		return fmt.Sprintf("the ClientHello is longer than the %d bytes the censor keeps", retainBytes)
	}
	return "the connection doesn't start with a ClientHello"
}

// upstreamTally is what a server's probing saw of its host's connections
// to the reference: during probes of total, during in all over probing,
// and between more outside any probe of the host over outside.
type upstreamTally struct {
	probes, total, during int
	probing               time.Duration
	between               int
	outside               time.Duration
}

// unattributable says whether the host connects to the reference outside
// its probes at least half as often as during them: then the probes
// didn't clearly cause the connections, which may be the host's own. A
// baseline shorter than the probing is too little evidence for that: the
// censor starts right before the first probe, so an entry's dial for the
// very client the censor suspects lands in a baseline of a second or two.
func (u upstreamTally) unattributable() bool {
	// between/outside >= during/probing / 2, in integers.
	return !u.shortBaseline() && u.between > 0 && 2*int64(u.between)*int64(u.probing) >= int64(u.during)*int64(u.outside)
}

// shortBaseline says whether the prober watched the host outside its
// probes for less time than it probed.
func (u upstreamTally) shortBaseline() bool { return u.outside < u.probing }

// upstreamTell judges the connections from server's host to the
// reference: a line for the report, or a difference when the tell flags.
func (m *prober) upstreamTell(server netip.Addr, u upstreamTally) (report, diff string) {
	from := server.String()
	if _, ok := m.hostOf[server]; ok {
		from += " or another address of its host"
	}
	base := fmt.Sprintf("%d dials in %s of probes, %d in %s outside them", u.during, u.probing.Round(time.Millisecond), u.between, u.outside.Round(time.Millisecond))
	if u.shortBaseline() {
		base += ", a baseline shorter than the probing, too short to call the tell unattributable"
	}
	tell := fmt.Sprintf("upstream tell: a connection from %s to the reference during every probe (%d of %d; %s)", from, u.probes, u.total, base)
	switch {
	case u.total < 2 || u.probes < u.total:
		return fmt.Sprintf("connections to the reference during %d of %d probes", u.probes, u.total), ""
	case u.unattributable():
		return fmt.Sprintf("upstream tell: unattributable (%s, at least half the rate; a connection from %s to the reference during %d of %d probes)", base, from, u.probes, u.total), ""
	case m.reportTell:
		return tell + ", reported, not flagged", ""
	}
	return "", tell
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
