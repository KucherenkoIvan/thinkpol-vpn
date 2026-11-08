package censor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

func init() {
	RegisterPassive("server-hello", newServerHelloCheck)
}

// serverHelloCheck compares a server's hello with the real site's: on a
// TCP connection whose ClientHello names a listed site, the passive half
// reads the server's ServerHello (JA3S, JA4S, the extensions in order, the
// ALPN when the hello carries it) and tags the server's flow; the active
// half sends the same ClientHello, byte for byte, to the site's own
// address, reads its ServerHello and compares. A server whose hello
// differs from the site's answer to the same ClientHello isn't the site:
// the connection is flagged, both directions, and the server, by address
// and port, is blocked from then on. A match is flagged Accept, so the
// verdict log says what was compared either way.
type serverHelloCheck struct {
	// sites maps a server name to the site's address, standing in for the
	// DNS a real censor resolves the name with.
	sites   map[string]netip.AddrPort
	block   blocking
	timeout time.Duration
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	blocked blockedServers

	mu      sync.Mutex
	pending map[FlowKey]helloCompare
}

// helloCompare is what the passive half leaves the active half for one
// server flow.
type helloCompare struct {
	name        string
	site        netip.AddrPort
	clientHello []byte
	got         serverHello
}

// newServerHelloCheck builds the module from its settings:
//
//	{"sites": {"camouflage.example.net": "198.51.100.10:443"}, "timeout": "3s"}
//
// with blockSettings' verdict (drop by default), rate and burst; timeout
// bounds the wait for the site's hello (3 s by default).
func newServerHelloCheck(settings json.RawMessage) (Passive, error) {
	var s struct {
		Sites   map[string]string `json:"sites"`
		Timeout string            `json:"timeout"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	m := &serverHelloCheck{sites: map[string]netip.AddrPort{}, timeout: 3 * time.Second, pending: map[FlowKey]helloCompare{}}
	for name, addr := range s.Sites {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("site %s: %w", name, err)
		}
		m.sites[canonicalName(name)] = ap
	}
	if len(m.sites) == 0 {
		return nil, errors.New("no sites")
	}
	var err error
	if m.timeout, err = parseTimeout(s.Timeout, m.timeout); err != nil {
		return nil, err
	}
	if m.block, err = s.parse(Drop); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: m.timeout}
	m.dial = d.DialContext
	return m, nil
}

// parseTimeout reads a duration setting, def when "".
func parseTimeout(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("timeout %q: want a positive duration", s)
	}
	return d, nil
}

func (m *serverHelloCheck) Name() string { return "server-hello" }

func (m *serverHelloCheck) Inspect(_ *Packet, f *Flow) Decision {
	if why, ok := m.blocked.of(f.Key); ok {
		return m.block.decide(why)
	}
	c := f.Reverse()
	if f.Stream == nil || f.Initiator() || c == nil || !c.Initiator() {
		return Decision{Verdict: Accept}
	}
	name, err := clientHelloServerName(c.Stream.Prefix())
	switch {
	case errors.Is(err, errIncomplete):
		return Decision{Verdict: Accept}
	case err != nil:
		return retired
	}
	site, ok := m.sites[canonicalName(name)]
	if !ok {
		return retired
	}
	got, err := serverHelloOf(f.Stream.Prefix())
	switch {
	case errors.Is(err, errIncomplete) && len(f.Stream.Prefix()) < retainBytes:
		return Decision{Verdict: Accept}
	case err != nil:
		return retired
	}
	_, used, _ := helloMessage(c.Stream.Prefix(), tlsClientHello)
	m.mu.Lock()
	m.pending[f.Key] = helloCompare{name: name, site: site, clientHello: append([]byte(nil), c.Stream.Prefix()[:used]...), got: got}
	m.mu.Unlock()
	return Decision{Verdict: Accept, Flow: true, Tag: fmt.Sprintf("server hello for %s: %s", name, got)}
}

func (m *serverHelloCheck) Run(ctx context.Context, flows <-chan FlowSnapshot, flag FlagFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			if f.Tagger != m.Name() {
				continue
			}
			m.mu.Lock()
			cmp, ok := m.pending[f.Key]
			delete(m.pending, f.Key)
			m.mu.Unlock()
			if ok {
				go m.compare(ctx, f.Key, cmp, flag)
			}
		}
	}
}

// compare asks the site for its hello and flags the connection by how
// the server's compares.
func (m *serverHelloCheck) compare(ctx context.Context, key FlowKey, cmp helloCompare, flag FlagFunc) {
	want, err := m.siteHello(ctx, cmp)
	if err != nil {
		if ctx.Err() == nil {
			flag(key, Accept, fmt.Sprintf("not compared: the site %s for %s: %v", cmp.site, cmp.name, err))
		}
		return
	}
	diffs := cmp.got.differences(want)
	if len(diffs) == 0 {
		flag(key, Accept, fmt.Sprintf("server hello matches the site %s's for %s: %s", cmp.site, cmp.name, cmp.got))
		return
	}
	why := fmt.Sprintf("server hello unlike the site %s's for the same ClientHello for %s: %s; the server's %s, the site's %s",
		cmp.site, cmp.name, strings.Join(diffs, "; "), cmp.got, want)
	m.blocked.add(netip.AddrPortFrom(key.Src, key.SrcPort), why)
	flag(key, m.block.verdict, why)
	flag(key.Reverse(), m.block.verdict, why)
}

// siteHello sends the client's ClientHello to the site and reads the
// ServerHello it answers with.
func (m *serverHelloCheck) siteHello(ctx context.Context, cmp helloCompare) (serverHello, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	c, err := m.dial(ctx, "tcp", cmp.site.String())
	if err != nil {
		return serverHello{}, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(cmp.clientHello); err != nil {
		return serverHello{}, err
	}
	return readServerHello(c)
}

// readServerHello reads from c until it holds a whole ServerHello.
func readServerHello(c io.Reader) (serverHello, error) {
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		h, herr := serverHelloOf(got)
		switch {
		case herr == nil:
			return h, nil
		case !errors.Is(herr, errIncomplete) || len(got) >= retainBytes:
			return serverHello{}, fmt.Errorf("answered %d bytes, no ServerHello: %w", len(got), herr)
		case err != nil:
			return serverHello{}, fmt.Errorf("after %d bytes: %w", len(got), err)
		}
	}
}
