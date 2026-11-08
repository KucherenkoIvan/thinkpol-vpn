package reality

import (
	"crypto/x509"
	"net/netip"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Options configure the adapter.
type Options struct {
	// Control, if set, is called on the adapter's own sockets before they
	// are bound or connected, e.g. to set a firewall mark so they bypass
	// the tunnel: the dialer's, the listener's, Listen's check of the
	// target's certificate, and the listener's dial to its target for each
	// connection. REALITY's detection of the target's records at Listen
	// dials with a plain net.Dial, without it.
	Control func(network, address string, c syscall.RawConn) error
	// Now is the clock; nil means time.Now. Nodes' clocks must agree within
	// the listener's time window. It drives the dialer's seal and the
	// listener's own freshness check; REALITY's check behind it uses the
	// real clock.
	Now func() time.Time
	// TrustTargetRoots, for tests and the lab only, replaces the system
	// roots Listen verifies the target's certificate against. Settings
	// never set it.
	TrustTargetRoots *x509.CertPool
}

// Transport is the reality adapter.
type Transport struct {
	control     func(network, address string, c syscall.RawConn) error
	now         func() time.Time
	targetRoots *x509.CertPool // nil: the system roots
	sent        *transport.SendMeter
}

var _ transport.Transport = (*Transport)(nil)

// New returns the reality adapter.
func New(o Options) *Transport {
	t := &Transport{control: o.Control, now: o.Now, targetRoots: o.TrustTargetRoots, sent: &transport.SendMeter{}}
	if t.now == nil {
		t.now = time.Now
	}
	return t
}

func (t *Transport) Name() string { return Name }

// Network implements transport.Transport.
func (t *Transport) Network() string { return "tcp" }

func (t *Transport) Dialer() transport.Dialer { return t }

// Overhead implements transport.Transport: the fixed Overhead plus the most
// random padding adds.
func (t *Transport) Overhead(s transport.Shaping) int { return Overhead + s.Padding.Growth() }

// SendStats is what this adapter's links put on the wire so far.
func (t *Transport) SendStats() transport.SendStats { return t.sent.Stats() }

// CheckEndpoint implements transport.Transport.
func (t *Transport) CheckEndpoint(endpoint string, cfg transport.DialConfig) error {
	_, err := checkDial(endpoint, cfg)
	return err
}

// dialTarget is a checked dial entry.
type dialTarget struct {
	addr     netip.AddrPort
	settings dialSettings
	id       shortID
}

func checkDial(endpoint string, cfg transport.DialConfig) (dialTarget, error) {
	var d dialTarget
	var err error
	if d.addr, err = transport.ParseEndpoint(endpoint); err != nil {
		return d, invalid("endpoint: %v", err)
	}
	if d.id, err = parseShortID(cfg.Credential); err != nil {
		return d, err
	}
	if d.settings, err = parseDial(cfg.Settings); err != nil {
		return d, err
	}
	return d, checkShaping(cfg.Shaping)
}

// CheckInbound implements transport.Transport.
func (t *Transport) CheckInbound(pl transport.PeerLink) error {
	if _, err := parseShortID(pl.Verifier); err != nil {
		return err
	}
	if err := parseInbound(pl.Settings); err != nil {
		return err
	}
	return checkShaping(pl.Shaping)
}

// support is the shaping reality implements: padding of the records it
// writes. Batching, jitter and cover traffic it refuses.
var support = transport.ShapingSupport{Padding: true}

func checkShaping(s transport.Shaping) error {
	return support.CheckBounds(Name, s, MaxRandomPadding, maxUnit)
}
