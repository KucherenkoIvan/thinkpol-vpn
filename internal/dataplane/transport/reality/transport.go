package reality

import (
	"fmt"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Options configure the adapter.
type Options struct {
	// Control, if set, is called on every socket before it is bound or
	// connected (the dialer's, the listener's, the listener's to its
	// target), e.g. to set a firewall mark so it bypasses the tunnel.
	Control func(network, address string, c syscall.RawConn) error
	// Now is the clock; nil means time.Now. Nodes' clocks must agree within
	// the listener's time window.
	Now func() time.Time
}

// Transport is the reality adapter.
type Transport struct {
	control func(network, address string, c syscall.RawConn) error
	now     func() time.Time
	sent    *transport.SendMeter
}

var _ transport.Transport = (*Transport)(nil)

// New returns the reality adapter.
func New(o Options) *Transport {
	t := &Transport{control: o.Control, now: o.Now, sent: &transport.SendMeter{}}
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
	if _, err := parseAddrPort(endpoint); err != nil {
		return invalid("endpoint: %v", err)
	}
	if _, err := parseShortID(cfg.Credential); err != nil {
		return err
	}
	if _, err := parseDial(cfg.Settings); err != nil {
		return err
	}
	return checkShaping(cfg.Shaping)
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
	if err := support.Check(s); err != nil {
		return fmt.Errorf("reality: %w", err)
	}
	p := s.Padding
	if int(p.Max) > MaxRandomPadding {
		return fmt.Errorf("reality: %w: random padding up to %d bytes, reality adds at most %d", transport.ErrUnsupportedShaping, p.Max, MaxRandomPadding)
	}
	for _, b := range p.Buckets {
		if int(b) > maxUnit {
			return fmt.Errorf("reality: %w: a bucket of %d bytes, reality writes records of at most %d", transport.ErrUnsupportedShaping, b, maxUnit)
		}
	}
	return nil
}
