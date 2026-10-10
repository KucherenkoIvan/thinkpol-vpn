package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// Name is the transport's name in the map.
const Name = "udp"

// MinSecretSize is the shortest link secret udp accepts.
const MinSecretSize = 32

// Options configure the adapter.
type Options struct {
	// Control, if set, is called on every socket before it is bound or
	// connected, e.g. to set a firewall mark so it bypasses the tunnel.
	Control func(network, address string, c syscall.RawConn) error
	// Now is the clock; nil means time.Now. Nodes' clocks must agree within
	// five minutes.
	Now func() time.Time
}

// Transport is the udp adapter.
type Transport struct {
	control func(network, address string, c syscall.RawConn) error
	now     func() time.Time
}

var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Routable  = (*Transport)(nil)
)

// New returns the udp adapter.
func New(o Options) *Transport {
	t := &Transport{control: o.Control, now: o.Now}
	if t.now == nil {
		t.now = time.Now
	}
	return t
}

func (t *Transport) Name() string { return Name }

func (t *Transport) Dialer() transport.Dialer { return t }

// Overhead implements transport.Transport: the fixed Overhead plus the most
// random padding adds.
func (t *Transport) Overhead(s transport.Shaping) int { return Overhead + s.Padding.Growth() }

// CheckEndpoint implements transport.Transport.
func (t *Transport) CheckEndpoint(endpoint string, cfg transport.DialConfig) error {
	if _, err := parseEndpoint(endpoint); err != nil {
		return err
	}
	if len(cfg.Credential) < MinSecretSize {
		return fmt.Errorf("udp: credential is %d bytes, need at least %d", len(cfg.Credential), MinSecretSize)
	}
	if err := checkShaping(cfg.Shaping); err != nil {
		return err
	}
	return proto.Unmarshal(cfg.Settings, &transportv1.UdpDialSettings{})
}

// CheckInbound implements transport.Transport.
func (t *Transport) CheckInbound(pl transport.PeerLink) error { return checkInbound(pl) }

func checkInbound(pl transport.PeerLink) error {
	if len(pl.Verifier) < MinSecretSize {
		return fmt.Errorf("udp: verifier is %d bytes, need at least %d", len(pl.Verifier), MinSecretSize)
	}
	if err := checkShaping(pl.Shaping); err != nil {
		return err
	}
	return proto.Unmarshal(pl.Settings, &transportv1.UdpInboundSettings{})
}

func parseEndpoint(endpoint string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return ap, fmt.Errorf("udp: endpoint %q is not an IP literal and port: %w", endpoint, err)
	}
	return ap, nil
}

// Listen implements transport.Transport.
func (t *Transport) Listen(ctx context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	if _, err := parseEndpoint(cfg.Address); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(cfg.Settings, &transportv1.UdpListenSettings{}); err != nil {
		return nil, fmt.Errorf("udp: listener settings: %w", err)
	}
	lc := net.ListenConfig{Control: t.control}
	pc, err := lc.ListenPacket(ctx, "udp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("udp: listen: %w", err)
	}
	return t.ListenOn(pc, cfg), nil
}

// ListenOn listens on pc, which it owns from now on; cfg.Address is
// ignored. pc need not be a socket: a worker behind a shared listener reads
// the datagrams the supervisor routed to it and writes replies back the
// same way.
func (t *Transport) ListenOn(pc net.PacketConn, cfg transport.ListenConfig) *Listener {
	return newListener(t, pc, cfg.Peers, cfg.Camouflage)
}

// Router implements transport.Routable.
func (t *Transport) Router(peers transport.Peers) transport.Router { return newRouter(t, peers) }

// Counters are what a udp receiver took in, dropped and why. Stale
// timestamps are counted apart because they point at a clock that is off.
type Counters struct {
	Delivered       uint64 // packets
	Cover           uint64 // authenticated datagrams that carried no packet
	Unauthenticated uint64 // unknown connection id, bad tag, malformed
	StaleTimestamp  uint64 // sent more than five minutes from our clock
	StaleSender     uint64 // an older sender while a newer one is active
	Replayed        uint64 // a counter seen before, or behind the window
}

type counters struct {
	delivered, cover, unauthenticated, staleTimestamp, staleSender, replayed atomic.Uint64
}

// received counts an authenticated datagram that passed every check.
func (c *counters) received(packets int) {
	if packets == 0 {
		c.cover.Add(1)
	}
	c.delivered.Add(uint64(packets))
}

func (c *counters) snapshot() Counters {
	return Counters{
		Delivered:       c.delivered.Load(),
		Cover:           c.cover.Load(),
		Unauthenticated: c.unauthenticated.Load(),
		StaleTimestamp:  c.staleTimestamp.Load(),
		StaleSender:     c.staleSender.Load(),
		Replayed:        c.replayed.Load(),
	}
}

// backoff paces a read loop through persistent errors.
type backoff struct{ d time.Duration }

func (b *backoff) wait() {
	b.d = min(max(2*b.d, time.Millisecond), 100*time.Millisecond)
	time.Sleep(b.d)
}

func (b *backoff) reset() { b.d = 0 }
