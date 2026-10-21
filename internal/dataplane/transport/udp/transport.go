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
	_ transport.Transport      = (*Transport)(nil)
	_ transport.PacketRoutable = (*Transport)(nil)
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

// Network implements transport.Transport.
func (t *Transport) Network() string { return "udp" }

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
func (t *Transport) Listen(ctx context.Context, cfg transport.ListenConfig, accept transport.Accept) (transport.Listener, error) {
	pc, err := t.ListenPacket(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return t.ListenOn(pc, accept), nil
}

// ListenPacket implements transport.PacketRoutable: the socket Listen would
// listen on, for a shared listener to read.
func (t *Transport) ListenPacket(ctx context.Context, cfg transport.ListenConfig) (*net.UDPConn, error) {
	ap, err := parseEndpoint(cfg.Address)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(cfg.Settings, &transportv1.UdpListenSettings{}); err != nil {
		return nil, fmt.Errorf("udp: listener settings: %w", err)
	}
	lc := net.ListenConfig{Control: t.control}
	pc, err := lc.ListenPacket(ctx, listenNetwork(ap), cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("udp: listen: %w", err)
	}
	return pc.(*net.UDPConn), nil
}

// ListenForwarded implements transport.PacketRoutable with ListenOn.
func (t *Transport) ListenForwarded(pc net.PacketConn, accept transport.Accept) (transport.Listener, error) {
	return t.ListenOn(pc, accept), nil
}

// listenNetwork binds one address family, as the map's listeners mean it:
// on plain "udp", Go makes a wildcard address one dual-stack socket, so
// 0.0.0.0:p and [::]:p would collide.
func listenNetwork(ap netip.AddrPort) string {
	if ap.Addr().Is4() || ap.Addr().Is4In6() {
		return "udp4"
	}
	return "udp6"
}

// ListenOn listens on pc, which it owns from now on. pc need not be a
// socket: a worker behind a shared listener reads the datagrams the
// supervisor routed to it and writes replies back the same way.
func (t *Transport) ListenOn(pc net.PacketConn, accept transport.Accept) *Listener {
	return newListener(t, pc, accept.Peers, accept.Camouflage)
}

// PacketRouter implements transport.PacketRoutable.
func (t *Transport) PacketRouter(peers transport.Peers) transport.PacketRouter {
	return newRouter(t, peers)
}

// Counters are what a udp receiver took in, dropped and why. Stale
// timestamps are counted apart because they point at a clock that is off.
type Counters struct {
	Delivered       uint64 // packets
	Cover           uint64 // authenticated datagrams that carried no packet
	Unauthenticated uint64 // unknown connection id, bad tag, malformed
	StaleTimestamp  uint64 // sent more than five minutes from our clock
	StaleSender     uint64 // an older sender while a newer one is active
	Replayed        uint64 // a counter seen before, or behind the window
	NoLink          uint64 // no link is open, and the datagram opens none
}

type counters struct {
	delivered, cover, unauthenticated, staleTimestamp, staleSender, replayed, noLink atomic.Uint64
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
		NoLink:          c.noLink.Load(),
	}
}

// backoff paces a read loop through persistent errors.
type backoff struct{ d time.Duration }

func (b *backoff) wait() {
	b.d = min(max(2*b.d, time.Millisecond), 100*time.Millisecond)
	time.Sleep(b.d)
}

func (b *backoff) reset() { b.d = 0 }

// writeError wraps a socket's write error, marking a datagram too long for
// the path.
func writeError(err error) error {
	if isMessageSize(err) {
		return fmt.Errorf("udp: write: %w: %w", transport.ErrPacketTooLong, err)
	}
	return fmt.Errorf("udp: write: %w", err)
}
