package udp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// TestCaptureShowsNoWireGuard runs two real WireGuard devices over a udp
// link, pings across, and checks the censor's view of the wire: none of the
// WireGuard messages that crossed it is recognisable.
func TestCaptureShowsNoWireGuard(t *testing.T) {
	f := newFixture(t)
	keyA, keyB := wgKey(t), wgKey(t)
	ipA, ipB := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2")

	bindA := newLinkBind(f.dial())
	tunA := tuntest.NewChannelTUN()
	devA := wgDevice(t, tunA, bindA, keyA, keyB, ipB)
	bindA.start()

	// A's handshake initiation opens the link at the listener.
	tunA.Outbound <- tuntest.Ping(ipB, ipA)
	bindB := newLinkBind(f.accept())
	tunB := tuntest.NewChannelTUN()
	devB := wgDevice(t, tunB, bindB, keyB, keyA, ipA)
	bindB.start()
	expectPing(t, tunB, ipB, ipA)

	tunB.Outbound <- tuntest.Ping(ipA, ipB)
	expectPing(t, tunA, ipA, ipB)
	devA.Close()
	devB.Close()

	sent := append(bindA.sent(), bindB.sent()...)
	types := map[byte]int{}
	for _, m := range sent {
		if !looksLikeWireGuard(m) {
			t.Fatalf("the classifier misses a raw WireGuard message: %x", m[:16])
		}
		types[m[0]]++
	}
	for typ, name := range map[byte]string{1: "handshake initiation", 2: "handshake response", 4: "transport data"} {
		if types[typ] == 0 {
			t.Fatalf("no WireGuard %s crossed the link; the test proves nothing", name)
		}
	}
	up, down := f.tap.captured()
	wire := append(up, down...)
	if len(wire) < len(sent) {
		t.Fatalf("captured %d datagrams for %d WireGuard messages", len(wire), len(sent))
	}
	for _, d := range wire {
		if looksLikeWireGuard(d) {
			t.Fatalf("captured datagram looks like WireGuard: %x", d[:min(len(d), 32)])
		}
		for _, m := range sent {
			// Type, reserved bytes, the sender or receiver index and the
			// start of the counter or ephemeral key.
			if bytes.Contains(d, m[:16]) {
				t.Fatalf("a WireGuard header shows through: %x", m[:16])
			}
		}
	}
	t.Logf("captured %d datagrams carrying %d WireGuard messages (by type: %v); none recognisable", len(wire), len(sent), types)
}

// looksLikeWireGuard is the usual DPI signature: a message type from 1 to 4,
// three zero bytes, and the length that type has on the wire.
func looksLikeWireGuard(d []byte) bool {
	if len(d) < 4 || d[1] != 0 || d[2] != 0 || d[3] != 0 {
		return false
	}
	switch d[0] {
	case 1:
		return len(d) == device.MessageInitiationSize
	case 2:
		return len(d) == device.MessageResponseSize
	case 3:
		return len(d) == device.MessageCookieReplySize
	case 4:
		return len(d) >= device.MessageTransportSize && len(d)%16 == 0
	}
	return false
}

func wgKey(t *testing.T) *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wgDevice(t *testing.T, tn *tuntest.ChannelTUN, bind conn.Bind, own, peer *ecdh.PrivateKey, peerIP netip.Addr) *device.Device {
	dev := device.NewDevice(tn.TUN(), bind, device.NewLogger(device.LogLevelSilent, ""))
	err := dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(own.Bytes()), hex.EncodeToString(peer.PublicKey().Bytes()), peerIP))
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return dev
}

// expectPing allows for one handshake retransmission (wireguard-go's
// REKEY_TIMEOUT is 5 s) on a slow run.
func expectPing(t *testing.T, tn *tuntest.ChannelTUN, dst, src netip.Addr) {
	t.Helper()
	want := tuntest.Ping(dst, src)
	select {
	case got := <-tn.Inbound:
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x, want the ping %x", got, want)
		}
	case <-time.After(3 * wait):
		t.Fatalf("the ping from %s to %s never arrived", src, dst)
	}
}

// linkBind is a conn.Bind over one transport.Link: the smallest path layer.
// WireGuard opens and closes binds as it likes, so the link is read by a
// pump that outlives each Open. The pump starts once the device is up:
// wireguard-go drops what arrives before its peers run.
type linkBind struct {
	link    transport.Link
	packets chan []byte

	mu       sync.Mutex
	open     chan struct{}
	messages [][]byte
}

func newLinkBind(l transport.Link) *linkBind {
	return &linkBind{link: l, packets: make(chan []byte, 256)}
}

func (b *linkBind) start() {
	l := b.link
	go func() {
		buf := make([]byte, transport.MaxPacketSize)
		for {
			n, err := l.ReadPacket(buf)
			if err != nil {
				close(b.packets)
				return
			}
			b.packets <- bytes.Clone(buf[:n])
		}
	}()
}

func (b *linkBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	open := make(chan struct{})
	b.open = open
	receive := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-open:
			return 0, net.ErrClosed
		default:
		}
		select {
		case p, ok := <-b.packets:
			if !ok {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(packets[0], p)
			eps[0] = linkEndpoint{}
			return 1, nil
		case <-open:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{receive}, 1, nil
}

func (b *linkBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open != nil {
		close(b.open)
		b.open = nil
	}
	return nil
}

func (b *linkBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, p := range bufs {
		b.mu.Lock()
		b.messages = append(b.messages, bytes.Clone(p))
		b.mu.Unlock()
		if err := b.link.WritePacket(p); err != nil {
			return err
		}
	}
	return nil
}

func (b *linkBind) sent() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.messages...)
}

func (b *linkBind) SetMark(uint32) error                        { return nil }
func (b *linkBind) ParseEndpoint(string) (conn.Endpoint, error) { return linkEndpoint{}, nil }
func (b *linkBind) BatchSize() int                              { return 1 }

type linkEndpoint struct{}

func (linkEndpoint) ClearSrc()           {}
func (linkEndpoint) SrcToString() string { return "" }
func (linkEndpoint) DstToString() string { return "link" }
func (linkEndpoint) DstToBytes() []byte  { return []byte("link") }
func (linkEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (linkEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
