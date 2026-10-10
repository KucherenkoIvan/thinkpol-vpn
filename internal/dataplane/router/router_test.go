package router_test

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
)

const wait = 5 * time.Second

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func newRouter(t *testing.T) (*router.Router, *tuntest.ChannelTUN) {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	r := router.New(ch.TUN())
	t.Cleanup(func() { _ = r.Close() })
	return r, ch
}

func egress(t *testing.T, r *router.Router, name string) *router.Egress {
	t.Helper()
	e, err := r.NewEgress(name, 1400)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// reads collects what a WireGuard device would read from an egress.
func reads(e *router.Egress) <-chan []byte {
	out := make(chan []byte, 64)
	go func() {
		defer close(out)
		bufs := make([][]byte, e.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, 16+router.MaxPacket)
		}
		sizes := make([]int, len(bufs))
		for {
			n, err := e.Read(bufs, sizes, 16)
			for i := range n {
				out <- bytes.Clone(bufs[i][16 : 16+sizes[i]])
			}
			if err != nil {
				return
			}
		}
	}()
	return out
}

func ping(src, dst string) []byte { return packettest.Echo(addr(src), addr(dst), 1, 1, nil) }

// The router is ready for one WireGuard device per egress: two egresses,
// overlay addresses classified before any rule, rules by longest prefix.
func TestRoutesEachDestinationToItsEgress(t *testing.T) {
	r, ch := newRouter(t)
	overlay, exit := egress(t, r, "overlay"), egress(t, r, "chain-de")
	err := r.SetTable(router.Table{
		Overlay: []netip.Prefix{prefix("100.64.0.0/16"), prefix("fd00:1::/48")},
		Peers: []router.Route{
			{Prefix: prefix("100.64.0.2/32"), Egress: overlay},
			{Prefix: prefix("fd00:1::2/128"), Egress: overlay},
			{Prefix: prefix("100.64.0.3/32"), Egress: exit}, // an exit is also an overlay peer
		},
		Rules: []router.Route{
			{Prefix: prefix("0.0.0.0/0"), Egress: exit},
			{Prefix: prefix("::/0"), Egress: exit},
			{Prefix: prefix("10.0.0.0/8"), Egress: overlay},
			{Prefix: prefix("10.1.0.0/16")}, // block
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	toOverlay, toExit := reads(overlay), reads(exit)

	cases := []struct {
		dst  string
		want <-chan []byte // nil: dropped
	}{
		{"100.64.0.2", toOverlay},
		{"fd00:1::2", toOverlay},
		{"100.64.0.3", toExit},
		{"100.64.0.9", nil}, // in the overlay, no peer: never to the exit's default
		{"fd00:1::9", nil},
		{"10.2.3.4", toOverlay},
		{"10.1.2.3", nil},
		{"192.0.2.1", toExit},
		{"2001:db8::1", toExit},
	}
	for _, c := range cases {
		src := "100.64.0.1"
		if addr(c.dst).Is6() {
			src = "fd00:1::1"
		}
		pkt := ping(src, c.dst)
		ch.Outbound <- pkt
		if c.want == nil {
			continue
		}
		select {
		case got := <-c.want:
			if !bytes.Equal(got, pkt) {
				t.Fatalf("%s: got %x, want %x", c.dst, got, pkt)
			}
		case <-time.After(wait):
			t.Fatalf("%s: nothing arrived at its egress", c.dst)
		}
	}
	ch.Outbound <- []byte{0x45, 0} // too short for a header
	ch.Outbound <- []byte{0x10, 0, 0, 0}
	ch.Outbound <- ping("100.64.0.1", "100.64.0.2") // a marker: everything before it was handled
	<-toOverlay
	select {
	case p := <-toOverlay:
		t.Fatalf("overlay got an extra %x", p)
	case p := <-toExit:
		t.Fatalf("exit got an extra %x", p)
	default:
	}
	c := r.Counters()
	if c.Routed != 7 || c.NoRoute != 2 || c.Blocked != 1 || c.Malformed != 2 {
		t.Fatalf("counters %+v", c)
	}
}

func TestEgressWritesGoToTheTUN(t *testing.T) {
	r, ch := newRouter(t)
	a, b := egress(t, r, "a"), egress(t, r, "b")
	for _, e := range []*router.Egress{a, b} {
		pkt := ping("100.64.0.2", "100.64.0.1")
		buf := append(make([]byte, 16), pkt...)
		written := make(chan int)
		go func() {
			n, _ := e.Write([][]byte{buf}, 16)
			written <- n
		}()
		select {
		case got := <-ch.Inbound:
			if !bytes.Equal(got, pkt) {
				t.Fatalf("TUN got %x, want %x", got, pkt)
			}
		case <-time.After(wait):
			t.Fatal("nothing reached the TUN")
		}
		if n := <-written; n != 1 {
			t.Fatalf("Write reported %d packets", n)
		}
	}
	if c := r.Counters(); c.Delivered != 2 {
		t.Fatalf("delivered %d, want 2", c.Delivered)
	}
}

func TestReadHandsOverABatch(t *testing.T) {
	r, ch := newRouter(t)
	e := egress(t, r, "overlay")
	if err := r.SetTable(router.Table{Rules: []router.Route{{Prefix: prefix("0.0.0.0/0"), Egress: e}}}); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		ch.Outbound <- packettest.Echo(addr("100.64.0.1"), addr("192.0.2.1"), 1, uint16(i), nil)
	}
	deadline := time.Now().Add(wait)
	for r.Counters().Routed < 5 {
		if time.Now().After(deadline) {
			t.Fatal("packets weren't queued")
		}
		time.Sleep(time.Millisecond)
	}
	bufs := [][]byte{make([]byte, 200), make([]byte, 200), make([]byte, 200)}
	sizes := make([]int, 3)
	if n, err := e.Read(bufs, sizes, 16); n != 3 || err != nil {
		t.Fatalf("read %d, %v; want a full batch of 3", n, err)
	}
	if n, err := e.Read(bufs, sizes, 16); n != 2 || err != nil {
		t.Fatalf("read %d, %v; want the 2 left", n, err)
	}
	if p, ok := packettest.Parse(bufs[1][16 : 16+sizes[1]]); !ok || !packettest.IsEchoRequest(p, 1, 4) {
		t.Fatalf("second packet of the batch %+v, want the fifth ping", p)
	}
}

// A slow WireGuard device loses packets; it doesn't stall the router.
func TestAFullQueueDropsInsteadOfBlocking(t *testing.T) {
	r, ch := newRouter(t)
	slow, other := egress(t, r, "slow"), egress(t, r, "other")
	err := r.SetTable(router.Table{Rules: []router.Route{
		{Prefix: prefix("10.0.0.0/8"), Egress: slow},
		{Prefix: prefix("192.0.2.0/24"), Egress: other},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range router.QueueLen + 10 {
		ch.Outbound <- ping("100.64.0.1", "10.0.0.1")
	}
	ch.Outbound <- ping("100.64.0.1", "192.0.2.1")
	select {
	case <-reads(other):
	case <-time.After(wait):
		t.Fatal("a full queue on one egress stalled the others")
	}
	if c := r.Counters(); c.QueueFull != 10 || c.Routed != router.QueueLen+1 {
		t.Fatalf("counters %+v", c)
	}
}

func TestSetTableRefusesBadTables(t *testing.T) {
	r, _ := newRouter(t)
	other, _ := newRouter(t)
	e, foreign := egress(t, r, "e"), egress(t, other, "f")
	for name, table := range map[string]router.Table{
		"a prefix twice": {Peers: []router.Route{{Prefix: prefix("100.64.0.2/32"), Egress: e}, {Prefix: prefix("100.64.0.2/32"), Egress: e}}},
		"another router": {Rules: []router.Route{{Prefix: prefix("0.0.0.0/0"), Egress: foreign}}},
		"invalid prefix": {Overlay: []netip.Prefix{{}}},
		"IPv4-mapped":    {Rules: []router.Route{{Prefix: prefix("::ffff:10.0.0.0/104"), Egress: e}}},
	} {
		if err := r.SetTable(table); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The same prefix in two lists is fine: the overlay is decided first.
	if err := r.SetTable(router.Table{
		Overlay: []netip.Prefix{prefix("100.64.0.0/10")},
		Peers:   []router.Route{{Prefix: prefix("100.64.0.0/10"), Egress: e}},
		Rules:   []router.Route{{Prefix: prefix("100.64.0.0/10")}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEgressMTUChangesReachWireGuard(t *testing.T) {
	r, _ := newRouter(t)
	e := egress(t, r, "overlay")
	if err := e.SetMTU(1280); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-e.Events():
		if ev != tun.EventMTUUpdate {
			t.Fatalf("event %v", ev)
		}
	case <-time.After(wait):
		t.Fatal("no MTU event")
	}
	if mtu, _ := e.MTU(); mtu != 1280 {
		t.Fatalf("MTU %d", mtu)
	}
	if err := e.SetMTU(router.MaxPacket + 1); err == nil {
		t.Fatal("an MTU above MaxPacket was accepted")
	}
}

func TestCloseUnblocksEgresses(t *testing.T) {
	r, _ := newRouter(t)
	e := egress(t, r, "overlay")
	out := reads(e)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-out:
		if open {
			t.Fatal("read a packet from a closed egress")
		}
	case <-time.After(wait):
		t.Fatal("Read still blocks after the router closed")
	}
	if _, err := e.Write([][]byte{make([]byte, 40)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	if _, err := r.NewEgress("late", 1400); !errors.Is(err, router.ErrClosed) {
		t.Fatalf("NewEgress after close: %v", err)
	}
	if _, open := <-e.Events(); open {
		t.Fatal("events still open")
	}
}
