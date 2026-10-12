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
			{Prefix: prefix("10.1.5.0/24"), Direct: true},
			{Prefix: prefix("2001:db8:d::/48"), Direct: true},
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
		{"10.1.5.5", nil}, // direct: dropped, never to the exit's default
		{"2001:db8:d::1", nil},
		{"::ffff:10.1.5.5", nil}, // IPv4-mapped: by its IPv4 address, direct, not ::/0's exit
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
	// An egress counts a packet once its queue took it, which may be just
	// after its reader has it.
	deadline := time.Now().Add(wait)
	for {
		c := r.Counters()
		if c.Routed == 7 && c.NoRoute == 2 && c.Blocked == 1 && c.Direct == 3 && c.Malformed == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters %+v", c)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestEgressWritesGoToTheTUN(t *testing.T) {
	r, ch := newRouter(t)
	a, b := egress(t, r, "a"), egress(t, r, "b")
	if err := r.SetTable(router.Table{Local: []netip.Addr{addr("100.64.0.1"), addr("fd00:1::1")}}); err != nil {
		t.Fatal(err)
	}
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

// What a WireGuard device decrypts reaches the TUN only for the node's own
// addresses: a peer can't route through the node into its other networks.
func TestEgressWritesOnlyLocalDestinations(t *testing.T) {
	r, ch := newRouter(t)
	e := egress(t, r, "overlay")
	if err := r.SetTable(router.Table{Local: []netip.Addr{addr("100.64.0.1"), addr("fd00:1::1")}}); err != nil {
		t.Fatal(err)
	}
	local := ping("100.64.0.2", "100.64.0.1")
	batch := [][]byte{
		append(make([]byte, 16), ping("100.64.0.2", "192.168.1.5")...), // the peer's own source, a LAN destination
		append(make([]byte, 16), local...),
		append(make([]byte, 16), ping("fd00:1::2", "fd00:1::3")...), // another overlay node
		append(make([]byte, 16), 0x45),                              // no header
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if n, err := e.Write(batch, 16); n != len(batch) || err != nil {
			t.Errorf("Write: %d, %v; want every packet taken", n, err)
		}
	}()
	select {
	case got := <-ch.Inbound:
		if !bytes.Equal(got, local) {
			t.Fatalf("TUN got %x, want only the local packet", got)
		}
	case <-time.After(wait):
		t.Fatal("the local packet didn't reach the TUN")
	}
	<-done
	select {
	case got := <-ch.Inbound:
		t.Fatalf("TUN got a non-local packet %x", got)
	default:
	}
	if c, s := r.Counters(), e.Status(); c.NotLocal != 3 || s.NotLocal != 3 || s.Delivered != 1 {
		t.Fatalf("router %+v, egress %+v", c, s)
	}
	// Nothing local at all: nothing written, still all taken.
	if n, err := e.Write(batch[:1], 16); n != 1 || err != nil {
		t.Fatalf("Write: %d, %v", n, err)
	}
}

// On an exit (Table.Forward), the overlay device's decrypted packets for
// the internet reach the TUN too, for the node to forward; overlay
// addresses other than the node's own still don't, nor anything another
// egress decrypts for the internet.
func TestForwardingEgressDeliversTheInternet(t *testing.T) {
	r, ch := newRouter(t)
	overlay, exit := egress(t, r, "overlay"), egress(t, r, "exit-1")
	table := router.Table{
		Overlay: []netip.Prefix{prefix("100.64.0.0/10"), prefix("fd00:1::/48")},
		Local:   []netip.Addr{addr("100.64.0.1"), addr("fd00:1::1")},
		Forward: []*router.Egress{overlay},
	}
	if err := r.SetTable(table); err != nil {
		t.Fatal(err)
	}
	pkt := func(src, dst string) []byte {
		return append(make([]byte, 16), packettest.Echo(addr(src), addr(dst), 1, 1, nil)...)
	}
	internet4, internet6 := pkt("100.64.0.2", "192.0.2.1"), pkt("fd00:1::2", "2001:db8::1")
	write := func(e *router.Egress, batch ...[]byte) {
		t.Helper()
		if n, err := e.Write(batch, 16); n != len(batch) || err != nil {
			t.Errorf("Write: %d, %v; want every packet taken", n, err)
		}
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		write(overlay,
			internet4,
			pkt("100.64.0.2", "100.64.0.3"),      // another overlay node
			pkt("fd00:1::2", "fd00:1::3"),        // the same, IPv6
			pkt("fd00:1::2", "::ffff:192.0.2.1"), // IPv4-mapped: no network routes it
			internet6)
	}()
	for _, want := range [][]byte{internet4[16:], internet6[16:]} {
		select {
		case got := <-ch.Inbound:
			if !bytes.Equal(got, want) {
				t.Fatalf("TUN got %x, want %x", got, want)
			}
		case <-time.After(wait):
			t.Fatal("an internet packet didn't reach the TUN")
		}
	}
	<-written
	if s := overlay.Status(); s.Delivered != 2 || s.Forwarded != 2 || s.NotLocal != 3 || r.Counters().Forwarded != 2 {
		t.Fatalf("overlay egress %+v", s)
	}
	// A chain's exit device isn't forwarding: what it decrypts for the
	// internet is dropped.
	write(exit, pkt("192.0.2.9", "198.51.100.1"))
	if s := exit.Status(); s.Delivered != 0 || s.NotLocal != 1 {
		t.Fatalf("exit egress %+v", s)
	}
	// Forwarding goes with the table.
	table.Forward = nil
	if err := r.SetTable(table); err != nil {
		t.Fatal(err)
	}
	write(overlay, internet4)
	if s := overlay.Status(); s.Delivered != 2 || s.NotLocal != 4 {
		t.Fatalf("overlay egress without forwarding %+v", s)
	}
	select {
	case got := <-ch.Inbound:
		t.Fatalf("TUN got %x without forwarding", got)
	default:
	}
	// An egress of another router can't forward.
	other, _ := newRouter(t)
	if err := r.SetTable(router.Table{Forward: []*router.Egress{egress(t, other, "overlay")}}); err == nil {
		t.Fatal("a forwarding egress of another router was taken")
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
	st := r.Egresses()
	if len(st) != 2 || st[1].Name != "slow" || st[1].Queued != router.QueueLen || st[1].QueueFull != 10 || st[0].Routed != 1 {
		t.Fatalf("egresses %+v", st)
	}
}

func TestSetTableRefusesBadTables(t *testing.T) {
	r, _ := newRouter(t)
	other, _ := newRouter(t)
	e, foreign := egress(t, r, "e"), egress(t, other, "f")
	for name, table := range map[string]router.Table{
		"a prefix twice":        {Peers: []router.Route{{Prefix: prefix("100.64.0.2/32"), Egress: e}, {Prefix: prefix("100.64.0.2/32"), Egress: e}}},
		"another router":        {Rules: []router.Route{{Prefix: prefix("0.0.0.0/0"), Egress: foreign}}},
		"invalid prefix":        {Overlay: []netip.Prefix{{}}},
		"IPv4-mapped":           {Rules: []router.Route{{Prefix: prefix("::ffff:10.0.0.0/104"), Egress: e}}},
		"invalid local":         {Local: []netip.Addr{{}}},
		"direct with an egress": {Rules: []router.Route{{Prefix: prefix("10.0.0.0/8"), Egress: e, Direct: true}}},
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

func TestEgressNamesAreUnique(t *testing.T) {
	r, _ := newRouter(t)
	e := egress(t, r, "overlay")
	if _, err := r.NewEgress("overlay", 1400); err == nil {
		t.Fatal("a second egress named overlay")
	}
	_ = e.Close()
	egress(t, r, "overlay") // the name is free again
}

// A packet routed to an egress that closed meanwhile has no route.
func TestAClosedEgressGetsNothing(t *testing.T) {
	r, ch := newRouter(t)
	e := egress(t, r, "overlay")
	if err := r.SetTable(router.Table{Rules: []router.Route{{Prefix: prefix("0.0.0.0/0"), Egress: e}}}); err != nil {
		t.Fatal(err)
	}
	_ = e.Close()
	ch.Outbound <- ping("100.64.0.1", "192.0.2.1")
	ch.Outbound <- []byte{0} // malformed: a marker
	deadline := time.Now().Add(wait)
	for r.Counters().Malformed == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the router didn't read")
		}
		time.Sleep(time.Millisecond)
	}
	if c := r.Counters(); c.NoRoute != 1 || c.Routed != 0 {
		t.Fatalf("counters %+v", c)
	}
}
