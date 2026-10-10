package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// Shapings udp implements, with the conformance suite run under each.
var shapings = map[string]transport.Shaping{
	"buckets": {Padding: transport.Buckets(128, 256, 512, 1024, 1452)},
	"random":  {Padding: transport.Padding{Mode: transport.PadRandom, Min: 0, Max: MaxRandomPadding}},
}

// Shapings udp can't honour.
var refused = []transport.Shaping{
	{BatchWindow: time.Millisecond},
	{Jitter: time.Millisecond},
	{CoverInterval: time.Second},
	{Padding: transport.Padding{Mode: transport.PadRandom, Max: MaxRandomPadding + 1}},
	{Padding: transport.Buckets(1280, maxDatagram+1)},
}

func harness(tr *Transport, address string, s transport.Shaping) transporttest.Harness {
	return transporttest.Harness{
		Listen: func(t *testing.T, addr string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
			if addr == "" {
				addr = address
			}
			l, err := tr.Listen(context.Background(), transport.ListenConfig{Address: addr, Peers: peers, Camouflage: camouflage})
			if err != nil {
				t.Fatal(err)
			}
			return l, transporttest.Endpoint{Address: l.Addr().String()}
		},
		Dialer:    tr.Dialer(),
		Interpose: interpose,
		Shaping:   s,
		Refused:   refused,
		Transport: tr,
	}
}

func TestConformance(t *testing.T) {
	tr := New(Options{})
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			transporttest.Run(t, harness(tr, address, transport.Shaping{}))
		})
	}
}

func TestConformanceShaped(t *testing.T) {
	tr := New(Options{})
	for name, s := range shapings {
		t.Run(name, func(t *testing.T) {
			transporttest.Run(t, harness(tr, "127.0.0.1:0", s))
		})
	}
}

// interpose puts a tap in front of address for the suite's Replay test.
func interpose(t *testing.T, address string) (string, func()) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	tp := newTap(t, addr)
	return tp.addr(), func() {
		up, _ := tp.captured()
		for _, d := range up {
			tp.inject(d)
		}
	}
}
