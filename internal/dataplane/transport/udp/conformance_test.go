package udp

import (
	"context"
	"net"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

func TestConformance(t *testing.T) {
	tr := New(Options{})
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			transporttest.Run(t, transporttest.Harness{
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
			})
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
