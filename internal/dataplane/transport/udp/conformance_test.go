package udp

import (
	"net"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

func TestConformance(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			transporttest.Run(t, transporttest.Harness{
				Listen: func(t *testing.T, endpoint string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, string) {
					if endpoint == "" {
						endpoint = address
					}
					l, err := Listen(endpoint, peers, camouflage)
					if err != nil {
						t.Fatal(err)
					}
					return l, l.Addr().String()
				},
				Dialer:    &Dialer{},
				Interpose: interpose,
			})
		})
	}
}

// interpose puts a tap in front of endpoint for the suite's Replay test.
func interpose(t *testing.T, endpoint string) (string, func()) {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
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
