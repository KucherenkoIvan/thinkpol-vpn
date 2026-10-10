package udp_test

import (
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

func TestConformance(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			transporttest.Run(t, transporttest.Harness{
				Listen: func(t *testing.T, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, string) {
					l, err := udp.Listen(address, peers, camouflage)
					if err != nil {
						t.Fatal(err)
					}
					return l, l.Addr().String()
				},
				Dialer: &udp.Dialer{},
			})
		})
	}
}
