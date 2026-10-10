package memory_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

func TestConformance(t *testing.T) {
	network := memory.NewNetwork()
	var endpoints atomic.Int64
	transporttest.Run(t, transporttest.Harness{
		Listen: func(t *testing.T, endpoint string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, string) {
			if endpoint == "" {
				endpoint = fmt.Sprintf("listener-%d", endpoints.Add(1))
			}
			l, err := network.Listen(endpoint, peers, camouflage)
			if err != nil {
				t.Fatal(err)
			}
			return l, endpoint
		},
		Dialer: network,
	})
}
