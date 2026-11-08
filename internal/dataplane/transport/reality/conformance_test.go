package reality

import (
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// Shapings reality implements, with the conformance suite run under each.
var shapings = map[string]transport.Shaping{
	"buckets": {Padding: transporttest.Buckets(128, 256, 512, 1024, 1452, 4096, 9000)},
	"random":  {Padding: transport.Padding{Mode: transport.PadRandom, Min: 0, Max: MaxRandomPadding}},
}

func TestConformance(t *testing.T) {
	transporttest.Run(t, harness(t, newTransport(Options{}), transport.Shaping{}))
}

func TestConformanceShaped(t *testing.T) {
	tr := newTransport(Options{})
	for name, s := range shapings {
		t.Run(name, func(t *testing.T) {
			transporttest.Run(t, harness(t, tr, s))
		})
	}
}
