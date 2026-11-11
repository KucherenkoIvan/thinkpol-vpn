package reality

import (
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// Shapings reality implements, with the conformance suite run under each.
var shapings = map[string]transport.Shaping{
	"buckets": {Padding: transporttest.Buckets(128, 256, 512, 1024, 1452, 4096, 9000)},
	"random":  {Padding: transport.Padding{Mode: transport.PadRandom, Min: 0, Max: MaxRandomPadding}},
}

// TestConformance runs unshaped with a table the listener takes late, as
// on a loaded node: a dial right after a table change admitted its peer
// still finds the old table.
func TestConformance(t *testing.T) {
	h := harness(t, newTransport(Options{}), transport.Shaping{})
	listen := h.Listen
	h.Listen = func(t *testing.T, addr string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
		t.Helper()
		return listen(t, addr, lateTable{peers, tableLag}, camouflage)
	}
	transporttest.Run(t, h)
}

func TestConformanceShaped(t *testing.T) {
	tr := newTransport(Options{})
	for name, s := range shapings {
		t.Run(name, func(t *testing.T) {
			transporttest.Run(t, harness(t, tr, s))
		})
	}
}

// tableLag is how late lateTable hands out a change: far longer than a
// dial takes on loopback, far shorter than the suite's quiet period.
const tableLag = 5 * time.Millisecond

// lateTable is a peer table whose snapshot is taken lag after it is asked
// for, so a listener takes every change at least lag after it was made.
type lateTable struct {
	transport.Peers
	lag time.Duration
}

func (p lateTable) Snapshot() ([]transport.PeerLink, <-chan struct{}) {
	time.Sleep(p.lag)
	return p.Peers.Snapshot()
}
