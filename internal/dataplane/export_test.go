package dataplane

import (
	"net/netip"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// PutPeerOnDeviceForTest makes later Applies put peer on its own device,
// as a chain's exit will be (TP-030).
func PutPeerOnDeviceForTest(e *Engine, peer netmap.NodeID, device string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.assign = func(oc OverlayConfig) map[string][]devicePeer {
		want := overlayOnly(oc)
		for i, p := range want[OverlayDevice] {
			if p.ID == peer {
				want[device] = []devicePeer{p}
				want[OverlayDevice] = append(want[OverlayDevice][:i:i], want[OverlayDevice][i+1:]...)
				break
			}
		}
		return want
	}
}

// RouteDefaultsToOverlayForTest makes later Applies route 0.0.0.0/0 and ::/0
// to the overlay device, as a rule would (TP-015).
func RouteDefaultsToOverlayForTest(e *Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = func(egresses map[string]*router.Egress) []router.Route {
		return []router.Route{
			{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Egress: egresses[OverlayDevice]},
			{Prefix: netip.MustParsePrefix("::/0"), Egress: egresses[OverlayDevice]},
		}
	}
}

// SetInterfaceTimingForTest paces the interface's re-applies.
func SetInterfaceTimingForTest(e *Engine, debounce, cooldown, retry time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ifcTiming = interfaceTiming{debounce: debounce, cooldown: cooldown, retry: retry}
}

// IPv6OffCodeForTest is ipv6OffCode.
var IPv6OffCodeForTest = ipv6OffCode

// FailRouterTablesForTest makes the router refuse every table while fail
// is set: the table names an egress of another router.
func FailRouterTablesForTest(e *Engine, fail *atomic.Bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	foreign, err := router.New(tuntest.NewChannelTUN().TUN()).NewEgress("foreign", 1280)
	if err != nil {
		panic(err)
	}
	rules := e.rules
	e.rules = func(egresses map[string]*router.Egress) []router.Route {
		if fail.Load() {
			return []router.Route{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Egress: foreign}}
		}
		return rules(egresses)
	}
}
