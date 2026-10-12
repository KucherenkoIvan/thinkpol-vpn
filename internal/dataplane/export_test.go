package dataplane

import (
	"net/netip"
	"time"

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
