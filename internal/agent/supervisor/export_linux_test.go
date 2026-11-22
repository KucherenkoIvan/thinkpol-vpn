//go:build linux && !android

package supervisor

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var SetNetSysctls = setNetSysctls

// WithUnboundAccepts turns on the negative control of the forged-ICMP tests
// (Options.unboundAccepts): the accepts take any established or related
// flow, whoever owns it. Test-only: production never sets it.
func WithUnboundAccepts(opts Options) Options {
	opts.unboundAccepts = true
	return opts
}

// WithArpOnOutput turns on the negative control of the forged-ARP test
// (Options.arpOnOutput): the arp chain sits on the ARP output hook, where
// a space's ARP never matches. Test-only: production never sets it.
func WithArpOnOutput(opts Options) Options {
	opts.arpOnOutput = true
	return opts
}

// ListenersAnswered reports how many Listeners messages the space's
// attached worker was sent and has answered; ok is false while none is
// attached.
func ListenersAnswered(s *Supervisor, space netmap.SpaceID) (sent, answered int64, ok bool) {
	routes := s.shared.routes.Load()
	if routes == nil {
		return 0, 0, false
	}
	r := (*routes)[transport.SpaceID(space)]
	if r == nil {
		return 0, 0, false
	}
	ws := r.end.Load()
	if ws == nil {
		return 0, 0, false
	}
	return ws.listenersSent.Load(), ws.listenersAnswered.Load(), true
}
