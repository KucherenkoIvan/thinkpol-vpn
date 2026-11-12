package agent

import (
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// supported reports whether this OS can run a node's data plane in mode:
// a device's, not a server's, whose supervisor and per-space workers need
// Linux's namespaces. Nothing is configured before this check.
func supported(mode Mode) error {
	if mode == ModeServer {
		return fmt.Errorf("%w: server mode needs Linux; run this node as a device (-mode device)", ErrUnsupported)
	}
	return nil
}

// killSwitchPlace is where the host holds the kill switch, as a report
// names it: the anchor, and the pf reference that keeps pf enabled for
// it with its record.
const killSwitchPlace = "the pf anchor " + firewall.KillSwitchAnchor + ", its pf reference and record"
