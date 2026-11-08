package firewall

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// KillSwitchRules is what the kill switch lets out of every interface but
// loopback: anything else a process of the device sends is refused, both
// families. The agent picks it (the connected shape while the tunnel is
// up, the down shape otherwise); the firewall only applies it.
type KillSwitchRules struct {
	// TUN is the overlay interface while connected, whose traffic is the
	// tunnel's; empty while the tunnel is down.
	TUN string
	// Mark is the links' socket mark (routetable.Mark): the transports'
	// and the direct DNS upstreams' sockets. Zero is none; macOS, without
	// socket marks, ignores it.
	Mark uint32
	// Allow are the destinations any socket may reach whatever happens to
	// the agent: the entries, and with allow-LAN the LAN.
	Allow *lists.Set
	// Direct are the destinations the rules send around the tunnel, while
	// connected. On Linux they expire DirectTimeout after the last Apply
	// unless applied again: an agent that dies leaves the entries alone.
	// pf can't expire them: macOS keeps them until the next start.
	Direct *lists.Set
	// Upstreams are the direct DNS upstreams, for an OS without socket
	// marks (macOS lets DNS to them out on their ports); while connected.
	Upstreams []netip.AddrPort
}

// Equal reports whether r and o let out the same traffic.
func (r KillSwitchRules) Equal(o KillSwitchRules) bool {
	return r.TUN == o.TUN && r.Mark == o.Mark && r.Allow.Equal(o.Allow) && r.Direct.Equal(o.Direct) &&
		slices.Equal(r.Upstreams, o.Upstreams)
}

// LAN is what allow-LAN lets out: private and link-local unicast, and
// multicast and broadcast, of both families.
var LAN = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

// DirectTimeout is how long, on Linux, Direct stays in place after the
// last Apply: the agent applies the kill switch again well within it
// while it runs (every 10 s), so only a dead agent lets it expire.
const DirectTimeout = 30 * time.Second

// ErrKillSwitchUnsupported: the OS can't hold the kill switch (no
// nf_tables in the kernel; no pfctl).
var ErrKillSwitchUnsupported = errors.New("firewall: the OS can't hold the kill switch")
