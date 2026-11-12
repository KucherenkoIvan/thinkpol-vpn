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
	// NoDNS are destinations DNS (UDP and TCP ports 53 and 853) is
	// refused to even where Allow lets everything else out: the agent's
	// LAN in the down shape with allow-LAN (on macOS but the entries
	// whose transport is on port 53 or 853), so the OS's own resolvers
	// (a home router forwarding in the clear) get no lookups while the
	// tunnel is down. The links' marked sockets pass on Linux.
	NoDNS *lists.Set
}

// Equal reports whether r and o let out the same traffic.
func (r KillSwitchRules) Equal(o KillSwitchRules) bool {
	return r.TUN == o.TUN && r.Mark == o.Mark && r.Allow.Equal(o.Allow) && r.Direct.Equal(o.Direct) &&
		slices.Equal(r.Upstreams, o.Upstreams) && r.NoDNS.Equal(o.NoDNS)
}

// LAN is what allow-LAN lets out: private and link-local unicast,
// broadcast, and multicast of link-local and site-local scope only (mDNS
// on 224.0.0.251 and ff02::fb, SSDP on 239.255.255.250, ff02::c and
// ff05::c), both families; multicast of a wider scope may be routed
// beyond the LAN. It is the agent's definition, which puts it in Allow
// (and, while down, in NoDNS); the firewall itself never reads it.
var LAN = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/24"),   // link-local multicast (RFC 5771)
	netip.MustParsePrefix("239.255.0.0/16"), // site-local scope (RFC 2365)
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff02::/16"), // link-local scope (RFC 4291)
	netip.MustParsePrefix("ff05::/16"), // site-local scope
}

// DirectTimeout is how long, on Linux, Direct stays in place after the
// last Apply: the agent applies the kill switch again at every 10 s tick
// while it runs, at most about 15 s apart (an apply between ticks can
// push the next one a tick later), so only a dead agent, or one whose
// node loop stalls for about 15 s, lets it expire. Longer would leave a
// dead agent's direct destinations open longer.
const DirectTimeout = 30 * time.Second

// ErrKillSwitchUnsupported: the OS can't hold the kill switch (no
// nf_tables in the kernel; no pfctl).
var ErrKillSwitchUnsupported = errors.New("firewall: the OS can't hold the kill switch")

// ErrKillSwitchInPlace marks an Apply error after which the rules are in
// place all the same, enforced but not as asked in full: on Linux the
// bridges couldn't be listed (none passes), on macOS pf took the load and
// is on but its read-back failed. Any other Apply error leaves what was
// in place before (one transaction).
var ErrKillSwitchInPlace = errors.New("firewall: the kill switch is in place, but")

// errKillSwitchClosed: the kill switch was closed. Shared by the Linux and
// macOS kill switches; Windows has none yet (TP-076).
var errKillSwitchClosed = errors.New("firewall: the kill switch is closed") //nolint:unused // unused on Windows only
