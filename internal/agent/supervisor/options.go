package supervisor

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ErrUnsupported is returned by New where there is no supervisor: it needs
// Linux namespaces.
var ErrUnsupported = errors.New("supervisor: needs Linux")

const (
	// LinkPrefix starts the name of every space's veth end in the root
	// namespace (tp-space0, tp-space1, …): the supervisor's nftables rules
	// match it, and links with it are a dead supervisor's leftovers.
	LinkPrefix = "tp-space"
	// SpaceInterface is the other end's name, inside each space's namespace.
	SpaceInterface = "veth0"
	// TableName is the supervisor's nftables table (family inet) in the root
	// namespace; nothing else in it is touched.
	TableName = "thinkpol-supervisor"
	// ArpTableName is the supervisor's nftables table in the arp family,
	// where a space's ARP is dropped (the inet family doesn't see ARP).
	ArpTableName = "thinkpol-supervisor-arp"
	// DefaultUIDBase is the first worker's host user id; the worker in slot n
	// runs in a user namespace whose root maps to host uid and gid
	// DefaultUIDBase+n. It only has to be a range unused on the node: this
	// one is above SSSD's default id-mapping ceiling (2 000 200 000) and
	// below 2^31, clear of real and SSSD-mapped users. Workers need no
	// passwd entry.
	DefaultUIDBase = 2_000_300_000
)

var (
	// DefaultTransitIPv4 holds a /30 per slot: .1 the root end, .2 the
	// space's. Link-local, so it never collides with an overlay
	// (100.64.0.0/10) or a provider's network, and it stays clear of the
	// cloud metadata address 169.254.169.254.
	DefaultTransitIPv4 = netip.MustParsePrefix("169.254.100.0/22")
	// DefaultTransitIPv6 holds a /64 per slot: ::1 the root end, ::2 the
	// space's.
	DefaultTransitIPv6 = netip.MustParsePrefix("fd74:7073:7061::/48")
)

// Space is one space the supervisor serves.
type Space struct {
	ID netmap.SpaceID
	// Config is the worker's opaque per-space configuration (TP-011 defines
	// it). The supervisor sends it to every incarnation after Init and to
	// the running worker when it changes. A large one travels as a sealed
	// memfd, never a disk file.
	Config []byte
	// Egress describes how the space reaches the internet, for the egress
	// rules in the supervisor's table (TP-014). The zero value is no egress.
	Egress Egress
	// Inbound is, per transport name, the links the space's own map says
	// to accept (dataplane.InboundFrom of its section). The supervisor
	// authenticates the shared listeners' traffic against every space's
	// links, and stamps each link's Space with ID, whatever it said.
	Inbound map[string][]transport.PeerLink
}

// Egress is a space's internet egress, enforced in the root namespace, the
// only place the spaces' veths meet (TP-014 implements the rules).
type Egress struct {
	// Uplink is the root-namespace interface a space's masqueraded traffic
	// leaves by; empty means no egress.
	Uplink string
	// IPv4 and IPv6 say which families may leave.
	IPv4, IPv6 bool
}

// Options configures a supervisor. Zero values take the defaults.
type Options struct {
	// Command starts a worker; the supervisor appends "-space <id>".
	// Default: the running binary's `worker` command (/proc/self/exe).
	Command []string
	// Env is the workers' whole environment (default: empty).
	Env []string
	// TransitIPv4 and TransitIPv6 are carved into one /30 and one /64 per
	// worker slot for its veth pair.
	TransitIPv4, TransitIPv6 netip.Prefix
	// UIDBase is the first worker's host uid/gid (DefaultUIDBase); 0 is
	// refused.
	UIDBase uint32
	// Backoff paces the restarts of a crashing worker.
	Backoff Backoff
	// ReadyTimeout bounds a worker's start, from exec to Ready (10 s).
	ReadyTimeout time.Duration
	// StopTimeout is how long a worker gets to exit after Stop before it is
	// killed (5 s).
	StopTimeout time.Duration
	// OutputBytes bounds each space's ring of its worker's output (64 KiB);
	// worker output never reaches a disk.
	OutputBytes int
	// MemoryMax and PidsMax cap a worker's cgroup (memory.max, pids.max);
	// zero leaves that limit unset. Enforced where cgroup v2 is available,
	// otherwise approximated by the worker's own rlimits.
	MemoryMax int64
	PidsMax   int64
	// Log gets the supervisor's own events (default: discarded). The node
	// agent points it at an in-memory ring.
	Log *slog.Logger
	// Transports are the transports the shared listeners may use
	// (SetListeners).
	Transports *transport.Registry
	// FairShare, if set, meters and caps each space's use of the shared
	// listeners; nil leaves them unmetered.
	FairShare FairShare
	// now is an injectable clock for the backoff schedule in tests.
	now func() time.Time
}

// Backoff paces restarts: the first after Initial, each next one twice as
// long, up to Max; a worker that ran for ResetAfter starts over at Initial.
type Backoff struct {
	Initial, Max, ResetAfter time.Duration
}

// DefaultBackoff is what a zero Backoff becomes.
var DefaultBackoff = Backoff{Initial: 500 * time.Millisecond, Max: 30 * time.Second, ResetAfter: time.Minute}

// next is the delay before a restart, given the previous delay (0 for the
// first crash) and how long the worker ran.
func (b Backoff) next(prev, ran time.Duration) time.Duration {
	if prev == 0 || ran >= b.ResetAfter {
		return b.Initial
	}
	return min(2*prev, b.Max)
}

func (o Options) withDefaults() (Options, error) {
	if o.TransitIPv4 == (netip.Prefix{}) {
		o.TransitIPv4 = DefaultTransitIPv4
	}
	if o.TransitIPv6 == (netip.Prefix{}) {
		o.TransitIPv6 = DefaultTransitIPv6
	}
	if o.UIDBase == 0 {
		o.UIDBase = DefaultUIDBase
	}
	if o.Backoff == (Backoff{}) {
		o.Backoff = DefaultBackoff
	}
	if o.ReadyTimeout == 0 {
		o.ReadyTimeout = 10 * time.Second
	}
	if o.StopTimeout == 0 {
		o.StopTimeout = 5 * time.Second
	}
	if o.OutputBytes == 0 {
		o.OutputBytes = 64 << 10
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Env == nil {
		o.Env = []string{}
	}
	if o.now == nil {
		o.now = time.Now
	}
	switch {
	case !o.TransitIPv4.Addr().Is4() || o.TransitIPv4.Bits() > 30 || o.TransitIPv4 != o.TransitIPv4.Masked():
		return o, fmt.Errorf("supervisor: IPv4 transit %v: want a masked IPv4 prefix of /30 or more", o.TransitIPv4)
	case !o.TransitIPv6.Addr().Is6() || o.TransitIPv6.Addr().Is4In6() || o.TransitIPv6.Bits() > 64 || o.TransitIPv6 != o.TransitIPv6.Masked():
		return o, fmt.Errorf("supervisor: IPv6 transit %v: want a masked IPv6 prefix of /64 or more", o.TransitIPv6)
	case o.Backoff.Initial <= 0 || o.Backoff.Max < o.Backoff.Initial || o.Backoff.ResetAfter <= 0:
		return o, fmt.Errorf("supervisor: bad backoff %+v", o.Backoff)
	case o.MemoryMax < 0 || o.PidsMax < 0:
		return o, fmt.Errorf("supervisor: negative resource limit")
	case uint64(o.UIDBase)+uint64(o.slots()) > 1<<32-2:
		return o, fmt.Errorf("supervisor: worker user ids from %d overflow", o.UIDBase)
	}
	return o, nil
}

// maxSlots keeps link names within the kernel's 15 bytes and zone ids within
// a conntrack zone's 16 bits.
const maxSlots = 60000

// slots is how many workers the transit prefixes have room for.
func (o Options) slots() int {
	return min(1<<min(30-o.TransitIPv4.Bits(), 30), 1<<min(64-o.TransitIPv6.Bits(), 30), maxSlots)
}

// transit is the address plan of slot n's veth pair: the root end's and the
// space end's addresses, IPv4 and IPv6.
type transit struct {
	root, space [2]netip.Prefix
}

func (o Options) transit(slot int) transit {
	v4 := nthAddr(o.TransitIPv4.Addr(), uint64(slot)*4) // the slot's /30 block base
	v6 := nthAddr(o.TransitIPv6.Addr(), uint64(slot))   // the slot's /64 base
	return transit{
		root:  [2]netip.Prefix{netip.PrefixFrom(v4.Next(), 30), netip.PrefixFrom(offset6(v6, 1), 64)},
		space: [2]netip.Prefix{netip.PrefixFrom(v4.Next().Next(), 30), netip.PrefixFrom(offset6(v6, 2), 64)},
	}
}

// nthAddr adds n to an IPv4 address (slots × 4 stays well within 32 bits for
// any sane prefix).
func nthAddr(base netip.Addr, n uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(n)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	// IPv6: n counts /64s, i.e. add n to the high 64 bits.
	b := base.As16()
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	hi += n
	for i := 0; i < 8; i++ {
		b[i] = byte(hi >> (56 - 8*i))
	}
	return netip.AddrFrom16(b)
}

// offset6 adds n to the low bits of an IPv6 address (for the two host
// addresses in a /64).
func offset6(a netip.Addr, n uint64) netip.Addr {
	b := a.As16()
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	lo += n
	for i := 0; i < 8; i++ {
		b[8+i] = byte(lo >> (56 - 8*i))
	}
	return netip.AddrFrom16(b)
}

// linkName is slot n's veth end in the root namespace.
func linkName(slot int) string { return fmt.Sprintf("%s%d", LinkPrefix, slot) }

// WorkerInfo is one space's worker as the supervisor sees it.
type WorkerInfo struct {
	Space netmap.SpaceID
	// Link is the space's veth end in the root namespace.
	Link string
	// RootAddrs and SpaceAddrs are the veth pair's addresses (IPv4, IPv6).
	RootAddrs, SpaceAddrs []netip.Prefix
	// UID is the host uid/gid the worker's user namespace maps its root to.
	UID uint32
	// PID is the running worker's process id in the root namespace, 0
	// between restarts.
	PID int
	// Ready is set once the running worker has sandboxed itself.
	Ready bool
	// Starts counts the worker's processes so far.
	Starts int
	// StartedAt and ReadyAt are when the current process started and became
	// ready; NextStart is when a restart is due after a crash (all zero when
	// not applicable).
	StartedAt, ReadyAt, NextStart time.Time
	// LastExit is why the previous process ended ("" before any did).
	LastExit string
	// OutputDropped counts lines dropped from the worker's output ring.
	OutputDropped uint64
	// Shared is what the shared listeners forwarded to the space's workers
	// and sent for them, and what they dropped.
	Shared SharedCounters
}
