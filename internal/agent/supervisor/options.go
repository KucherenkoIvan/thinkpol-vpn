package supervisor

import (
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ErrUnsupported is returned by New where there is no supervisor: it needs
// Linux namespaces.
var ErrUnsupported = errors.New("supervisor: needs Linux")

const (
	// LinkPrefix starts the name of every space's veth end in the root
	// namespace (tp-space0, tp-space1, …): the supervisor's nftables table
	// matches it, and links with it are a dead supervisor's leftovers.
	LinkPrefix = "tp-space"
	// SpaceInterface is the other end's name, inside each space's namespace.
	SpaceInterface = "veth0"
	// TableName is the supervisor's nftables table (family inet) in the root
	// namespace; nothing else in it is touched.
	TableName = "thinkpol-supervisor"
	// DefaultUIDBase is the first worker user id: the worker in slot n runs
	// as user and group DefaultUIDBase+n. Workers need no passwd entry; the
	// range only has to be unused on the node.
	DefaultUIDBase = 0x74700000
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
	// UIDBase is the first worker user id (DefaultUIDBase); 0 is refused.
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
	// Log gets the supervisor's own events (default: discarded). The node
	// agent points it at an in-memory ring.
	Log *slog.Logger
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
	switch {
	case !o.TransitIPv4.Addr().Is4() || o.TransitIPv4.Bits() > 30 || o.TransitIPv4 != o.TransitIPv4.Masked():
		return o, fmt.Errorf("supervisor: IPv4 transit %v: want a masked IPv4 prefix of /30 or more", o.TransitIPv4)
	case !o.TransitIPv6.Addr().Is6() || o.TransitIPv6.Addr().Is4In6() || o.TransitIPv6.Bits() > 64 || o.TransitIPv6 != o.TransitIPv6.Masked():
		return o, fmt.Errorf("supervisor: IPv6 transit %v: want a masked IPv6 prefix of /64 or more", o.TransitIPv6)
	case o.Backoff.Initial <= 0 || o.Backoff.Max < o.Backoff.Initial:
		return o, fmt.Errorf("supervisor: bad backoff %+v", o.Backoff)
	case uint64(o.UIDBase)+uint64(o.slots()) > 1<<32-2:
		return o, fmt.Errorf("supervisor: worker user ids from %d overflow", o.UIDBase)
	}
	return o, nil
}

// maxSlots keeps link names within the kernel's 15 bytes.
const maxSlots = 10_000_000

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
	v4 := nthAddr(o.TransitIPv4.Addr(), big.NewInt(int64(slot)*4))
	v6 := nthAddr(o.TransitIPv6.Addr(), new(big.Int).Lsh(big.NewInt(int64(slot)), 64))
	return transit{
		root:  [2]netip.Prefix{netip.PrefixFrom(v4.Next(), 30), netip.PrefixFrom(v6.Next(), 64)},
		space: [2]netip.Prefix{netip.PrefixFrom(v4.Next().Next(), 30), netip.PrefixFrom(v6.Next().Next(), 64)},
	}
}

func nthAddr(base netip.Addr, n *big.Int) netip.Addr {
	b := base.AsSlice()
	sum := new(big.Int).Add(new(big.Int).SetBytes(b), n).FillBytes(make([]byte, len(b)))
	a, _ := netip.AddrFromSlice(sum)
	return a
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
	// UID is the user the worker runs as.
	UID uint32
	// PID is the running worker's process id in the root namespace, 0
	// between restarts.
	PID int
	// Ready is set once the running worker has sandboxed itself.
	Ready bool
	// Starts counts the worker's processes so far.
	Starts int
	// LastExit is why the previous process ended ("" before any did).
	LastExit string
}
