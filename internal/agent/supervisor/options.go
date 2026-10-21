package supervisor

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
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
	// Seeds, if set, returns the space's blob seeds (the lists its map
	// names that the node's state directory holds). It is called when a
	// worker starts and when the config changes, and each seed the worker
	// hasn't had yet goes to it as a sealed memfd before the config: the
	// supervisor keeps no copy, and none rides in the config.
	Seeds func() [][]byte `json:"-"`
	// Egress is the families the space may reach the internet in: its
	// traffic leaves the root namespace by the node's uplink, masqueraded,
	// in those of them the uplink carries. The zero value is no egress.
	Egress EgressGrant
	// Dials are the endpoints the space's worker dials (its section's
	// links to other servers). They leave by the uplink, masqueraded,
	// whatever Egress says; nothing else does without egress.
	Dials []Dial
	// Inbound is, per transport name, the links the space's own map says
	// to accept (dataplane.AcceptedInbound of its section, the table its
	// worker's engine accepts too). The supervisor
	// authenticates the shared listeners' traffic against every space's
	// links, and stamps each link's Space with ID, whatever it said.
	Inbound map[string][]transport.PeerLink
}

// EgressGrant is what a space may send to the internet, enforced in the
// root namespace, the only place the spaces' veths meet, and in the space's
// own namespace. A family granted that the uplink doesn't carry is refused
// inside the space's namespace with ICMP "no route", so clients fall back
// to the other at once instead of timing out.
type EgressGrant struct {
	IPv4, IPv6 bool
}

// Dial is an endpoint a space's worker dials: an address and port, and the
// transport's network ("udp" or "tcp").
type Dial struct {
	Address netip.AddrPort
	Network string
}

// EgressInfo is the node's egress as the supervisor sees it: the uplink, the
// families it carries, and whether the root namespace forwards them.
type EgressInfo struct {
	// Uplink is the interface of the root namespace's default route; empty
	// when there is none (Err says why), and then no space has egress.
	Uplink                   string
	IPv4, IPv6               bool
	Forwarding4, Forwarding6 bool
	Err                      EgressError
}

// EgressError says why a node has no uplink: a code, the supervisor's log
// has the detail.
type EgressError string

const (
	EgressNoDefaultRoute EgressError = "no_default_route" // egress.ErrNoUplink
	// EgressUplinkUnusable: the default route's interface has a name the
	// tables can't match exactly.
	EgressUplinkUnusable EgressError = "uplink_unusable"
	EgressUplinkUnknown  EgressError = "uplink_unknown" // finding it failed
	EgressUnsupported    EgressError = "unsupported"    // no supervisor here
)

// egressError is err's code.
func egressError(err error) EgressError {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, egress.ErrNoUplink):
		return EgressNoDefaultRoute
	case errors.Is(err, errUplinkUnusable):
		return EgressUplinkUnusable
	case errors.Is(err, egress.ErrUnsupported), errors.Is(err, ErrUnsupported):
		return EgressUnsupported
	}
	return EgressUplinkUnknown
}

// errUplinkUnusable is an uplink whose name the tables can't match.
var errUplinkUnusable = errors.New("not an interface name the tables can match")

// MasqueradePorts is the source port range masqueraded flows get (fully
// random within it). Listeners can't bind inside it, so no reply to a space's
// flow is taken for a connection to a listener, or the other way round.
var MasqueradePorts = [2]uint16{32768, 60999}

// DefaultRuntimeDir holds what the supervisor changed in the root
// namespace's sysctls, so a successor restores it: a tmpfs, like the
// sysctls' own lifetime.
const DefaultRuntimeDir = "/run/thinkpol"

// Options configures a supervisor. Zero values take the defaults; NewRoot
// has none.
type Options struct {
	// Command starts a worker; the supervisor appends "-space <id>".
	// Default: the running binary's `worker` command (/proc/self/exe).
	Command []string
	// NewRoot builds the supervisor's network configurator, the root
	// namespace's owner. Required.
	NewRoot func() (netcfg.Configurator, error)
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
	// Output, if set, gives a writer per space that gets its worker's
	// output too, besides the ring; nil for a space whose output stays in
	// its ring. Never a file. The output is the space's: the writer must
	// neutralize control bytes. A slow writer slows that worker's logging.
	Output func(space netmap.SpaceID) io.Writer
	// MemoryMax and PidsMax cap a worker's cgroup (memory.max, pids.max);
	// zero leaves that limit unset. Enforced where cgroup v2 is available,
	// otherwise approximated by the worker's own rlimits.
	MemoryMax int64
	PidsMax   int64
	// Log gets the supervisor's own events (default: discarded).
	Log *slog.Logger
	// Transports are the transports the shared listeners may use
	// (SetListeners).
	Transports *transport.Registry
	// FairShare, if set, meters and caps each space's use of the shared
	// listeners; nil leaves them unmetered.
	FairShare FairShare
	// CountersInterval is how often each worker is sent its space's
	// SharedCounters, for its telemetry (10 s).
	CountersInterval time.Duration
	// Uplink finds the node's uplink (egress.FindUplink). The supervisor
	// asks again on every SetSpaces and whenever the root namespace's
	// routes change.
	Uplink func() (egress.Uplink, error)
	// EgressAllowed are destinations spaces may reach by egress and dials
	// although egressBlocked holds them (a provider network that is the
	// internet to this node, as the lab's is).
	EgressAllowed []netip.Prefix
	// MaxFlowsPerSpace caps the connections a space has through the root
	// namespace at once (new ones over it are dropped), so one space can't
	// fill the node's conntrack table. 0: a quarter of nf_conntrack_max;
	// negative: no cap.
	MaxFlowsPerSpace int
	// RuntimeDir is where the supervisor records the forwarding sysctls it
	// changed (DefaultRuntimeDir).
	RuntimeDir string
	// sysctls are the root namespace's sysctls (the supervisor's own
	// /proc/sys); tests stand in for the kernel.
	sysctls netSysctls
	// unboundAccepts, arpOnOutput and failIsolation are test-only hooks,
	// and only the linux build reads them; production never sets them.
	// unboundAccepts is the forged-ICMP tests' negative control: the
	// accepts then take any established or related flow, whoever owns it.
	// arpOnOutput is the forged-ARP test's: the arp chain goes on the ARP
	// output hook, where a space's ARP never matches. failIsolation is the
	// failure injected into a table rebuild. All are set at New and never
	// written afterwards; failIsolation is armed and disarmed atomically.
	unboundAccepts bool           //nolint:unused // test-only, read in the linux build
	arpOnOutput    bool           //nolint:unused // test-only, read in the linux build
	failIsolation  *rebuildFailer //nolint:unused // test-only, read in the linux build
	// now is an injectable clock for the backoff schedule in tests.
	now func() time.Time
}

// rebuildFailer is the test-only Options.failIsolation: the injected
// failure of an isolation-table rebuild. Like the field, the type and its
// methods are read in the linux build only.
//
//nolint:unused // test-only, read in the linux build
type rebuildFailer struct {
	armed atomic.Bool
	// err is what an armed rebuild fails with.
	err error
	// before, if set, runs just before the failure, to open a window.
	before atomic.Pointer[func()]
	// failEmpty fails the no-slot install too (New's), not only a rebuild
	// for spaces: a test failing New itself needs that, while one failing
	// a SetSpaces leaves it off, so a concurrent no-slot rebuild passes.
	failEmpty bool
}

// arm fails every rebuild until disarm, running before just before
// failing, if set.
//
//nolint:unused // test-only, read in the linux build
func (f *rebuildFailer) arm(before func()) {
	if before != nil {
		f.before.Store(&before)
	}
	f.armed.Store(true)
}

//nolint:unused // test-only, read in the linux build
func (f *rebuildFailer) disarm() {
	f.armed.Store(false)
	f.before.Store(nil)
}

// fail is what applyIsolation asks before it touches nftables.
//
//nolint:unused // test-only, read in the linux build
func (f *rebuildFailer) fail(slots int) error {
	if !f.armed.Load() || (slots == 0 && !f.failEmpty) {
		return nil
	}
	if b := f.before.Load(); b != nil {
		(*b)()
	}
	return f.err
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
	if o.Uplink == nil {
		o.Uplink = egress.FindUplink
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
	}
	if o.CountersInterval == 0 {
		o.CountersInterval = 10 * time.Second
	}
	if o.sysctls == nil {
		o.sysctls = procSysFS{root: "/proc/sys"}
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
	for _, p := range o.EgressAllowed {
		if !p.IsValid() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return o, fmt.Errorf("supervisor: egress allowed %v: want an IPv4 or IPv6 prefix", p)
		}
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
	return transitOf(o.TransitIPv4, o.TransitIPv6, slot)
}

// transitOf is the address plan of slot n's veth pair under the transit
// prefixes: the root end's and the space end's addresses, IPv4 and IPv6.
func transitOf(transit4, transit6 netip.Prefix, slot int) transit {
	v4 := nthAddr(transit4.Addr(), uint64(slot)*4) // the slot's /30 block base
	v6 := nthAddr(transit6.Addr(), uint64(slot))   // the slot's /64 base
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
	// and sent for them, and what they dropped; the worker gets the same
	// figures for its telemetry.
	Shared SharedCounters
}
