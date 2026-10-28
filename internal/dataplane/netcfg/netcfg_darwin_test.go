package netcfg

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// fakeKernel is a routing table and interfaces in memory, keeping the
// kernel's rules that matter here: one unscoped route per destination,
// clones and scoped routes beside them, addresses with one prefix length.
type fakeKernel struct {
	mu     sync.Mutex
	rs     map[netip.Prefix]kroute
	scoped map[rkey]kroute // scoped routes added
	extra  []kroute        // the system's scoped and cloned routes
	ifcs   map[string]*kifc
	addrsB map[int][]netip.Prefix

	ops int // changes made
	// failAdd fails the add that would be change number failAdd+1.
	failAdd int
	// onAdd sees each route just before it is added.
	onAdd func(kroute)
	// failDel fails deletes; failChange fails changes; changes counts
	// routes changed in place.
	failDel, failChange bool
	changes             int
}

func newFakeKernel() *fakeKernel {
	k := &fakeKernel{rs: map[netip.Prefix]kroute{}, scoped: map[rkey]kroute{}, ifcs: map[string]*kifc{}, addrsB: map[int][]netip.Prefix{}, failAdd: -1}
	k.ifcs["lo0"] = &kifc{name: "lo0", index: 1, mtu: 16384, up: true, loopback: true}
	k.ifcs["en0"] = &kifc{name: "en0", index: 11, mtu: 1500, up: true}
	k.ifcs["utun7"] = &kifc{name: "utun7", index: 20, mtu: 1500, p2p: true}
	k.addrsB[11] = []netip.Prefix{pfx("192.168.1.20/24")}
	// What a Mac on a home network has.
	for _, r := range []kroute{
		{dst: pfx("0.0.0.0/0"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_PRCLONING | unix.RTF_GLOBAL},
		{dst: pfx("127.0.0.0/8"), gw: ip("127.0.0.1"), index: 1, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_CLONING},
		{dst: pfx("169.254.0.0/16"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_CLONING},
		{dst: pfx("192.168.1.0/24"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_CLONING},
		{dst: pfx("224.0.0.0/4"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_CLONING | unix.RTF_MULTICAST},
		{dst: pfx("255.255.255.255/32"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_CLONING},
		{dst: pfx("::1/128"), gw: ip("::1"), index: 1, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LOCAL},
	} {
		k.rs[r.dst] = r
	}
	k.extra = []kroute{
		{dst: pfx("0.0.0.0/0"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE},
		// A neighbour, cloned from a route of ours someday: it carries the
		// parent's flags, routeFlag included.
		{dst: pfx("8.8.8.8/32"), link: 20, index: 20, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_WASCLONED | routeFlag},
		{dst: pfx("192.168.1.1/32"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LLINFO | unix.RTF_WASCLONED | unix.RTF_IFSCOPE},
	}
	return k
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

func (k *fakeKernel) routes() ([]kroute, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := slices.Collect(maps.Values(k.rs))
	out = append(out, slices.Collect(maps.Values(k.scoped))...)
	return append(out, k.extra...), nil
}

func (k *fakeKernel) add(r kroute) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.onAdd != nil {
		k.onAdd(r)
	}
	if k.failAdd == 0 {
		return unix.ENETUNREACH
	}
	if k.failAdd > 0 {
		k.failAdd--
	}
	if r.link != 0 && k.byIndex(r.link) == nil {
		return unix.ENXIO
	}
	if r.flags&unix.RTF_IFSCOPE != 0 {
		if k.byIndex(r.index) == nil {
			return unix.ENXIO
		}
		if _, ok := k.scoped[r.key()]; ok || k.hasExtra(r.key()) {
			return unix.EEXIST
		}
		k.scoped[r.key()] = r
		k.ops++
		return nil
	}
	if _, ok := k.rs[r.dst]; ok {
		return unix.EEXIST
	}
	// The kernel adds its own flags and fills the interface in.
	r.flags |= unix.RTF_PRCLONING
	if r.link != 0 {
		r.index = r.link
	}
	k.rs[r.dst] = r
	k.ops++
	return nil
}

func (k *fakeKernel) del(r kroute) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failDel {
		return unix.EPERM
	}
	if r.flags&unix.RTF_IFSCOPE != 0 {
		if _, ok := k.scoped[r.key()]; !ok {
			return unix.ESRCH
		}
		delete(k.scoped, r.key())
		k.ops++
		return nil
	}
	if _, ok := k.rs[r.dst]; !ok {
		return unix.ESRCH
	}
	delete(k.rs, r.dst)
	k.ops++
	return nil
}

func (k *fakeKernel) change(r kroute) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failChange {
		return unix.EINVAL
	}
	if r.flags&unix.RTF_IFSCOPE != 0 {
		if _, ok := k.scoped[r.key()]; !ok {
			return unix.ESRCH
		}
		k.scoped[r.key()] = r
		k.ops++
		k.changes++
		return nil
	}
	if _, ok := k.rs[r.dst]; !ok {
		return unix.ESRCH
	}
	r.flags |= unix.RTF_PRCLONING
	if r.link != 0 {
		r.index = r.link
	}
	k.rs[r.dst] = r
	k.ops++
	k.changes++
	return nil
}

func (k *fakeKernel) hasExtra(key rkey) bool {
	for _, r := range k.extra {
		if !r.ignored() && r.key() == key {
			return true
		}
	}
	return false
}

func (k *fakeKernel) byIndex(i int) *kifc {
	for _, l := range k.ifcs {
		if l.index == i {
			return l
		}
	}
	return nil
}

func (k *fakeKernel) interfaces() ([]kifc, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []kifc
	for _, l := range k.ifcs {
		out = append(out, *l)
	}
	return out, nil
}

func (k *fakeKernel) addrs(index int) ([]netip.Prefix, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.byIndex(index) == nil {
		return nil, errNoInterface
	}
	return slices.Clone(k.addrsB[index]), nil
}

func (k *fakeKernel) addAddr(ifc kifc, p netip.Prefix) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	l := k.ifcs[ifc.name]
	if l == nil {
		return errNoInterface
	}
	for _, a := range k.addrsB[l.index] {
		if a.Addr() == p.Addr() {
			return unix.EEXIST
		}
	}
	k.addrsB[l.index] = append(k.addrsB[l.index], p)
	k.ops++
	return nil
}

func (k *fakeKernel) delAddr(ifc kifc, p netip.Prefix) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	l := k.ifcs[ifc.name]
	if l == nil {
		return errNoInterface
	}
	i := slices.Index(k.addrsB[l.index], p)
	if i < 0 {
		return unix.EADDRNOTAVAIL
	}
	k.addrsB[l.index] = slices.Delete(k.addrsB[l.index], i, i+1)
	k.ops++
	return nil
}

func (k *fakeKernel) setMTU(name string, mtu int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ifcs[name] == nil {
		return errNoInterface
	}
	k.ifcs[name].mtu = mtu
	k.ops++
	return nil
}

func (k *fakeKernel) setUp(name string, up bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ifcs[name] == nil {
		return errNoInterface
	}
	k.ifcs[name].up = up
	k.ops++
	return nil
}

func (k *fakeKernel) watch(context.Context) (<-chan struct{}, error) {
	return nil, errors.ErrUnsupported
}

func (k *fakeKernel) close() error { return nil }

// snapshot is everything the kernel holds, as text.
func (k *fakeKernel) snapshot() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var lines []string
	for _, r := range k.rs {
		lines = append(lines, fmt.Sprintf("%v flags=%#x", r, r.flags&^unix.RTF_PRCLONING))
	}
	for _, r := range k.scoped {
		lines = append(lines, fmt.Sprintf("%v scope %d flags=%#x", r, r.index, r.flags))
	}
	for _, l := range k.ifcs {
		lines = append(lines, fmt.Sprintf("%s mtu=%d up=%v addrs=%v", l.name, l.mtu, l.up, k.addrsB[l.index]))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func (k *fakeKernel) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ops
}

func (k *fakeKernel) route(s string) (kroute, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.rs[pfx(s)]
	return r, ok
}

func newTestConfigurator(t *testing.T, k kernel, dir string, o Owner) *darwinConfigurator {
	t.Helper()
	c, err := newDarwin(o, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// overlayConfig is what the engine applies to a utun.
var overlayConfig = Config{Interfaces: []Interface{{
	Name: "utun7", Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")}, MTU: 1328, Up: true,
}}}

// routeTableConfig is a split-route layout like routetable's for macOS.
var routeTableConfig = Config{Routes: []Route{
	{Dst: pfx("0.0.0.0/1"), Interface: "utun7"},
	{Dst: pfx("128.0.0.0/1"), Interface: "utun7"},
	{Dst: pfx("::/1"), Type: RouteUnreachable},
	{Dst: pfx("8000::/1"), Type: RouteUnreachable},
	{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.1"), Interface: "en0"},
	{Dst: pfx("203.0.113.9/32"), Gateway: ip("192.168.1.1")},
	{Dst: pfx("2001:db8::/32"), Gateway: ip("fe80::1"), Interface: "en0"},
}}

// tempDir is a test's directory by a path without symlinks (macOS's
// temporary directories are under /var, a symlink), as trusteddir wants.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func openDir(t *testing.T, dir string) *os.File {
	t.Helper()
	d, err := trusteddir.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func thisBoot(t *testing.T) string {
	t.Helper()
	boot, err := trusteddir.BootSession()
	if err != nil {
		t.Fatal(err)
	}
	return boot
}

func record(t *testing.T, dir string, o Owner) []string {
	t.Helper()
	rec, err := readRecord(openDir(t, dir), recordName(o), thisBoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for p := range rec {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

func TestApplyThenCloseRestoresEverything(t *testing.T) {
	k := newFakeKernel()
	before := k.snapshot()
	dir := tempDir(t)
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if err := rt.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	// The utun is point-to-point: the overlay's networks are routed into
	// it by the overlay's configurator.
	for _, dst := range []string{"100.64.0.0/11", "100.96.0.0/11", "fd12:3456:789a::/49", "fd12:3456:789a:8000::/49"} {
		r, ok := k.route(dst)
		if !ok || r.link != 20 || r.flags&routeFlag == 0 {
			t.Errorf("%s: %v, %v; want an owned route into utun7", dst, r, ok)
		}
	}
	if r, _ := k.route("203.0.113.9/32"); r.flags&unix.RTF_HOST == 0 || r.gw != ip("192.168.1.1") {
		t.Errorf("endpoint route %v flags %#x", r, r.flags)
	}
	if r, _ := k.route("2001:db8::/32"); r.gw != ip("fe80::1") || r.gwZone != 11 {
		t.Errorf("link-local gateway route %v zone %d, want en0's zone 11", r, r.gwZone)
	}
	if r, _ := k.route("::/1"); r.flags&unix.RTF_REJECT == 0 || r.gw != ip("::1") {
		t.Errorf("reject route %v flags %#x", r, r.flags)
	}
	if got := record(t, dir, OwnerOverlay); !slices.Equal(got, []string{"100.64.0.0/11", "100.96.0.0/11", "fd12:3456:789a:8000::/49", "fd12:3456:789a::/49"}) {
		t.Errorf("overlay's record %v", got)
	}
	if got := record(t, dir, OwnerRouteTable); len(got) != len(routeTableConfig.Routes) {
		t.Errorf("route table's record %v", got)
	}
	l := k.ifcs["utun7"]
	if l.mtu != 1328 || !l.up || len(k.addrsB[20]) != 2 {
		t.Errorf("utun7: %+v %v", *l, k.addrsB[20])
	}

	n := k.count()
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if err := rt.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if k.count() != n {
		t.Errorf("re-applying made %d changes", k.count()-n)
	}

	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("after Close:\n%s\nwant:\n%s", got, before)
	}
	for _, o := range []Owner{OwnerOverlay, OwnerRouteTable} {
		if _, err := os.Stat(filepath.Join(dir, recordName(o))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%v's record left: %v", o, err)
		}
		// Its place is free again.
		c, err := newDarwin(o, k, dir)
		if err != nil {
			t.Fatalf("%v after Close: %v", o, err)
		}
		_ = c.Close()
	}
	if err := rt.Apply(ctx, routeTableConfig); !errors.Is(err, ErrClosed) {
		t.Errorf("Apply after Close: %v", err)
	}
}

func TestOneConfiguratorPerOwner(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if _, err := newDarwin(OwnerRouteTable, k, dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second configurator: %v, want ErrBusy", err)
	}
	newTestConfigurator(t, k, dir, OwnerOverlay) // another owner may
	_ = c.Close()
	newTestConfigurator(t, k, dir, OwnerRouteTable)
}

// Routes that aren't an owner's (not recorded by it, or without the
// thinkpol flag) are never changed or removed, whatever flags they carry.
func TestForeignStateIsNeverTouched(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	// Another VPN's split route (RTF_PROTO1), and a route someone else
	// tagged with our flag.
	k.rs[pfx("0.0.0.0/1")] = kroute{dst: pfx("0.0.0.0/1"), link: 11, index: 11, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO1}
	k.rs[pfx("10.0.0.0/8")] = kroute{dst: pfx("10.0.0.0/8"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | routeFlag}
	before := k.snapshot()
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	for _, cfg := range []Config{
		{Routes: []Route{{Dst: pfx("0.0.0.0/1"), Interface: "utun7"}}},
		{Routes: []Route{{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.1")}}},
		// An address on en0 with another prefix length.
		{Interfaces: []Interface{{Name: "en0", Addrs: []netip.Prefix{pfx("192.168.1.20/16")}}}},
	} {
		if err := rt.Apply(ctx, cfg); !errors.Is(err, ErrConflict) {
			t.Errorf("%+v: %v, want ErrConflict", cfg, err)
		}
	}
	// An Apply wanting nothing takes nothing foreign along.
	if err := rt.Apply(ctx, Config{}); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("foreign state changed:\n%s\nwant:\n%s", got, before)
	}
}

func TestOwnersNeverTouchEachOther(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	clash := Config{Routes: []Route{{Dst: pfx("100.64.0.0/11"), Interface: "utun7"}}}
	if err := rt.Apply(ctx, clash); !errors.Is(err, ErrConflict) {
		t.Fatalf("the overlay's route: %v, want ErrConflict", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.route("100.64.0.0/11"); !ok {
		t.Fatal("the route table's Close removed the overlay's route")
	}
	if got := record(t, dir, OwnerOverlay); len(got) != 4 {
		t.Errorf("overlay's record %v", got)
	}
}

// A configurator that died without Close leaves routes and a record; its
// successor takes over what the new config wants and removes the rest.
func TestTakesOverRoutesLeftByACrash(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	dead, err := newDarwin(OwnerRouteTable, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dead.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	_ = dead.lock.release() // the process died: the kernel drops the flock

	next := Config{Routes: slices.Clone(routeTableConfig.Routes[:4])}
	next.Routes = append(next.Routes, Route{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.254")}) // moved
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	n := k.count()
	if err := c.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	// Kept: the four split routes; moved in place: one; removed: two.
	if got := k.count() - n; got != 1+2 || k.changes != 1 {
		t.Errorf("%d changes", got)
	}
	if r, _ := k.route("10.0.0.0/8"); r.gw != ip("192.168.1.254") {
		t.Errorf("moved route %v", r)
	}
	for _, gone := range []string{"203.0.113.9/32", "2001:db8::/32"} {
		if _, ok := k.route(gone); ok {
			t.Errorf("leftover %s still there", gone)
		}
	}
	if got := record(t, dir, OwnerRouteTable); len(got) != 5 {
		t.Errorf("record %v", got)
	}
}

// A failure halfway puts back what the Apply changed, record included.
func TestFailedApplyLeavesNothing(t *testing.T) {
	for _, first := range []bool{true, false} {
		k, dir := newFakeKernel(), tempDir(t)
		ctx := context.Background()
		c := newTestConfigurator(t, k, dir, OwnerRouteTable)
		ov := newTestConfigurator(t, k, dir, OwnerOverlay)
		if !first {
			if err := c.Apply(ctx, Config{Routes: routeTableConfig.Routes[:2]}); err != nil {
				t.Fatal(err)
			}
		}
		before, rec := k.snapshot(), record(t, dir, OwnerRouteTable)
		k.failAdd = 3
		if err := c.Apply(ctx, routeTableConfig); err == nil {
			t.Fatal("no error")
		}
		if got := k.snapshot(); got != before {
			t.Errorf("first=%v: after a failed Apply:\n%s\nwant:\n%s", first, got, before)
		}
		if got := record(t, dir, OwnerRouteTable); !slices.Equal(got, rec) {
			t.Errorf("first=%v: record %v, want %v", first, got, rec)
		}
		// The overlay's interface too: MTU, link and addresses back.
		k.failAdd = 0 // its first connected route fails
		ovBefore := k.snapshot()
		if err := ov.Apply(ctx, overlayConfig); err == nil {
			t.Fatal("no error")
		}
		if got := k.snapshot(); got != ovBefore {
			t.Errorf("overlay after a failed Apply:\n%s\nwant:\n%s", got, ovBefore)
		}
		k.failAdd = -1
	}
}

// Every route an Apply adds is in the record before it is added, so a
// crash at any moment leaves nothing the successor wouldn't take over.
func TestTheRecordIsWrittenAhead(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	var missing []string
	k.onAdd = func(r kroute) {
		rec, _ := readRecord(c.dir, recordName(OwnerRouteTable), c.boot)
		if !rec[r.key()] {
			missing = append(missing, r.dst.String())
		}
	}
	if err := c.Apply(context.Background(), routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Errorf("added before being recorded: %v", missing)
	}
}

func TestReApplyRepairsOutsideChanges(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := c.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	want := k.snapshot()
	k.mu.Lock()
	delete(k.rs, pfx("128.0.0.0/1"))
	delete(k.rs, pfx("100.96.0.0/11"))
	k.addrsB[20] = k.addrsB[20][:1] // the IPv6 address went
	k.ifcs["utun7"].mtu = 1500
	k.mu.Unlock()
	if err := c.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != want {
		t.Errorf("after re-applying:\n%s\nwant:\n%s", got, want)
	}
}

// A recreated utun (same name, new index) gets everything back.
func TestARecreatedInterfaceGetsItsConfigBack(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	delete(k.ifcs, "utun7")
	delete(k.addrsB, 20)
	for _, p := range []string{"100.64.0.0/11", "100.96.0.0/11", "fd12:3456:789a::/49", "fd12:3456:789a:8000::/49"} {
		delete(k.rs, pfx(p))
	}
	k.ifcs["utun7"] = &kifc{name: "utun7", index: 21, mtu: 1500, p2p: true}
	k.mu.Unlock()
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if r, ok := k.route("100.96.0.0/11"); !ok || r.link != 21 {
		t.Errorf("connected route %v, %v", r, ok)
	}
	if len(k.addrsB[21]) != 2 || k.ifcs["utun7"].mtu != 1328 {
		t.Errorf("utun7 %+v %v", *k.ifcs["utun7"], k.addrsB[21])
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if len(k.addrsB[21]) != 0 {
		t.Errorf("addresses left %v", k.addrsB[21])
	}
}

// The kernel's own route into a point-to-point interface is used, not
// owned.
func TestAConnectedRouteOfTheKernelIsUsed(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	k.rs[pfx("100.64.0.0/10")] = kroute{dst: pfx("100.64.0.0/10"), link: 20, index: 20, flags: unix.RTF_UP | unix.RTF_CLONING}
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := ov.Apply(context.Background(), overlayConfig); err != nil {
		t.Fatal(err)
	}
	if got := record(t, dir, OwnerOverlay); !slices.Equal(got, []string{"fd12:3456:789a:8000::/49", "fd12:3456:789a::/49"}) {
		t.Errorf("record %v", got)
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.route("100.64.0.0/10"); !ok {
		t.Error("the kernel's route was removed")
	}
}

func TestWhatMacOSCantHoldIsRefused(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	before := k.snapshot()
	for _, cfg := range []Config{
		{Routes: []Route{{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.1"), Metric: 5}}},
		{Routes: []Route{{Dst: pfx("10.0.0.0/8"), Type: RouteThrow, Table: 100}}},
		{Routes: []Route{{Dst: pfx("10.0.0.0/8"), Type: RouteThrow}}},
		{Routes: []Route{{Dst: pfx("0.0.0.0/0"), Interface: "utun7"}}},
		{Rules: []Rule{{Family: IPv4, Priority: 100}}},
	} {
		if err := c.Apply(context.Background(), cfg); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%+v: %v, want ErrUnsupported", cfg, err)
		}
	}
	if k.snapshot() != before {
		t.Error("a refused config changed something")
	}
	if _, err := New(OwnerSupervisor); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("a supervisor: %v", err)
	}
}

func TestSurveyAndDefaultRoute(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	// Another VPN's routes into its utun, a DHCP server's classless route,
	// a reject route of someone's.
	k.ifcs["utun100"] = &kifc{name: "utun100", index: 30, up: true, p2p: true}
	for _, r := range []kroute{
		{dst: pfx("10.10.0.0/20"), link: 30, index: 30, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO1},
		{dst: pfx("8.8.8.0/24"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC},
		{dst: pfx("198.18.0.0/15"), gw: ip("127.0.0.1"), index: 1, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_REJECT},
		{dst: pfx("192.168.1.20/32"), gw: ip("192.168.1.20"), index: 1, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LOCAL},
	} {
		k.rs[r.dst] = r
	}
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := rt.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	s, err := rt.Survey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(s.OnLink); got != "[169.254.0.0/16 192.168.1.0/24 224.0.0.0/4 255.255.255.255/32]" {
		t.Errorf("on-link %s", got)
	}
	if got := fmt.Sprint(s.Defaults); got != "[0.0.0.0/0 via 192.168.1.1 dev en0]" {
		t.Errorf("defaults %s", got)
	}
	if got := fmt.Sprint(s.Routes); got != "[8.8.8.0/24 via 192.168.1.1 dev en0 10.10.0.0/20 dev utun100]" {
		t.Errorf("routes %s", got)
	}
	// Every identity no owner holds, whatever the route does.
	for _, p := range []string{"0.0.0.0/0", "127.0.0.0/8", "198.18.0.0/15", "192.168.1.20/32", "8.8.8.0/24", "::1/128"} {
		if !slices.Contains(s.Held, pfx(p)) {
			t.Errorf("%s not held: %v", p, s.Held)
		}
	}
	if slices.Contains(s.Held, pfx("0.0.0.0/1")) {
		t.Error("the route table's own route is held")
	}
	if !slices.ContainsFunc(s.Links, func(l Link) bool { return l.Name == "utun7" && !l.Up }) {
		t.Errorf("links %v", s.Links)
	}
	d, err := rt.DefaultRoute(ctx, IPv4)
	if err != nil || d.String() != "0.0.0.0/0 via 192.168.1.1 dev en0" {
		t.Errorf("IPv4 default: %v, %v", d, err)
	}
	// Only a scoped IPv6 default: none for unbound traffic.
	k.extra = append(k.extra, kroute{dst: pfx("::/0"), gw: ip("fe80::1"), gwZone: 11, index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE})
	if _, err := rt.DefaultRoute(ctx, IPv6); !errors.Is(err, ErrNoDefaultRoute) {
		t.Errorf("IPv6 default: %v", err)
	}
}

// crashed is a configurator of o that applied cfg and died: its routes
// and its record stay, its lock is gone.
func crashed(t *testing.T, k *fakeKernel, dir string, o Owner, cfg Config) {
	t.Helper()
	dead, err := newDarwin(o, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dead.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	_ = dead.lock.release() // the process died: the kernel drops the flock
	_ = dead.dir.Close()
}

// corrupt overwrites o's record with what writeRecord never writes, and
// returns its path and where it is set aside.
func corrupt(t *testing.T, dir string, o Owner) (path, aside string) {
	t.Helper()
	path = filepath.Join(dir, recordName(o))
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(dir, setAsideName(o, thisBoot(t)))
}

// wasSetAside checks that the record at path is gone and its content is
// at aside.
func wasSetAside(t *testing.T, path, aside string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the corrupt record is still there: %v", err)
	}
	if got, err := os.ReadFile(aside); err != nil || string(got) != "garbage\n" {
		t.Errorf("set aside: %q, %v", got, err)
	}
}

// A corrupt record of another owner that isn't running says nothing of
// which routes are its owner's: Survey and DefaultRoute still answer,
// the record is set aside, and the owner's routes count as foreign,
// which nothing removes.
func TestACorruptRecordOfAnotherOwnerIsSetAside(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	crashed(t, k, dir, OwnerOverlay, overlayConfig)
	overlays := k.snapshot()
	path, aside := corrupt(t, dir, OwnerOverlay)
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	s, err := rt.Survey(ctx)
	if err != nil {
		t.Fatalf("Survey over a corrupt record: %v", err)
	}
	wasSetAside(t, path, aside)
	if !slices.Equal(s.SetAside, []string{aside}) {
		t.Errorf("SetAside %v, want %v", s.SetAside, []string{aside})
	}
	if !slices.Contains(s.Held, pfx("100.64.0.0/11")) {
		t.Errorf("the overlay's route isn't foreign: held %v", s.Held)
	}
	if d, err := rt.DefaultRoute(ctx, IPv4); err != nil || d.String() != "0.0.0.0/0 via 192.168.1.1 dev en0" {
		t.Errorf("DefaultRoute: %v, %v", d, err)
	}
	// It stays reported for the boot.
	if s, err := rt.Survey(ctx); err != nil || !slices.Equal(s.SetAside, []string{aside}) {
		t.Errorf("the next Survey: %v, %v", s.SetAside, err)
	}
	if err := rt.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != overlays {
		t.Errorf("the overlay's routes changed:\n%s\nwant:\n%s", got, overlays)
	}
	// Its owner starts again, owning nothing.
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if len(ov.owned) != 0 {
		t.Errorf("the overlay owns %v", ov.owned)
	}
}

// A running owner's record is never moved from under it: a corrupt one
// holds nothing for the survey, and its owner rewrites it at its next
// change.
func TestACorruptRecordOfARunningOwnerIsLeftToIt(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	path, aside := corrupt(t, dir, OwnerOverlay)
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	s, err := rt.Survey(ctx)
	if err != nil {
		t.Fatalf("Survey over a corrupt record: %v", err)
	}
	if len(s.SetAside) != 0 {
		t.Errorf("SetAside %v", s.SetAside)
	}
	if _, err := os.Lstat(aside); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("set aside: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "garbage\n" {
		t.Errorf("the record: %q, %v", got, err)
	}
	if !slices.Contains(s.Held, pfx("100.64.0.0/11")) {
		t.Errorf("the overlay's route isn't foreign: held %v", s.Held)
	}
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if got := record(t, dir, OwnerOverlay); len(got) != 4 {
		t.Errorf("rewritten record %v", got)
	}
}

// A record that can't be read for another reason than its content stays
// an error: nothing is set aside on a failed read.
func TestAnUnreadableRecordFailsTheSurvey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0")
	}
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	path := filepath.Join(dir, recordName(OwnerOverlay))
	if err := writeRecord(openDir(t, dir), recordName(OwnerOverlay), thisBoot(t), map[rkey]bool{unscoped(pfx("10.0.0.0/8")): true}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Survey(ctx); err == nil || !strings.Contains(err.Error(), "overlay's route record") || !strings.Contains(err.Error(), path) {
		t.Errorf("Survey over an unreadable record: %v", err)
	}
	if _, err := rt.DefaultRoute(ctx, IPv4); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("DefaultRoute over an unreadable record: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, setAsideName(OwnerOverlay, thisBoot(t)))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("set aside: %v", err)
	}
}

// The owner's own corrupt record, at start: it is set aside, the
// configurator owns nothing, and the routes it named are foreign: an
// Apply conflicts with them and Close leaves them.
func TestTheOwnersCorruptRecordIsSetAsideAtStart(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	crashed(t, k, dir, OwnerRouteTable, routeTableConfig)
	before := k.snapshot()
	path, aside := corrupt(t, dir, OwnerRouteTable)
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	wasSetAside(t, path, aside)
	if len(c.owned) != 0 {
		t.Errorf("owns %v", c.owned)
	}
	s, err := c.Survey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.SetAside, []string{aside}) {
		t.Errorf("SetAside %v, want %v", s.SetAside, []string{aside})
	}
	for _, p := range []string{"::/1", "10.0.0.0/8", "203.0.113.9/32"} {
		if !slices.Contains(s.Held, pfx(p)) {
			t.Errorf("the leftover %s isn't foreign: held %v", p, s.Held)
		}
	}
	if err := c.Apply(ctx, routeTableConfig); !errors.Is(err, ErrConflict) {
		t.Errorf("Apply over the leftovers: %v, want ErrConflict", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("the leftovers changed:\n%s\nwant:\n%s", got, before)
	}
}

func TestRecordsRoundTrip(t *testing.T) {
	dir := tempDir(t)
	d, path, boot := openDir(t, dir), filepath.Join(dir, "x.routes"), thisBoot(t)
	want := map[rkey]bool{unscoped(pfx("0.0.0.0/1")): true, unscoped(pfx("2001:db8::/32")): true, unscoped(pfx("203.0.113.9/32")): true,
		{pfx("203.0.113.9/32"), 11}: true}
	if err := writeRecord(d, "x.routes", boot, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRecord(d, "x.routes", boot)
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("%v, %v", got, err)
	}
	if got, err := readRecord(d, "x.routes", "another boot"); err != nil || len(got) != 0 {
		t.Errorf("a record of another boot: %v, %v", got, err)
	}
	if err := writeRecord(d, "x.routes", boot, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an empty record stays: %v", err)
	}
	// A record without a boot line (empty, or comments only) is corrupt,
	// not empty, and every failure names the record and its reason.
	for name, tc := range map[string]struct{ data, want string }{
		"an unmasked prefix":               {"boot " + boot + "\n10.0.0.1/8\n", `bad line 1 after the boot line: not a masked prefix`},
		"a bad scope":                      {"boot " + boot + "\n10.0.0.1/32 scope en0\n", `bad line 1 after the boot line: bad scope`},
		"a data line before the boot line": {"10.0.0.0/8\n", `line 1, before the boot session, is no boot line`},
		"an empty record":                  {"", "no boot session"},
		"comments only":                    {recordHeader + "\n", "no boot session"},
	} {
		if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRecord(d, "x.routes", boot); !isCorrupt(err) || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A record that isn't a regular file is refused, not read.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(d, "x.routes", boot); !isCorrupt(err) || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a fifo: %v", err)
	}
	// Nor is a symlink followed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(d, "x.routes", boot); !isCorrupt(err) || !errors.Is(err, unix.ELOOP) {
		t.Errorf("a symlink: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// The temporary file is never followed out of the directory.
	target := filepath.Join(dir, "elsewhere")
	if err := os.Symlink(target, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(d, "x.routes", boot, want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the symlink's target was written: %v", err)
	}
}

// LockDir outlives a reboot, the routes don't: a record from an earlier
// boot owns nothing, so a route someone else tagged with our flag at one
// of its destinations stays foreign.
func TestARecordOfAnEarlierBootOwnsNothing(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	k.rs[pfx("10.0.0.0/8")] = kroute{dst: pfx("10.0.0.0/8"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | routeFlag}
	before := k.snapshot()
	if err := writeRecord(openDir(t, dir), recordName(OwnerRouteTable), "an-earlier-boot", map[rkey]bool{unscoped(pfx("10.0.0.0/8")): true}); err != nil {
		t.Fatal(err)
	}
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := c.Apply(context.Background(), Config{Routes: []Route{{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.1")}}}); !errors.Is(err, ErrConflict) {
		t.Errorf("Apply over it: %v, want ErrConflict", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("after Close:\n%s\nwant:\n%s", got, before)
	}
}

// The lock directory and everything above it must be this user's (or
// root's) alone, never a symlink: its record decides what gets deleted,
// and a directory someone else could rename would let a second
// configurator lock a fresh file.
func TestALockDirOthersControlIsRefused(t *testing.T) {
	t.Run("a parent others can write to", func(t *testing.T) {
		parent := tempDir(t)
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := newDarwin(OwnerRouteTable, newFakeKernel(), filepath.Join(parent, "netcfg")); err == nil {
			t.Fatal("a world-writable parent was accepted")
		}
	})
	t.Run("a grandparent others can write to", func(t *testing.T) {
		grand := tempDir(t)
		if err := os.Mkdir(filepath.Join(grand, "thinkpol"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(grand, 0o775); err != nil {
			t.Fatal(err)
		}
		if _, err := newDarwin(OwnerRouteTable, newFakeKernel(), filepath.Join(grand, "thinkpol", "netcfg")); err == nil {
			t.Fatal("a group-writable ancestor was accepted")
		}
	})
	t.Run("a symlinked directory", func(t *testing.T) {
		base := tempDir(t)
		if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(base, "netcfg")); err != nil {
			t.Fatal(err)
		}
		if _, err := newDarwin(OwnerRouteTable, newFakeKernel(), filepath.Join(base, "netcfg")); err == nil {
			t.Fatal("a symlink was followed")
		}
	})
}

// A route that only moves (a new gateway: another network) is changed in
// place, so traffic never falls through meanwhile; one that changes kind
// (into the TUN ↔ rejected) is deleted and added; a change the kernel
// refuses falls back to that.
func TestMovedRoutesChangeInPlace(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	cfg := Config{Routes: []Route{
		{Dst: pfx("0.0.0.0/1"), Interface: "utun7"},
		{Dst: pfx("10.0.0.0/8"), Gateway: ip("192.168.1.1")},
	}}
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Routes[1].Gateway = ip("192.168.1.254")
	n := k.count()
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if k.count()-n != 1 || k.changes != 1 {
		t.Errorf("a new gateway: %d changes, %d in place", k.count()-n, k.changes)
	}
	cfg.Routes[0] = Route{Dst: pfx("0.0.0.0/1"), Type: RouteUnreachable}
	n = k.count()
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if r, _ := k.route("0.0.0.0/1"); k.count()-n != 2 || r.flags&unix.RTF_REJECT == 0 {
		t.Errorf("into the TUN → rejected: %d changes, %v", k.count()-n, r)
	}
	k.failChange = true
	cfg.Routes[1].Gateway = ip("192.168.1.1")
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if r, _ := k.route("10.0.0.0/8"); r.gw != ip("192.168.1.1") {
		t.Errorf("fallback: %v", r)
	}
}

// When undoing a failed Apply can't remove a route it added, the route
// stays recorded, so the next Apply or Close still removes it.
func TestARouteUndoCantRemoveStaysRecorded(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	before := k.snapshot()
	added := 0
	k.failAdd = 3
	k.onAdd = func(kroute) {
		if added++; added == 4 {
			k.failDel = true // the undo's deletes fail
		}
	}
	if err := c.Apply(ctx, routeTableConfig); err == nil {
		t.Fatal("no error")
	}
	k.onAdd, k.failDel = nil, false
	if got := record(t, dir, OwnerRouteTable); len(got) != 3 {
		t.Fatalf("record after a failed undo: %v, want the 3 routes left", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("after Close:\n%s\nwant:\n%s", got, before)
	}
}

// A Close that fails still frees the owner's place; the next configurator
// takes over what is left from the record.
func TestAFailedCloseFreesTheOwnersPlace(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	before := k.snapshot()
	c, err := newDarwin(OwnerRouteTable, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	k.failDel = true
	if err := c.Close(); err == nil {
		t.Fatal("Close: no error")
	}
	k.failDel = false
	next, err := newDarwin(OwnerRouteTable, k, dir)
	if err != nil {
		t.Fatalf("after a failed Close: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("after the next Close:\n%s\nwant:\n%s", got, before)
	}
}

// A crash leaves both owners' records behind: the route table's routes
// stay in the kernel (its rejects outlive the utun), the overlay's go with
// the utun but stay recorded. A configurator that takes an owner's place
// and closes with nothing applied (Clear) empties its record either way,
// so a recorded destination never outlives the run that routed it.
func TestClosingWithNothingAppliedClearsACrashedRunsRecord(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	for _, o := range []struct {
		owner Owner
		cfg   Config
	}{{OwnerOverlay, overlayConfig}, {OwnerRouteTable, routeTableConfig}} {
		dead, err := newDarwin(o.owner, k, dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := dead.Apply(ctx, o.cfg); err != nil {
			t.Fatal(err)
		}
		_ = dead.lock.release() // the process died: the kernel drops the flock
		_ = dead.dir.Close()
	}
	// The utun goes with the process, and its routes with it.
	k.mu.Lock()
	delete(k.ifcs, "utun7")
	delete(k.addrsB, 20)
	for dst, r := range k.rs {
		if r.index == 20 || r.link == 20 {
			delete(k.rs, dst)
		}
	}
	k.mu.Unlock()
	if got := record(t, dir, OwnerOverlay); len(got) == 0 {
		t.Fatal("the crashed overlay recorded nothing")
	}

	for _, o := range []Owner{OwnerOverlay, OwnerRouteTable} {
		c, err := newDarwin(o, k, dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("%v: %v", o, err)
		}
		if got := record(t, dir, o); len(got) != 0 {
			t.Errorf("%v: record left %v", o, got)
		}
	}
	for _, r := range k.rs {
		if r.flags&routeFlag != 0 {
			t.Errorf("route %v left", r)
		}
	}
}

// A scoped route (RTF_IFSCOPE, only sockets bound to its interface use it)
// is owned like any other, by its destination and its interface: it lives
// beside an unscoped route to the same destination, someone else's scoped
// route there is a conflict, it follows its gateway in place, a crashed
// run's is cleared through the record, and Close removes it.
func TestScopedRoutesAreOwnedByTheirScopeToo(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	ctx := context.Background()
	before := k.snapshot()
	upstream := Route{Dst: pfx("203.0.113.53/32"), Gateway: ip("192.168.1.1"), Interface: "en0", Scope: "en0"}
	cfg := Config{Routes: []Route{
		{Dst: pfx("0.0.0.0/1"), Interface: "utun7"},
		{Dst: pfx("203.0.113.53/32"), Interface: "utun7"}, // the same destination, unscoped
		upstream,
	}}
	dead, err := newDarwin(OwnerRouteTable, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dead.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r, ok := k.scoped[rkey{pfx("203.0.113.53/32"), 11}]
	if !ok || r.flags&unix.RTF_IFSCOPE == 0 || r.flags&routeFlag == 0 || r.index != 11 || r.gw != ip("192.168.1.1") {
		t.Fatalf("scoped route %+v, %v", r, ok)
	}
	if got := record(t, dir, OwnerRouteTable); !slices.Contains(got, "203.0.113.53/32 scope 11") || !slices.Contains(got, "203.0.113.53/32") {
		t.Errorf("record %v", got)
	}
	// Re-applying changes nothing; a new gateway moves it in place.
	n := k.count()
	if err := dead.Apply(ctx, cfg); err != nil || k.count() != n {
		t.Errorf("re-apply: %v, %d changes", err, k.count()-n)
	}
	moved := cfg
	moved.Routes = slices.Clone(cfg.Routes)
	moved.Routes[2].Gateway = ip("192.168.1.254")
	if err := dead.Apply(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if r := k.scoped[rkey{pfx("203.0.113.53/32"), 11}]; r.gw != ip("192.168.1.254") || k.changes != 1 {
		t.Errorf("moved: %+v, %d changes in place", r, k.changes)
	}
	_ = dead.lock.release() // a crash
	_ = dead.dir.Close()

	// The next run's clear removes it through the record.
	c, err := newDarwin(OwnerRouteTable, k, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := k.snapshot(); got != before {
		t.Errorf("after the clear:\n%s\nwant:\n%s", got, before)
	}

	// Someone else's scoped route with that identity is a conflict, and
	// stays.
	k.extra = append(k.extra, kroute{dst: pfx("203.0.113.53/32"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_IFSCOPE | unix.RTF_STATIC})
	c2 := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := c2.Apply(ctx, Config{Routes: []Route{upstream}}); !errors.Is(err, ErrConflict) {
		t.Errorf("over another's scoped route: %v, want ErrConflict", err)
	}
	s, err := c2.Survey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.HeldScoped) != 2 || !slices.ContainsFunc(s.HeldScoped, func(r Route) bool { return r.Dst == pfx("203.0.113.53/32") && r.Scope == "en0" }) {
		t.Errorf("held scoped %v", s.HeldScoped)
	}
	for _, p := range s.Held {
		if p == pfx("203.0.113.53/32") {
			t.Error("a scoped route counted as an unscoped identity")
		}
	}
}

func TestAScopedRouteMustLeaveThroughItsScope(t *testing.T) {
	c := newTestConfigurator(t, newFakeKernel(), tempDir(t), OwnerRouteTable)
	for _, r := range []Route{
		{Dst: pfx("203.0.113.53/32"), Gateway: ip("192.168.1.1"), Interface: "utun7", Scope: "en0"},
		{Dst: pfx("203.0.113.53/32"), Type: RouteUnreachable, Scope: "en0"},
	} {
		if err := c.Apply(context.Background(), Config{Routes: []Route{r}}); err == nil {
			t.Errorf("%v: applied", r)
		}
	}
}
