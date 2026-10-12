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
)

// fakeKernel is a routing table and interfaces in memory, keeping the
// kernel's rules that matter here: one unscoped route per destination,
// clones and scoped routes beside them, addresses with one prefix length.
type fakeKernel struct {
	mu     sync.Mutex
	rs     map[netip.Prefix]kroute
	extra  []kroute // scoped and cloned routes
	ifcs   map[string]*kifc
	addrsB map[int][]netip.Prefix

	ops int // changes made
	// failAdd fails the add that would be change number failAdd+1.
	failAdd int
	// onAdd sees each route just before it is added.
	onAdd func(kroute)
}

func newFakeKernel() *fakeKernel {
	k := &fakeKernel{rs: map[netip.Prefix]kroute{}, ifcs: map[string]*kifc{}, addrsB: map[int][]netip.Prefix{}, failAdd: -1}
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
	if _, ok := k.rs[r.dst]; ok {
		return unix.EEXIST
	}
	if r.link != 0 && k.byIndex(r.link) == nil {
		return unix.ENXIO
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
	if _, ok := k.rs[r.dst]; !ok {
		return unix.ESRCH
	}
	delete(k.rs, r.dst)
	k.ops++
	return nil
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
	for _, l := range k.ifcs {
		lines = append(lines, fmt.Sprintf("%s mtu=%d up=%v addrs=%v", l.name, l.mtu, l.up, k.addrsB[l.index]))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func (k *fakeKernel) changes() int {
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

func record(t *testing.T, dir string, o Owner) []string {
	t.Helper()
	rec, err := readRecord(recordPath(dir, o))
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
	dir := t.TempDir()
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
	for _, dst := range []string{"100.64.0.0/10", "fd12:3456:789a::/48"} {
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
	if got := record(t, dir, OwnerOverlay); !slices.Equal(got, []string{"100.64.0.0/10", "fd12:3456:789a::/48"}) {
		t.Errorf("overlay's record %v", got)
	}
	if got := record(t, dir, OwnerRouteTable); len(got) != len(routeTableConfig.Routes) {
		t.Errorf("route table's record %v", got)
	}
	l := k.ifcs["utun7"]
	if l.mtu != 1328 || !l.up || len(k.addrsB[20]) != 2 {
		t.Errorf("utun7: %+v %v", *l, k.addrsB[20])
	}

	n := k.changes()
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if err := rt.Apply(ctx, routeTableConfig); err != nil {
		t.Fatal(err)
	}
	if k.changes() != n {
		t.Errorf("re-applying made %d changes", k.changes()-n)
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
		if _, err := os.Stat(recordPath(dir, o)); !errors.Is(err, os.ErrNotExist) {
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
	k, dir := newFakeKernel(), t.TempDir()
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
	k, dir := newFakeKernel(), t.TempDir()
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
	k, dir := newFakeKernel(), t.TempDir()
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	rt := newTestConfigurator(t, k, dir, OwnerRouteTable)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	clash := Config{Routes: []Route{{Dst: pfx("100.64.0.0/10"), Interface: "utun7"}}}
	if err := rt.Apply(ctx, clash); !errors.Is(err, ErrConflict) {
		t.Fatalf("the overlay's route: %v, want ErrConflict", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.route("100.64.0.0/10"); !ok {
		t.Fatal("the route table's Close removed the overlay's route")
	}
	if got := record(t, dir, OwnerOverlay); len(got) != 2 {
		t.Errorf("overlay's record %v", got)
	}
}

// A configurator that died without Close leaves routes and a record; its
// successor takes over what the new config wants and removes the rest.
func TestTakesOverRoutesLeftByACrash(t *testing.T) {
	k, dir := newFakeKernel(), t.TempDir()
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
	n := k.changes()
	if err := c.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	// Kept: the four split routes; moved (deleted, added): one; removed:
	// two.
	if got := k.changes() - n; got != 2+2 {
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
		k, dir := newFakeKernel(), t.TempDir()
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
	k, dir := newFakeKernel(), t.TempDir()
	c := newTestConfigurator(t, k, dir, OwnerRouteTable)
	var missing []string
	k.onAdd = func(r kroute) {
		rec, _ := readRecord(recordPath(dir, OwnerRouteTable))
		if !rec[r.dst] {
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
	k, dir := newFakeKernel(), t.TempDir()
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
	delete(k.rs, pfx("100.64.0.0/10"))
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
	k, dir := newFakeKernel(), t.TempDir()
	ctx := context.Background()
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	delete(k.ifcs, "utun7")
	delete(k.addrsB, 20)
	delete(k.rs, pfx("100.64.0.0/10"))
	delete(k.rs, pfx("fd12:3456:789a::/48"))
	k.ifcs["utun7"] = &kifc{name: "utun7", index: 21, mtu: 1500, p2p: true}
	k.mu.Unlock()
	if err := ov.Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	if r, ok := k.route("100.64.0.0/10"); !ok || r.link != 21 {
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
	k, dir := newFakeKernel(), t.TempDir()
	k.rs[pfx("100.64.0.0/10")] = kroute{dst: pfx("100.64.0.0/10"), link: 20, index: 20, flags: unix.RTF_UP | unix.RTF_CLONING}
	ov := newTestConfigurator(t, k, dir, OwnerOverlay)
	if err := ov.Apply(context.Background(), overlayConfig); err != nil {
		t.Fatal(err)
	}
	if got := record(t, dir, OwnerOverlay); !slices.Equal(got, []string{"fd12:3456:789a::/48"}) {
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
	k, dir := newFakeKernel(), t.TempDir()
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
	k, dir := newFakeKernel(), t.TempDir()
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

func TestRecordsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.routes")
	want := map[netip.Prefix]bool{pfx("0.0.0.0/1"): true, pfx("2001:db8::/32"): true, pfx("203.0.113.9/32"): true}
	if err := writeRecord(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRecord(path)
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("%v, %v", got, err)
	}
	if err := writeRecord(path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an empty record stays: %v", err)
	}
	if err := os.WriteFile(path, []byte("10.0.0.1/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(path); err == nil {
		t.Error("an unmasked prefix was read")
	}
}

// The lock directory must be this user's alone: its record decides what
// gets deleted.
func TestALockDirOthersCanWriteIsRefused(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := newDarwin(OwnerRouteTable, newFakeKernel(), filepath.Join(parent, "netcfg")); err == nil {
		t.Fatal("a world-writable parent was accepted")
	}
}
