package dns

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Unprotected sorts a Problem: an untagged error is unprotected (a
// System that reports a problem it doesn't name fails closed), only nil
// and ErrUpstreamsStale are not.
func TestUnprotectedSortsProblems(t *testing.T) {
	if Unprotected(nil) {
		t.Error("nil is unprotected")
	}
	if !Unprotected(ErrUnprotected) || !Unprotected(fmt.Errorf("%w: rewrite failed", ErrUnprotected)) {
		t.Error("an ErrUnprotected problem is not unprotected")
	}
	if Unprotected(fmt.Errorf("%w: read failed", ErrUpstreamsStale)) {
		t.Error("stale upstreams are unprotected")
	}
	if !Unprotected(errors.New("the store is unreadable")) {
		t.Error("an untagged problem reads as protected")
	}
	if !Unprotected(fmt.Errorf("dns: %w; %w", nil, nil)) {
		t.Error("a problem wrapping only nils reads as protected")
	}
	if !Unprotected(taggedUnprotected{fmt.Errorf("%w: read failed", ErrUpstreamsStale)}) {
		t.Error("a wrapper that is ErrUnprotected around a stale problem reads as protected")
	}
	stale := fmt.Errorf("%w: read failed", ErrUpstreamsStale)
	if !Unprotected(errors.Join(errors.New("the store is unreadable"), stale)) {
		t.Error("an untagged problem joined with a stale one reads as protected")
	}
	if !Unprotected(errors.Join(stale, fmt.Errorf("%w: rewrite failed", ErrUnprotected))) {
		t.Error("an unprotected problem joined with a stale one reads as protected")
	}
	if !Unprotected(fmt.Errorf("checking: %w", errors.Join(stale, errors.New("the store is unreadable")))) {
		t.Error("a wrapped join with an untagged part reads as protected")
	}
	if Unprotected(errors.Join(stale, fmt.Errorf("again: %w", ErrUpstreamsStale))) {
		t.Error("two stale problems are unprotected")
	}
	if Unprotected(errors.Join(nil, nil)) {
		t.Error("a join of nothing is unprotected")
	}
}

var testSystem = SystemConfig{
	Servers: []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd12:3456:789a::2")},
	Search:  []string{"home.internal"},
}

const isp = "# from DHCP\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch lan\noptions timeout:1 attempts:2\n"

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeFileAtomic puts content at a file the way the product's own
// writers do (replace with writeNew: a new file, then a rename), so a
// watcher reading the file never sees a half-written intermediate state.
// Every test write to a file a watcher reads goes through it; writes to
// files nothing watches may write directly.
func writeFileAtomic(t *testing.T, path, content string) {
	t.Helper()
	err := replace(path, func(tmp string) error { return writeNew(tmp, []byte(content)) })
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolvConfIsReplacedAndRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	got := readString(t, path)
	if servers := nameservers([]byte(got)); !slices.Equal(servers, testSystem.Servers) {
		t.Errorf("nameservers %v in\n%s", servers, got)
	}
	for _, want := range []string{"\nsearch home.internal\n", "\noptions timeout:1 attempts:2\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	// The OS's own search domains are out while the node runs: a failed
	// name retried under one would go wherever the rules send that domain.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "search") && strings.Contains(line, "lan") {
			t.Errorf("the original search domain stays: %q", line)
		}
	}
	// What the OS used before stays readable while the node runs.
	if orig, err := originalResolvConf(path); err != nil || string(orig) != isp {
		t.Errorf("original %q, %v", orig, err)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s\nwant\n%s", got, isp)
	}
	if err := r.Restore(); err != nil {
		t.Errorf("second Restore: %v", err)
	}
}

// After a crash the managed file is still there; the next run keeps the
// original it holds, and restoring puts that back.
func TestALeftoverResolvConfKeepsItsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, render(testSystem, []byte(isp), ""), 0o644); err != nil {
		t.Fatal(err)
	}
	next := testSystem
	next.Servers = next.Servers[:1]
	r, err := setResolvConf(path, "", next)
	if err != nil {
		t.Fatal(err)
	}
	if servers := nameservers([]byte(readString(t, path))); !slices.Equal(servers, next.Servers) {
		t.Errorf("nameservers %v", servers)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
}

func TestASymlinkedResolvConfComesBackAsTheLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed-elsewhere.conf")
	if err := os.WriteFile(target, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("while running: %v, %v", fi.Mode(), err)
	}
	if got := readString(t, target); got != isp {
		t.Error("the link's target was changed")
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(path); err != nil || link != target {
		t.Errorf("restored link %q, %v", link, err)
	}
}

// Another program rewriting resolv.conf while the node runs (a DHCP
// client) would send names around the resolver: the file is taken back,
// with the new content as the original.
func TestAResolvConfRewrittenMeanwhileIsTakenBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	upstreams := make(chan []netip.Addr, 1)
	r.mu.Lock()
	r.cfg.Upstreams = func(a []netip.Addr) { upstreams <- a }
	r.mu.Unlock()
	renewed := "nameserver 192.0.2.99\n"
	writeFileAtomic(t, path, renewed)
	deadline := time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case got := <-upstreams:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.99")}) {
			t.Errorf("told the OS's resolvers are %v", got)
		}
	case <-time.After(time.Second):
		t.Error("not told the OS's resolvers changed")
	}
	if err := r.Problem(); err != nil {
		t.Errorf("problem %v", err)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != renewed {
		t.Errorf("restored\n%s\nwant the renewed one", got)
	}
}

func TestARewrittenResolvConfFiltersStubUpstreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	uplink := filepath.Join(dir, "uplink.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, uplink, testSystem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	upstreams := make(chan []netip.Addr, 2)
	var lastUpstreams []netip.Addr
	r.mu.Lock()
	r.cfg.Upstreams = func(a []netip.Addr) {
		lastUpstreams = a
		upstreams <- a
	}
	r.mu.Unlock()

	mixed := "nameserver 127.0.0.53\nnameserver 192.0.2.88\n"
	writeFileAtomic(t, path, mixed)
	deadline := time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case got := <-upstreams:
		want := []netip.Addr{netip.MustParseAddr("192.0.2.88")}
		if !slices.Equal(got, want) {
			t.Errorf("mixed stub and real: upstreams %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("mixed stub and real: not told upstreams changed")
	}

	writeFileAtomic(t, uplink, "nameserver 198.51.100.53\n")
	stubOnly := "nameserver 127.0.0.53\n"
	writeFileAtomic(t, path, stubOnly)
	deadline = time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("stub-only rewrite not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case got := <-upstreams:
		want := []netip.Addr{netip.MustParseAddr("198.51.100.53")}
		if !slices.Equal(got, want) {
			t.Errorf("stub-only with uplink: upstreams %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("stub-only with uplink: not told upstreams changed")
	}

	if err := os.Remove(uplink); err != nil {
		t.Fatal(err)
	}
	stubOnlyOther := "nameserver 127.0.0.54\noptions edns0\n"
	writeFileAtomic(t, path, stubOnlyOther)
	deadline = time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("stub-only without uplink not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	wantKept := []netip.Addr{netip.MustParseAddr("198.51.100.53")}
	select {
	case got := <-upstreams:
		t.Errorf("stub-only without uplink: upstreams %v, want previous kept without callback", got)
	case <-time.After(300 * time.Millisecond):
	}
	if !slices.Equal(lastUpstreams, wantKept) {
		t.Errorf("stub-only without uplink: upstreams %v, want previous %v kept", lastUpstreams, wantKept)
	}
}

// Behind the stub, an unreadable uplink file is a failed read: a failed
// first read over a stub resolv.conf stays stale, and the uplink file
// appearing is the first good read and is told.
func TestResolvConfAFailedFirstReadBehindTheStubWaitsForTheUplink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	uplink := filepath.Join(dir, "uplink.conf") // missing: behind the stub, the read fails
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, uplink, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a read behind a stub with no uplink: %v", p)
	}
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after another failed read: %v", p)
	}
	writeFileAtomic(t, uplink, "nameserver 198.51.100.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
			t.Errorf("told %v, want 198.51.100.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}

// A resolv.conf that is a dangling link at setup is managed with an
// unknown original; while untold, the link's target is read on every
// tick, so its appearing is the first good read and is told, and the
// staleness clears.
func TestResolvConfAFailedFirstReadOverADanglingLinkReadsItsTargetWhenItAppears(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink("real.conf", path); err != nil { // a relative link
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a read of a dangling link: %v", p)
	}
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after another failed read: %v", p)
	}
	writeFileAtomic(t, target, "nameserver 192.0.2.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("told %v, want 192.0.2.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
	// Restore puts the link back, whatever its target holds now.
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(path); err != nil || link != "real.conf" {
		t.Errorf("restored link %q, %v", link, err)
	}
}

// A link whose target reads back as the managed file (a self-link, or a
// loop through another link): reading it reads the node's own file,
// which is no original, so the read is skipped and the staleness stays.
func TestResolvConfALinkToTheManagedFileItselfIsNotAGoodRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		links func(dir string) error
	}{
		{"self", func(dir string) error {
			return os.Symlink("resolv.conf", filepath.Join(dir, "resolv.conf"))
		}},
		{"through another link", func(dir string) error {
			if err := os.Mkdir(filepath.Join(dir, "run"), 0o755); err != nil {
				return err
			}
			if err := os.Symlink("../resolv.conf", filepath.Join(dir, "run", "resolv.conf")); err != nil {
				return err
			}
			return os.Symlink("run/resolv.conf", filepath.Join(dir, "resolv.conf"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "resolv.conf")
			if err := tc.links(dir); err != nil { // a loop: dangling at setup
				t.Fatal(err)
			}
			told := make(chan []netip.Addr, 8)
			c := testSystem
			c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
			r, err := setResolvConf(path, "", c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Restore() })
			if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
				t.Errorf("problem after a read of the link: %v", p)
			}
			applyOnce(t, r)
			toldNothing(t, told)
			if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
				t.Errorf("problem after a tick over the link: %v", p)
			}
		})
	}
}

// While untold, a read that works but loses (a link target appearing
// with only resolved's stub in it, the uplink file still missing) warns
// nothing: the agent already said the resolvers are unknown, and the
// staleness says it until a read answers.
func TestResolvConfWhileUntoldAStubTargetWithoutUplinkWarnsNothing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink("real.conf", path); err != nil { // dangling at setup
		t.Fatal(err)
	}
	var log bytes.Buffer
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	uplink := filepath.Join(dir, "uplink.conf") // missing until the last phase
	r, err := setResolvConf(path, uplink, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after a read of a dangling link: %v", p)
	}
	// The target appears, naming only resolved's stub: a read that
	// answers nothing, not a good one.
	writeFileAtomic(t, target, "nameserver 127.0.0.53\n")
	applyOnce(t, r)
	if strings.Contains(log.String(), "no upstream to ask") {
		t.Errorf("warned while untold:\n%s", log.String())
	}
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after a stub target with no uplink: %v", p)
	}
	// The uplink file appears: the first good read, told.
	writeFileAtomic(t, uplink, "nameserver 198.51.100.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
			t.Errorf("told %v, want 198.51.100.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
}

// An existing but empty uplink file is a failed read, not a good read
// with no upstreams: a zero-byte read cannot be told from a half-written
// file. On this path a false "no upstreams" told as the first good read
// clears the staleness for good — a later read of the same resolv.conf
// tells nothing, however the uplink file reads — while a failed read
// only waits for the next tick.
func TestResolvConfAnEmptyUplinkFileIsAFailedRead(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink("real.conf", path); err != nil { // dangling at setup
		t.Fatal(err)
	}
	uplink := filepath.Join(dir, "uplink.conf") // missing until the last phase
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, uplink, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	// The target appears, naming only resolved's stub: behind the stub,
	// the missing uplink is a failed read.
	writeFileAtomic(t, target, "nameserver 127.0.0.53\n")
	applyOnce(t, r)
	toldNothing(t, told)
	// The uplink file is there but empty, as a file caught mid-write
	// reads: no answer yet.
	writeFileAtomic(t, uplink, "")
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after an empty uplink file: %v", p)
	}
	// Written, the uplink file is the first good read, told.
	writeFileAtomic(t, uplink, "nameserver 198.51.100.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
			t.Errorf("told %v, want 198.51.100.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}

// The default Linux path (Upstreams set, UpstreamsUnknown false): a
// setup tells nothing and reports nothing stale, and after a first apply
// that wrote nothing, a real change is told.
func TestResolvConfTheDefaultPathTellsNothingUntilAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, render(testSystem, []byte(isp), ""), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	toldNothing(t, told)
	if p := r.Problem(); p != nil {
		t.Errorf("problem at setup: %v", p)
	}
	applyOnce(t, r) // the first apply wrote nothing: still nothing
	toldNothing(t, told)
	writeFileAtomic(t, path, "nameserver 192.0.2.99\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.99")}) {
			t.Errorf("told %v, want 192.0.2.99", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the change")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a change: %v", p)
	}
}

// An original without a trailing newline: the managed copy adds one, and
// the next tick must not read the same original as changed because of it.
func TestResolvConfAnOriginalWithoutATrailingNewlineIsNotAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.53"), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	toldNothing(t, told)
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a same-original read: %v", p)
	}
}

func TestSystemUpstreams(t *testing.T) {
	dir := t.TempDir()
	etc, uplink := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "uplink.conf")
	own := testSystem.Servers
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := func(what string, want ...string) {
		t.Helper()
		got, err := upstreamsFrom(etc, uplink, own)
		if err != nil {
			t.Fatal(err)
		}
		var gs []string
		for _, a := range got {
			gs = append(gs, a.String())
		}
		if !slices.Equal(gs, want) {
			t.Errorf("%s: %v, want %v", what, gs, want)
		}
	}
	write(etc, isp)
	check("a plain resolv.conf", "192.0.2.53", "2001:db8::53")
	write(etc, string(render(testSystem, []byte(isp), "")))
	check("while the node manages it", "192.0.2.53", "2001:db8::53")
	write(etc, "nameserver 127.0.0.53\noptions edns0 trust-ad\n")
	write(uplink, "nameserver 198.51.100.53\nnameserver 100.64.0.2\n")
	check("through systemd-resolved, without the node's own", "198.51.100.53")
	// An existing but empty uplink file is a failed read, not a good
	// read with no upstreams: SystemUpstreams then errors, so a startup
	// that reads an empty uplink (caught mid-write or truncated) reports
	// the resolvers unknown instead of answering none.
	write(etc, "nameserver 127.0.0.53\n")
	write(uplink, "")
	if _, err := upstreamsFrom(etc, uplink, own); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("a stub resolv.conf with an empty uplink: %v, want the failed read", err)
	}
	if err := os.Remove(uplink); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamsFrom(etc, uplink, own); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("a stub resolv.conf with an unreadable uplink: %v, want the read's cause", err)
	}
}

// A new configuration goes over the old one; the original stays.
func TestResolvConfUpdatesInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	next := SystemConfig{Servers: testSystem.Servers[:1], Search: []string{"other.internal"}}
	if err := r.Update(next); err != nil {
		t.Fatal(err)
	}
	got := readString(t, path)
	if !slices.Equal(nameservers([]byte(got)), next.Servers) || !strings.Contains(got, "\nsearch other.internal\n") {
		t.Errorf("after Update:\n%s", got)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
}

// What a crash left is put back when the node starts, whatever it does
// next; anything else is left alone.
func TestALeftoverIsRestoredAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, render(testSystem, []byte(isp), ""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreResolvConf(path); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
	if err := restoreResolvConf(path); err != nil || readString(t, path) != isp {
		t.Errorf("a file the node doesn't manage changed: %v", err)
	}
}

// taggedUnprotected is ErrUnprotected itself, whatever it wraps.
type taggedUnprotected struct{ inner error }

func (e taggedUnprotected) Error() string        { return "unprotected: " + e.inner.Error() }
func (e taggedUnprotected) Unwrap() error        { return e.inner }
func (e taggedUnprotected) Is(target error) bool { return target == ErrUnprotected }

// applyOnce runs one check as the watcher would, telling what apply
// returned.
func applyOnce(t *testing.T, r *resolvConf) {
	t.Helper()
	r.mu.Lock()
	tell, _ := r.apply()
	r.mu.Unlock()
	if tell != nil {
		tell()
	}
}

// toldNothing says nothing was told to the callback yet: it waits a
// while first, so a tell that is only about to happen (the watch
// goroutine's, at setup) is still caught.
func toldNothing(t *testing.T, told <-chan []netip.Addr) {
	t.Helper()
	select {
	case got := <-told:
		t.Fatalf("told %v", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// The caller's own read of the OS's resolvers failed (UpstreamsUnknown):
// a resolv.conf taken over while the file was missing reports them stale
// and tells the first good read, though nothing changed from the file's
// point of view.
func TestResolvConfAFailedFirstReadIsStaleUntilAGoodReadTellsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf") // missing: the first read fails
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a failed first read: %v", p)
	}
	// A later read that still fails keeps it stale and tells nothing.
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after another failed read: %v", p)
	}
	// The file appears (a DHCP client wrote it): the read works, and the
	// first one is told whether or not it changed.
	writeFileAtomic(t, path, "nameserver 192.0.2.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("told %v, want 192.0.2.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
	// Nothing further: an unchanged read tells nothing.
	applyOnce(t, r)
	toldNothing(t, told)
}

// The first good read is told whatever it found: a resolv.conf with no
// nameservers tells an empty answer and clears the staleness all the
// same.
func TestResolvConfAFailedFirstReadThenEmptyTellsAnEmptyAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf") // missing: the first read fails
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after a failed first read: %v", p)
	}
	writeFileAtomic(t, path, "options timeout:1\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if got != nil {
			t.Errorf("told %v, want one empty answer", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}

// When the file is readable at setup, its read is the first good one: it
// is told at once, without waiting for the file to change.
func TestResolvConfTheFirstGoodReadAtSetupIsToldAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	select {
	case got := <-told:
		want := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
		if !slices.Equal(got, want) {
			t.Errorf("told %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the read at setup")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}

// Without Upstreams to tell, UpstreamsUnknown is nothing to report: a
// failed first read is no stale problem.
func TestResolvConfUpstreamsUnknownWithoutUpstreamsIsNeverStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf") // missing: the read fails
	c := testSystem
	c.UpstreamsUnknown = true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); p != nil {
		t.Errorf("problem without Upstreams: %v", p)
	}
}

// A resolv.conf that is a symlink to a file that isn't there is no good
// read: a failed first read over one stays stale and tells nothing, and
// the first good read of a real file is told.
func TestResolvConfAFailedFirstReadOverADanglingSymlinkStaysStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(filepath.Join(dir, "gone"), path); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := setResolvConf(path, "", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a read of a dangling link: %v", p)
	}
	applyOnce(t, r) // the managed file keeps an unknown original
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after another failed read: %v", p)
	}
	writeFileAtomic(t, path, "nameserver 192.0.2.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("told %v, want 192.0.2.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}
