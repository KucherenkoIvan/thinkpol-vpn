package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is a dynamic store in memory.
type fakeStore struct {
	mu      sync.Mutex
	kv      map[string]dict
	sets    int
	setsLog []string
	// keysErrs fails keys for its patterns; getErrs fails get for its keys.
	keysErrs map[string]error
	getErrs  map[string]error
}

func (f *fakeStore) keys(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.keysErrs[pattern]; err != nil {
		return nil, err
	}
	re := regexp.MustCompile("^" + pattern + "$")
	var out []string
	for k := range f.kv {
		if re.MatchString(k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (f *fakeStore) get(key string) (dict, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErrs[key]; err != nil {
		return dict{}, false, err
	}
	d, ok := f.kv[key]
	return clone(d), ok, nil
}

func (f *fakeStore) set(key string, d dict) error {
	if _, err := setScript(key, d); err != nil { // what scutil would refuse
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv[key] = clone(d)
	f.sets++
	f.setsLog = append(f.setsLog, "set "+key)
	return nil
}

func (f *fakeStore) remove(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.kv, key)
	f.setsLog = append(f.setsLog, "remove "+key)
	return nil
}

func (f *fakeStore) put(key string, d dict) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv[key] = d
}

func clone(d dict) dict {
	c := newDict()
	c.opaque = d.opaque
	for k, v := range d.strs {
		c.strs[k] = v
	}
	for k, v := range d.arrays {
		c.arrays[k] = slices.Clone(v)
	}
	return c
}

func (f *fakeStore) dump() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var lines []string
	for _, k := range sortedKeys(f.kv) {
		d := f.kv[k]
		lines = append(lines, fmt.Sprintf("%s %v %v %v", k, d.strs, d.arrays, d.opaque))
	}
	return strings.Join(lines, "\n")
}

func dnsDict(servers []string, extra map[string]string) dict {
	d := newDict()
	d.arrays["ServerAddresses"] = servers
	for k, v := range extra {
		d.strs[k] = v
	}
	return d
}

// wifiService sorts before resolverKey so restore order can't pass on plain
// sorted keys alone.
const wifiService = "0B2D6C1E-0000-4000-8000-000000000001"

// aMac is the store of a Mac with Wi-Fi (primary, DHCP's DNS),
// Ethernet (B, active, DNS set by hand), an inactive service with DNS set
// by hand (C) and another VPN's per-domain resolver (D).
func aMac(t *testing.T) *fakeStore {
	t.Helper()
	resolverDir = t.TempDir() // no /etc/resolver files
	f := &fakeStore{kv: map[string]dict{}}
	global := newDict()
	global.strs["PrimaryService"] = wifiService
	f.put("State:/Network/Global/IPv4", global)
	ipv4 := newDict()
	ipv4.arrays["Addresses"] = []string{"192.168.1.20"}
	f.put("State:/Network/Service/"+wifiService+"/IPv4", ipv4)
	f.put("State:/Network/Service/B/IPv4", ipv4)
	f.put("State:/Network/Service/"+wifiService+"/DNS", dnsDict([]string{"192.168.1.1"}, map[string]string{"DomainName": "lan"}))
	f.put("Setup:/Network/Service/B/DNS", dnsDict([]string{"9.9.9.9"}, nil))
	f.put("Setup:/Network/Service/C/DNS", dnsDict([]string{"8.8.8.8"}, nil))
	vpn := dnsDict([]string{"10.1.1.1"}, map[string]string{"ServerPort": "53"})
	vpn.arrays["SupplementalMatchDomains"] = []string{"corp.example"}
	f.put("State:/Network/Service/D/DNS", vpn)
	return f
}

var nodeConfig = SystemConfig{
	Servers: []netip.Addr{netip.MustParseAddr("100.64.0.7"), netip.MustParseAddr("fd12:3456:789a::7")},
	Search:  []string{"home.internal"},
}

func overridden(t *testing.T, f *fakeStore, key string) {
	t.Helper()
	d, ok, _ := f.get(key)
	if !ok || !isOverride(d) || !slices.Equal(d.array("ServerAddresses"), []string{"100.64.0.7", "fd12:3456:789a::7"}) ||
		!slices.Equal(d.array("SearchDomains"), []string{"home.internal"}) {
		t.Errorf("%s: %+v, ok %v; want the node's resolver", key, d, ok)
	}
}

// ownResolver checks the node's own service: an unscoped default resolver
// (an empty supplemental match domain, no interface), asked first.
func ownResolver(t *testing.T, f *fakeStore, servers ...string) {
	t.Helper()
	d, ok, _ := f.get(resolverKey)
	if !ok || !isOverride(d) || !slices.Equal(d.array("ServerAddresses"), servers) ||
		!slices.Equal(d.array("SupplementalMatchDomains"), []string{""}) || d.strs["SearchOrder"] != "100000" {
		t.Errorf("the node's service: %+v, ok %v", d, ok)
	}
	// An IPv4 or IPv6 entity would give it an interface: a scoped
	// resolver, which mDNSResponder asks bound to that interface.
	id := strings.TrimSuffix(strings.TrimPrefix(resolverKey, "State:/Network/Service/"), "/DNS")
	if keys, _ := f.keys("(State|Setup):/Network/Service/" + id + "/.*"); len(keys) != 1 {
		t.Errorf("the node's service has %v", keys)
	}
}

func TestDNSApplyPublishesTheResolverLast(t *testing.T) {
	f := aMac(t)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resolverSet := -1
	for i, op := range f.setsLog {
		if op == "set "+resolverKey {
			resolverSet = i
		}
	}
	if resolverSet < 0 {
		t.Fatal("the supplemental resolver was never written")
	}
	for i, op := range f.setsLog {
		if strings.HasPrefix(op, "set State:/Network/Service/") && strings.HasSuffix(op, "/DNS") && op != "set "+resolverKey && i >= resolverSet {
			t.Fatalf("apply order: %q at %d is not before the resolver at %d\n%v", op, i, resolverSet, f.setsLog)
		}
	}
	f.setsLog = nil
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	resolverOp := -1
	for i, op := range f.setsLog {
		if strings.Contains(op, resolverKey) {
			resolverOp = i
			break
		}
	}
	if resolverOp < 0 {
		t.Fatal("restore never touched the supplemental resolver")
	}
	for i, op := range f.setsLog {
		if !strings.HasPrefix(op, "set State:/Network/Service/") || !strings.HasSuffix(op, "/DNS") || strings.Contains(op, "8E3C1F52") {
			continue
		}
		if i < resolverOp {
			t.Fatalf("restore order: %q at %d is before the resolver at %d\n%v", op, i, resolverOp, f.setsLog)
		}
	}
}

func TestEveryActiveServiceResolvesThroughTheNodeUntilRestore(t *testing.T) {
	f := aMac(t)
	before := f.dump()
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ownResolver(t, f, "100.64.0.7", "fd12:3456:789a::7")
	for _, k := range []string{"State:/Network/Service/" + wifiService + "/DNS", "State:/Network/Service/B/DNS"} {
		overridden(t, f, k)
	}
	// Setup: keys are the preferences' copy: never written.
	for _, k := range []string{"Setup:/Network/Service/B/DNS", "Setup:/Network/Service/C/DNS", "State:/Network/Service/D/DNS"} {
		if d, _, _ := f.get(k); isOverride(d) {
			t.Errorf("%s overridden", k)
		}
	}
	// The other VPN's domain still goes to its resolver: not protected.
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "1 domains") {
		t.Errorf("problem: %v", err)
	}
	// The OS's own resolvers are the originals, not the node's.
	if got, err := systemUpstreams(f, nil); err != nil || fmt.Sprint(got) != "[192.168.1.1]" {
		t.Errorf("upstreams: %v, %v", got, err)
	}
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := f.dump(); got != before {
		t.Errorf("after Restore:\n%s\nwant:\n%s", got, before)
	}
}

// A node that died connected left the overrides; its next start puts the
// originals back from the store itself.
func TestACrashedNodesOverridesAreRestoredAtStart(t *testing.T) {
	f := aMac(t)
	before := f.dump()
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.stopped = true // it died: no Restore
	close(s.stop)
	s.mu.Unlock()
	if err := restoreBackup(f); err != nil {
		t.Fatal(err)
	}
	if got := f.dump(); got != before {
		t.Errorf("after a restart:\n%s\nwant:\n%s", got, before)
	}
	if err := restoreBackup(f); err != nil { // nothing left: a no-op
		t.Fatal(err)
	}
}

// DHCP renewing on another network publishes the system's DNS over the
// override: the check overrides it again, takes the new servers as the
// original, and tells the resolver its new domestic upstreams.
func TestTheSystemsRepublishedConfigurationIsOverriddenAgain(t *testing.T) {
	f := aMac(t)
	var told [][]netip.Addr
	c := nodeConfig
	c.Upstreams = func(a []netip.Addr) { told = append(told, a) }
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.put("State:/Network/Service/"+wifiService+"/DNS", dnsDict([]string{"10.0.0.1"}, nil))
	s.check()
	overridden(t, f, "State:/Network/Service/"+wifiService+"/DNS")
	if len(told) != 1 || fmt.Sprint(told[0]) != "[10.0.0.1]" {
		t.Errorf("told %v", told)
	}
	// A new service (Ethernet plugged in) is overridden too.
	ipv4 := newDict()
	f.put("State:/Network/Service/E/IPv4", ipv4)
	s.check()
	overridden(t, f, "State:/Network/Service/E/DNS")
	// Restore puts back what the system published last, and removes what
	// it never had.
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := f.get("State:/Network/Service/" + wifiService + "/DNS"); fmt.Sprint(d.array("ServerAddresses")) != "[10.0.0.1]" || isOverride(d) {
		t.Errorf("A after Restore: %+v", d)
	}
	if _, ok, _ := f.get("State:/Network/Service/E/DNS"); ok {
		t.Error("E's DNS key stays")
	}
}

// What the system publishes after the node's last check is the system's:
// Restore leaves it.
func TestRestoreLeavesWhatTheSystemPublishedSince(t *testing.T) {
	f := aMac(t)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.put("State:/Network/Service/"+wifiService+"/DNS", dnsDict([]string{"10.0.0.1"}, nil))
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := f.get("State:/Network/Service/" + wifiService + "/DNS"); fmt.Sprint(d.array("ServerAddresses")) != "[10.0.0.1]" {
		t.Errorf("A after Restore: %+v", d)
	}
}

func TestUpdatePointsEveryServiceAtTheNewServers(t *testing.T) {
	f := aMac(t)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	c := nodeConfig
	c.Servers = c.Servers[:1]
	if err := s.Update(c); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"State:/Network/Service/" + wifiService + "/DNS", "State:/Network/Service/B/DNS", resolverKey} {
		if d, _, _ := f.get(k); fmt.Sprint(d.array("ServerAddresses")) != "[100.64.0.7]" {
			t.Errorf("%s: %+v", k, d)
		}
	}
	// Re-checking with nothing changed writes nothing.
	n := f.sets
	s.check()
	if f.sets != n {
		t.Errorf("%d writes for nothing", f.sets-n)
	}
}

// An original scutil can't set back as it was (nested values, values
// with spaces) is overridden all the same, failing closed, and put back by
// removing the key, so the system publishes its own again; its servers
// are still the domestic upstreams meanwhile.
func TestAnOriginalThatCantBePutBackIsOverriddenAndRemovedAfter(t *testing.T) {
	for name, odd := range map[string]dict{
		"opaque": func() dict { d := dnsDict([]string{"192.168.1.1"}, nil); d.opaque = true; return d }(),
		"spaces": dnsDict([]string{"192.168.1.1"}, map[string]string{"Options": "ndots:2 timeout:1"}),
	} {
		f := aMac(t)
		f.put("State:/Network/Service/"+wifiService+"/DNS", odd)
		s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		overridden(t, f, "State:/Network/Service/"+wifiService+"/DNS")
		if got, err := systemUpstreams(f, nil); err != nil || fmt.Sprint(got) != "[192.168.1.1]" {
			t.Errorf("%s: upstreams %v, %v", name, got, err)
		}
		// A crash, then the next start.
		s.mu.Lock()
		s.stopped = true
		close(s.stop)
		s.mu.Unlock()
		if err := restoreBackup(f); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := f.get("State:/Network/Service/" + wifiService + "/DNS"); ok {
			t.Errorf("%s: the key stays after the restore", name)
		}
		for _, k := range []string{"State:/Network/Service/B/DNS", resolverKey} {
			if d, _, _ := f.get(k); isOverride(d) {
				t.Errorf("%s: %s still overridden", name, k)
			}
		}
	}
}

func TestNoActiveServiceFailsAndChangesNothing(t *testing.T) {
	resolverDir = t.TempDir()
	f := &fakeStore{kv: map[string]dict{"Setup:/Network/Service/C/DNS": dnsDict([]string{"8.8.8.8"}, nil)}}
	before := f.dump()
	if _, err := setDynamicStore(f, nodeConfig, nil, time.Hour); err == nil {
		t.Fatal("no error")
	}
	if f.dump() != before {
		t.Error("changed")
	}
	if _, err := setDynamicStore(f, SystemConfig{}, nil, time.Hour); err == nil {
		t.Fatal("no servers: no error")
	}
}

func TestResolverFilesAreOtherResolvers(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	if err := os.WriteFile(filepath.Join(resolverDir, "example.test"), []byte("nameserver 10.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) {
		t.Errorf("problem: %v", err)
	}
}

// A resolver directory that can't be read is not an empty one: what it
// holds is unknown, so Update fails and Problem calls the node
// unprotected. Only its absence reads as empty.
func TestAnUnreadableResolverDirectoryIsReported(t *testing.T) {
	f := aMac(t)
	unreadable := filepath.Join(t.TempDir(), "resolver")
	if err := os.WriteFile(unreadable, []byte("nameserver 10.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolverDir = unreadable
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Update(nodeConfig); err == nil {
		t.Error("Update over an unreadable resolver directory: nil error")
	}
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "reading "+unreadable) {
		t.Errorf("problem: %v", err)
	}
}

func TestManualServersAreTheUpstreams(t *testing.T) {
	f := aMac(t)
	f.put("Setup:/Network/Service/"+wifiService+"/DNS", dnsDict([]string{"1.1.1.1", "100.64.0.7"}, nil))
	got, err := systemUpstreams(f, []netip.Addr{netip.MustParseAddr("100.64.0.7")})
	if err != nil || fmt.Sprint(got) != "[1.1.1.1]" {
		t.Errorf("%v, %v", got, err)
	}
}

// A change the store notifies is overridden at once, not at the next
// backstop check; the watch covers the services' and the global keys.
func TestTheStoresNotificationsTriggerACheck(t *testing.T) {
	f := aMac(t)
	events := make(chan struct{}, 1)
	var watched []string
	notify := func(_ context.Context, patterns []string) (<-chan struct{}, error) {
		watched = patterns
		return events, nil
	}
	s, err := setDynamicStore(f, nodeConfig, notify, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if len(watched) == 0 {
		t.Fatal("nothing watched")
	}
	f.put("State:/Network/Service/"+wifiService+"/DNS", dnsDict([]string{"10.0.0.1"}, nil))
	events <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if d, _, _ := f.get("State:/Network/Service/" + wifiService + "/DNS"); isOverride(d) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not overridden after the notification")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A service with DNS set by hand keeps its own servers (Setup: wins over
// State:, and Setup: is never written): they stay a fallback, which
// Problem says.
func TestDNSSetByHandIsReported(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS") // no other VPN
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "1 network services have DNS set by hand") {
		t.Errorf("problem: %v", err)
	}
	_ = f.remove("Setup:/Network/Service/B/DNS")
	s.check()
	if err := s.Problem(); err != nil {
		t.Errorf("nothing set by hand: %v", err)
	}
}

// Another program's default resolver (its own empty supplemental domain)
// may be asked before the node's: reported.
func TestAnotherDefaultResolverIsReported(t *testing.T) {
	f := aMac(t)
	_ = f.remove("Setup:/Network/Service/B/DNS")
	other := dnsDict([]string{"10.2.2.2"}, map[string]string{"SearchOrder": "50000"})
	other.arrays["SupplementalMatchDomains"] = []string{""}
	f.put("State:/Network/Service/D/DNS", other)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) {
		t.Errorf("problem: %v", err)
	}
}

// A store read that fails while looking for other resolvers is an error,
// not an empty answer: what can't be read may hold a resolver, so Problem
// must not call the node protected.
func TestAFailedReadOfAnotherResolverIsReported(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); err != nil {
		t.Fatalf("problem before the failure: %v", err)
	}
	vpn := dnsDict([]string{"10.1.1.1"}, map[string]string{"ServerPort": "53"})
	vpn.arrays["SupplementalMatchDomains"] = []string{"corp.example"}
	f.put("State:/Network/Service/D/DNS", vpn)
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Service/D/DNS": errors.New("read failed")}
	f.mu.Unlock()
	if err := s.Update(nodeConfig); err == nil {
		t.Error("Update over a failed read: nil error")
	}
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "State:/Network/Service/D/DNS") {
		t.Errorf("problem: %v", err)
	}
}

func TestAFailedListingOfOtherResolversIsReported(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); err != nil {
		t.Fatalf("problem before the failure: %v", err)
	}
	f.mu.Lock()
	f.keysErrs = map[string]error{serviceDNSPattern: errors.New("list failed")}
	f.mu.Unlock()
	if err := s.Update(nodeConfig); err == nil {
		t.Error("Update over a failed listing: nil error")
	}
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "listing the network services' DNS states") {
		t.Errorf("problem: %v", err)
	}
}

// One unreadable scutil answer is not an empty one: the last known
// upstreams stay (warned about once, not at every check), and only the
// node going offline (no primary network service) tells an empty answer.
func TestAFailedPrimaryReadKeepsTheUpstreamsOfflineClearsThem(t *testing.T) {
	f := aMac(t)
	var log bytes.Buffer
	var told [][]netip.Addr
	c := nodeConfig
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	c.Upstreams = func(a []netip.Addr) { told = append(told, a) }
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv4": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	s.check()
	if len(told) != 0 {
		t.Errorf("a failed read told %v", told)
	}
	if n := strings.Count(log.String(), "level=WARN"); n != 1 {
		t.Errorf("a failed read warned %d times, want once", n)
	}
	if !strings.Contains(log.String(), "dns: reading State:/Network/Global/IPv4") {
		t.Errorf("the warning doesn't name the read: %s", log.String())
	}
	f.mu.Lock()
	delete(f.getErrs, "State:/Network/Global/IPv4")
	f.mu.Unlock()
	_ = f.remove("State:/Network/Global/IPv4")
	s.check()
	if len(told) != 1 || told[0] != nil {
		t.Errorf("offline told %v, want one empty answer", told)
	}
	if n := strings.Count(log.String(), "level=WARN"); n != 1 {
		t.Errorf("warned %d times after recovery, want once", n)
	}
	// A good read re-arms the warning: a second episode warns again.
	f.put("State:/Network/Global/IPv4", globalDict())
	s.check()
	if len(told) != 2 || fmt.Sprint(told[1]) != "[192.168.1.1]" {
		t.Errorf("recovered told %v, want the Wi-Fi servers", told)
	}
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv4": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	s.check()
	if len(told) != 2 {
		t.Errorf("a second failed read told %v", told)
	}
	if n := strings.Count(log.String(), "level=WARN"); n != 2 {
		t.Errorf("warned %d times over two episodes, want twice", n)
	}
}

// globalDict is the IPv4 global dictionary of aMac: Wi-Fi is the primary
// service.
func globalDict() dict {
	g := newDict()
	g.strs["PrimaryService"] = wifiService
	return g
}

// An earlier version overrode Setup: keys too: a start puts such a
// leftover back, and a running node puts back any it finds in its backup.
func TestASetupOverrideLeftByAnEarlierVersionGoesBack(t *testing.T) {
	f := aMac(t)
	manual := dnsDict([]string{"9.9.9.9"}, nil)
	f.put("Setup:/Network/Service/B/DNS", dnsDict([]string{"100.64.0.7"}, map[string]string{overrideProp: "1"}))
	if err := writeBackup(f, map[string]original{"Setup:/Network/Service/B/DNS": originalOf("Setup:/Network/Service/B/DNS", manual, true)}); err != nil {
		t.Fatal(err)
	}
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d, _, _ := f.get("Setup:/Network/Service/B/DNS"); isOverride(d) || fmt.Sprint(d.array("ServerAddresses")) != "[9.9.9.9]" {
		t.Errorf("Setup: of B while running: %+v", d)
	}
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.get(resolverKey); ok {
		t.Error("the node's service stays after Restore")
	}
}

// The IPv6 fallback's read failure is not an empty answer either: on an
// IPv6-only network (no IPv4 global) a failed IPv6 read keeps the last
// upstreams, and only both globals being gone is offline.
func TestAFailedIPv6ReadKeepsTheUpstreamsOfflineClearsThem(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Global/IPv4")
	ipv6 := newDict()
	ipv6.strs["PrimaryService"] = wifiService
	f.put("State:/Network/Global/IPv6", ipv6)
	var log bytes.Buffer
	var told [][]netip.Addr
	c := nodeConfig
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	c.Upstreams = func(a []netip.Addr) { told = append(told, a) }
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv6": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	s.check()
	if len(told) != 0 {
		t.Errorf("a failed read told %v", told)
	}
	if n := strings.Count(log.String(), "level=WARN"); n != 1 {
		t.Errorf("a failed read warned %d times, want once", n)
	}
	if !strings.Contains(log.String(), "State:/Network/Global/IPv6") {
		t.Errorf("the warning doesn't name the read: %s", log.String())
	}
	f.mu.Lock()
	delete(f.getErrs, "State:/Network/Global/IPv6")
	f.mu.Unlock()
	_ = f.remove("State:/Network/Global/IPv6")
	s.check()
	if len(told) != 1 || told[0] != nil {
		t.Errorf("offline told %v, want one empty answer", told)
	}
	if n := strings.Count(log.String(), "level=WARN"); n != 1 {
		t.Errorf("warned %d times after recovery, want once", n)
	}
}

// An offline Mac (no primary network service) has no upstreams to
// report: an empty answer, not an error.
func TestAnOfflineMacsUpstreamsAreEmpty(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Global/IPv4")
	got, err := systemUpstreams(f, nil)
	if err != nil || got != nil {
		t.Errorf("upstreams: %v, %v", got, err)
	}
}

// A primary read that failed at the last check leaves the last upstreams in place:
// not unprotected (the OS still resolves through the node), but the
// direct upstreams may be stale, which Problem says without calling the
// node unprotected.
func TestStaleUpstreamsAreReportedNotUnprotected(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	c := nodeConfig
	c.Upstreams = func([]netip.Addr) {}
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); err != nil {
		t.Fatalf("problem before the failure: %v", err)
	}
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv4": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	if err := s.Problem(); !errors.Is(err, ErrUpstreamsStale) || errors.Is(err, ErrUnprotected) {
		t.Errorf("problem: %v", err)
	}
	f.mu.Lock()
	delete(f.getErrs, "State:/Network/Global/IPv4")
	f.mu.Unlock()
	s.check()
	if err := s.Problem(); err != nil {
		t.Errorf("problem after a good read: %v", err)
	}
}

// Staleness doesn't hide behind an unprotected cause: Problem joins
// them, and Unprotected still sorts the join out.
func TestStaleUpstreamsAreReportedAlongsideUnprotected(t *testing.T) {
	f := aMac(t)
	c := nodeConfig
	c.Upstreams = func([]netip.Addr) {}
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv4": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	p := s.Problem()
	if !errors.Is(p, ErrUnprotected) || !errors.Is(p, ErrUpstreamsStale) || !Unprotected(p) {
		t.Errorf("problem: %v", p)
	}
	if !strings.Contains(p.Error(), "1 domains") || !strings.Contains(p.Error(), "failed at the last check") {
		t.Errorf("problem doesn't name both: %v", p)
	}
}

// With the upstreams configured (-dns-upstream) the system's servers
// aren't used as the direct upstreams: they aren't read, and a failed
// read reports nothing.
func TestUnusedUpstreamsArentReadOrReported(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	var log bytes.Buffer
	c := nodeConfig // no Upstreams callback
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); err != nil {
		t.Fatalf("problem before the failure: %v", err)
	}
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Global/IPv4": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	if err := s.Problem(); err != nil {
		t.Errorf("a failed read of unused upstreams: %v", err)
	}
	if strings.Contains(log.String(), "level=WARN") {
		t.Errorf("warned about unused upstreams: %s", log.String())
	}
}

// An empty string value (seen for an empty DomainName) can be written
// back as `d.add Key ""`: the original stays restorable, and Restore
// sets it back instead of removing the key and leaving that network
// without DNS until its next renewal.
func TestAnEmptyStringValueIsRestorable(t *testing.T) {
	f := aMac(t)
	odd := dnsDict([]string{"192.168.1.1"}, map[string]string{"DomainName": ""})
	f.put("State:/Network/Service/"+wifiService+"/DNS", odd)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	overridden(t, f, "State:/Network/Service/"+wifiService+"/DNS")
	s.mu.Lock()
	o := s.backup["State:/Network/Service/"+wifiService+"/DNS"]
	s.mu.Unlock()
	if o.Unrestorable || !o.Present || o.Strs["DomainName"] != "" {
		t.Errorf("the original: %+v", o)
	}
	f.setsLog = nil
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if d, ok, _ := f.get("State:/Network/Service/" + wifiService + "/DNS"); !ok || !d.equal(odd) {
		t.Errorf("after Restore: %+v, ok %v", d, ok)
	}
	for _, op := range f.setsLog {
		if op == "remove State:/Network/Service/"+wifiService+"/DNS" {
			t.Errorf("the key was removed: %v", f.setsLog)
		}
	}
}

// A read that fails inside the primary service's lookup names what was
// read.
func TestAFailedPrimaryServiceReadNamesTheKey(t *testing.T) {
	f := aMac(t)
	var log bytes.Buffer
	c := nodeConfig
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	c.Upstreams = func([]netip.Addr) {}
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	f.mu.Lock()
	f.getErrs = map[string]error{"State:/Network/Service/" + wifiService + "/DNS": errors.New("read failed")}
	f.mu.Unlock()
	s.check()
	if !strings.Contains(log.String(), "dns: reading State:/Network/Service/"+wifiService+"/DNS") {
		t.Errorf("the warning doesn't name the read: %s", log.String())
	}
}

// A target that can't be read before it is overridden names the key, and
// the node is unprotected meanwhile.
func TestAFailedReadOfATargetNamesTheKey(t *testing.T) {
	f := aMac(t)
	s, err := setDynamicStore(f, nodeConfig, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	key := "State:/Network/Service/B/DNS"
	f.mu.Lock()
	f.getErrs = map[string]error{key: errors.New("read failed")}
	f.mu.Unlock()
	err = s.Update(nodeConfig)
	if err == nil || !strings.Contains(err.Error(), "dns: reading "+key+": read failed") {
		t.Errorf("update: %v", err)
	}
	if p := s.Problem(); !Unprotected(p) {
		t.Errorf("problem: %v", p)
	}
}

// toldUpstreams collects what a store tells cfg.Upstreams, from its own
// goroutine.
type toldUpstreams struct {
	mu   sync.Mutex
	told [][]netip.Addr
	ch   chan struct{}
}

func newToldUpstreams() *toldUpstreams { return &toldUpstreams{ch: make(chan struct{}, 16)} }

func (u *toldUpstreams) tell(a []netip.Addr) {
	u.mu.Lock()
	u.told = append(u.told, a)
	u.mu.Unlock()
	u.ch <- struct{}{}
}

func (u *toldUpstreams) all() [][]netip.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.told)
}

// wait waits for one more tell.
func (u *toldUpstreams) wait(t *testing.T) {
	t.Helper()
	select {
	case <-u.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("never told")
	}
}

// A store whose caller couldn't read the system's resolvers (its first
// read failed) reports them stale and tells the first good read,
// although nothing changed from the store's point of view.
func TestAFailedFirstReadIsStaleUntilAGoodReadTellsIt(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	var log bytes.Buffer
	u := newToldUpstreams()
	c := nodeConfig
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	c.Upstreams, c.UpstreamsUnknown = u.tell, true
	f.mu.Lock()
	f.getErrs = map[string]error{globalIPv4Key: errors.New("read failed")}
	f.mu.Unlock()
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	s.check()
	if p := s.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a failed first read: %v", p)
	}
	if told := u.all(); len(told) != 0 {
		t.Errorf("a failed read told %v", told)
	}
	if strings.Contains(log.String(), "level=WARN") {
		t.Errorf("warned again for the caller's episode: %s", log.String())
	}
	f.mu.Lock()
	delete(f.getErrs, globalIPv4Key)
	f.mu.Unlock()
	s.check()
	u.wait(t)
	if told := u.all(); len(told) != 1 || fmt.Sprint(told[0]) != "[192.168.1.1]" {
		t.Errorf("told %v, want the Wi-Fi servers once", told)
	}
	if p := s.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}

// Offline, the first good read tells an empty answer and clears the
// staleness all the same.
func TestAFailedFirstReadThenOfflineTellsNothing(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	_ = f.remove("Setup:/Network/Service/B/DNS")
	u := newToldUpstreams()
	c := nodeConfig
	c.Upstreams, c.UpstreamsUnknown = u.tell, true
	f.mu.Lock()
	f.getErrs = map[string]error{globalIPv4Key: errors.New("read failed")}
	f.mu.Unlock()
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	s.check()
	if p := s.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after a failed first read: %v", p)
	}
	f.mu.Lock()
	delete(f.getErrs, globalIPv4Key)
	f.mu.Unlock()
	_ = f.remove(globalIPv4Key)
	s.check()
	u.wait(t)
	if told := u.all(); len(told) != 1 || told[0] != nil {
		t.Errorf("offline told %v, want one empty answer", told)
	}
	if p := s.Problem(); p != nil {
		t.Errorf("problem offline: %v", p)
	}
}

// When the store's own first read works, it tells at once, without
// waiting for a change or the backstop.
func TestAFailedFirstReadIsToldTheStoresGoodRead(t *testing.T) {
	f := aMac(t)
	u := newToldUpstreams()
	c := nodeConfig
	c.Upstreams, c.UpstreamsUnknown = u.tell, true
	s, err := setDynamicStore(f, c, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	u.wait(t)
	if told := u.all(); len(told) != 1 || fmt.Sprint(told[0]) != "[192.168.1.1]" {
		t.Errorf("told %v, want the Wi-Fi servers once", told)
	}
	if p := s.Problem(); errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("stale after a good read: %v", p)
	}
}
