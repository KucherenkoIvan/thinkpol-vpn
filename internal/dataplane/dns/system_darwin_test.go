package dns

import (
	"errors"
	"fmt"
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
	mu   sync.Mutex
	kv   map[string]dict
	sets int
}

func (f *fakeStore) keys(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	return nil
}

func (f *fakeStore) remove(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.kv, key)
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

// aMac is the store of a Mac with Wi-Fi (A, primary, DHCP's DNS),
// Ethernet (B, active, DNS set by hand), an inactive service with DNS set
// by hand (C) and another VPN's per-domain resolver (D).
func aMac(t *testing.T) *fakeStore {
	t.Helper()
	resolverDir = t.TempDir() // no /etc/resolver files
	f := &fakeStore{kv: map[string]dict{}}
	global := newDict()
	global.strs["PrimaryService"] = "A"
	f.put("State:/Network/Global/IPv4", global)
	ipv4 := newDict()
	ipv4.arrays["Addresses"] = []string{"192.168.1.20"}
	f.put("State:/Network/Service/A/IPv4", ipv4)
	f.put("State:/Network/Service/B/IPv4", ipv4)
	f.put("State:/Network/Service/A/DNS", dnsDict([]string{"192.168.1.1"}, map[string]string{"DomainName": "lan"}))
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

func TestEveryActiveServiceResolvesThroughTheNodeUntilRestore(t *testing.T) {
	f := aMac(t)
	before := f.dump()
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"State:/Network/Service/A/DNS", "State:/Network/Service/B/DNS", "Setup:/Network/Service/B/DNS"} {
		overridden(t, f, k)
	}
	for _, k := range []string{"Setup:/Network/Service/C/DNS", "State:/Network/Service/D/DNS"} {
		if d, _, _ := f.get(k); isOverride(d) {
			t.Errorf("%s overridden: not an active service's", k)
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
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
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
	s, err := setDynamicStore(f, c, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.put("State:/Network/Service/A/DNS", dnsDict([]string{"10.0.0.1"}, nil))
	s.check()
	overridden(t, f, "State:/Network/Service/A/DNS")
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
	if d, _, _ := f.get("State:/Network/Service/A/DNS"); fmt.Sprint(d.array("ServerAddresses")) != "[10.0.0.1]" || isOverride(d) {
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
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.put("State:/Network/Service/A/DNS", dnsDict([]string{"10.0.0.1"}, nil))
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := f.get("State:/Network/Service/A/DNS"); fmt.Sprint(d.array("ServerAddresses")) != "[10.0.0.1]" {
		t.Errorf("A after Restore: %+v", d)
	}
}

func TestUpdatePointsEveryServiceAtTheNewServers(t *testing.T) {
	f := aMac(t)
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	c := nodeConfig
	c.Servers = c.Servers[:1]
	if err := s.Update(c); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"State:/Network/Service/A/DNS", "Setup:/Network/Service/B/DNS"} {
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

// A configuration the node couldn't put back exactly is left alone, and
// the system is not protected.
func TestAnOriginalThatCantBePutBackIsLeftAlone(t *testing.T) {
	f := aMac(t)
	odd := dnsDict([]string{"192.168.1.1"}, nil)
	odd.opaque = true
	f.put("State:/Network/Service/A/DNS", odd)
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if d, _, _ := f.get("State:/Network/Service/A/DNS"); isOverride(d) {
		t.Error("an opaque original was overridden")
	}
	overridden(t, f, "State:/Network/Service/B/DNS")
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) {
		t.Errorf("problem: %v", err)
	}
}

func TestNoActiveServiceFailsAndChangesNothing(t *testing.T) {
	resolverDir = t.TempDir()
	f := &fakeStore{kv: map[string]dict{"Setup:/Network/Service/C/DNS": dnsDict([]string{"8.8.8.8"}, nil)}}
	before := f.dump()
	if _, err := setDynamicStore(f, nodeConfig, time.Hour); err == nil {
		t.Fatal("no error")
	}
	if f.dump() != before {
		t.Error("changed")
	}
	if _, err := setDynamicStore(f, SystemConfig{}, time.Hour); err == nil {
		t.Fatal("no servers: no error")
	}
}

func TestResolverFilesAreOtherResolvers(t *testing.T) {
	f := aMac(t)
	_ = f.remove("State:/Network/Service/D/DNS")
	if err := os.WriteFile(filepath.Join(resolverDir, "example.test"), []byte("nameserver 10.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := setDynamicStore(f, nodeConfig, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Restore() }()
	if err := s.Problem(); !errors.Is(err, ErrUnprotected) {
		t.Errorf("problem: %v", err)
	}
}

func TestManualServersAreTheUpstreams(t *testing.T) {
	f := aMac(t)
	f.put("Setup:/Network/Service/A/DNS", dnsDict([]string{"1.1.1.1", "100.64.0.7"}, nil))
	got, err := systemUpstreams(f, []netip.Addr{netip.MustParseAddr("100.64.0.7")})
	if err != nil || fmt.Sprint(got) != "[1.1.1.1]" {
		t.Errorf("%v, %v", got, err)
	}
}
