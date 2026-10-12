package dns

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// macOS: the resolver configuration lives in configd's dynamic store, per
// network service: State:/Network/Service/<id>/DNS (what DHCP or a VPN
// published) and, where DNS servers were set by hand,
// Setup:/Network/Service/<id>/DNS, which wins over it. SetSystem overrides
// both for every active service with the node's resolver, so the default
// resolver (the primary service's) and every service's scoped one ask the
// node. The originals are kept in the store itself (backupKey), which,
// like the overrides, lives until the machine restarts: a node that
// crashed puts them back when it starts again (RestoreSystem), and a
// reboot has the system publish its own again. Supplemental resolvers
// other software adds (another VPN's per-domain DNS, /etc/resolver files)
// still take the names under their domains: Problem says so.
const (
	backupKey  = "State:/Network/thinkpol/DNS"
	backupProp = "Originals"
	// overrideProp marks a DNS dictionary as the node's.
	overrideProp = "ThinkpolOverride"
	// checkEvery is how often the overrides are checked: DHCP renewing a
	// lease, the user editing DNS settings or a new network service
	// publishes the system's configuration over them.
	checkEvery = 2 * time.Second
)

var (
	serviceStatePattern = `State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)`
	serviceKey          = regexp.MustCompile(`^(State|Setup):/Network/Service/([^/]+)/(IPv4|IPv6|DNS)$`)
	resolverDir         = "/etc/resolver"
)

// SetSystem points the OS resolver at c.Servers, searching c.Search
// only, until Restore; it keeps doing so as the system republishes its
// own configuration.
func SetSystem(c SystemConfig) (System, error) {
	return setDynamicStore(scutil{}, c, checkEvery)
}

// RestoreSystem puts back what a node that died while connected left
// overridden. Call it when the node starts.
func RestoreSystem() error { return restoreBackup(scutil{}) }

// SystemUpstreams are the resolvers the OS uses on its own: the primary
// service's DNS servers (set by hand, else published), as they were
// before the node overrode them. Addresses in exclude are left out.
func SystemUpstreams(exclude []netip.Addr) ([]netip.Addr, error) {
	return systemUpstreams(scutil{}, exclude)
}

// original is a DNS key as the system had it before the override.
type original struct {
	Key     string              `json:"key"`
	Present bool                `json:"present"`
	Strs    map[string]string   `json:"strs,omitempty"`
	Arrays  map[string][]string `json:"arrays,omitempty"`
}

func (o original) dict() dict {
	d := newDict()
	for k, v := range o.Strs {
		d.strs[k] = v
	}
	for k, v := range o.Arrays {
		d.arrays[k] = v
	}
	return d
}

func originalOf(key string, d dict, present bool) original {
	return original{Key: key, Present: present, Strs: d.strs, Arrays: d.arrays}
}

func readBackup(st store) (map[string]original, error) {
	d, ok, err := st.get(backupKey)
	if err != nil || !ok {
		return map[string]original{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(d.strs[backupProp])
	if err != nil {
		return nil, fmt.Errorf("dns: the store's backup: %w", err)
	}
	var list []original
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("dns: the store's backup: %w", err)
	}
	out := make(map[string]original, len(list))
	for _, o := range list {
		out[o.Key] = o
	}
	return out, nil
}

func writeBackup(st store, b map[string]original) error {
	if len(b) == 0 {
		return st.remove(backupKey)
	}
	list := make([]original, 0, len(b))
	for _, k := range sortedKeys(b) {
		list = append(list, b[k])
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	d := newDict()
	d.strs[backupProp] = base64.StdEncoding.EncodeToString(raw)
	return st.set(backupKey, d)
}

func isOverride(d dict) bool { return d.strs[overrideProp] == "1" }

// restorable reports whether scutil can set d back as it is: no nested
// values, nothing with spaces or quotes (`Options : ndots:2 timeout:1`).
func restorable(key string, d dict) bool {
	_, err := setScript(key, d)
	return !d.opaque && err == nil
}

// dynamicStore is the OS's resolver configuration while overridden.
type dynamicStore struct {
	st store

	mu      sync.Mutex
	cfg     SystemConfig
	backup  map[string]original
	err     error // the last check's failure
	others  []string
	stopped bool
	stop    chan struct{}
	done    chan struct{}
	// primary is the primary service's original servers, last told to
	// cfg.Upstreams.
	primary []netip.Addr
}

func setDynamicStore(st store, c SystemConfig, every time.Duration) (*dynamicStore, error) {
	if len(c.Servers) == 0 {
		return nil, errors.New("dns: no resolver address to point the system at")
	}
	backup, err := readBackup(st)
	if err != nil {
		return nil, err
	}
	s := &dynamicStore{st: st, cfg: c, backup: backup, stop: make(chan struct{}), done: make(chan struct{})}
	s.mu.Lock()
	err = s.apply()
	s.primary = s.primaryOriginal()
	s.err = err
	s.mu.Unlock()
	if err != nil && len(s.backup) == 0 {
		_ = s.restore()
		return nil, err // nothing points at the node
	}
	// Some services may still resolve elsewhere: Problem says so, and
	// every check tries again.
	go s.watch(every)
	return s, nil
}

// override is the DNS dictionary every service gets.
func (s *dynamicStore) override() dict {
	d := newDict()
	for _, a := range s.cfg.Servers {
		d.arrays["ServerAddresses"] = append(d.arrays["ServerAddresses"], a.WithZone("").String())
	}
	if len(s.cfg.Search) > 0 {
		d.arrays["SearchDomains"] = slices.Clone(s.cfg.Search)
		d.strs["DomainName"] = s.cfg.Search[0]
	}
	d.strs[overrideProp] = "1"
	return d
}

// targets are the DNS keys to override: every active service's State
// key, and its Setup key where DNS was set by hand.
func (s *dynamicStore) targets() ([]string, error) {
	keys, err := s.st.keys(serviceStatePattern)
	if err != nil {
		return nil, err
	}
	setup, err := s.st.keys(`Setup:/Network/Service/[^/]+/DNS`)
	if err != nil {
		return nil, err
	}
	active := map[string]bool{}
	for _, k := range keys {
		if m := serviceKey.FindStringSubmatch(k); m != nil && m[3] != "DNS" {
			active[m[2]] = true
		}
	}
	var out []string
	for _, id := range sortedKeys(active) {
		out = append(out, "State:/Network/Service/"+id+"/DNS")
		if k := "Setup:/Network/Service/" + id + "/DNS"; slices.Contains(setup, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// apply overrides every target that isn't overridden yet, taking what is
// there as its original (written to the backup before it is replaced),
// and puts back the targets that are gone from the list. Called with mu
// held.
func (s *dynamicStore) apply() error {
	targets, err := s.targets()
	if err != nil {
		return fmt.Errorf("dns: reading the system's network services: %w", err)
	}
	if len(targets) == 0 {
		return errors.New("dns: no active network service to point at the resolver")
	}
	want := s.override()
	type change struct {
		key  string
		have dict
	}
	var changes []change
	var errs []error
	for _, k := range targets {
		have, present, err := s.st.get(k)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if present && isOverride(have) {
			if !have.equal(want) {
				changes = append(changes, change{k, have}) // Update's new servers
			}
			continue
		}
		if present && !restorable(k, have) {
			errs = append(errs, fmt.Errorf("dns: %s holds values the node can't put back; it is left alone", k))
			continue
		}
		s.backup[k] = originalOf(k, have, present)
		changes = append(changes, change{k, have})
	}
	if len(changes) > 0 {
		if err := writeBackup(s.st, s.backup); err != nil {
			return errors.Join(append(errs, fmt.Errorf("dns: keeping the system's configuration: %w", err))...)
		}
	}
	for _, c := range changes {
		if err := s.st.set(c.key, want); err != nil {
			errs = append(errs, fmt.Errorf("dns: overriding %s: %w", c.key, err))
			continue
		}
		// Read back: a write the store took differently is no override.
		if got, ok, err := s.st.get(c.key); err != nil || !ok || !isOverride(got) {
			errs = append(errs, fmt.Errorf("dns: %s doesn't hold the override after setting it", c.key))
		}
	}
	// Services that went (or went inactive): theirs goes back.
	putBack := false
	for _, k := range sortedKeys(s.backup) {
		if !slices.Contains(targets, k) {
			putBack = true
			if err := s.putBack(k); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if putBack {
		if err := writeBackup(s.st, s.backup); err != nil {
			errs = append(errs, err)
		}
	}
	s.others = s.otherResolvers()
	return errors.Join(errs...)
}

// putBack restores one key's original if the override is still there
// (the system may have published its own since), and forgets it.
func (s *dynamicStore) putBack(k string) error {
	o := s.backup[k]
	have, present, err := s.st.get(k)
	if err != nil {
		return err
	}
	if present && isOverride(have) {
		if o.Present {
			err = s.st.set(k, o.dict())
		} else {
			err = s.st.remove(k)
		}
		if err != nil {
			return fmt.Errorf("dns: putting %s back: %w", k, err)
		}
	}
	delete(s.backup, k)
	return nil
}

// otherResolvers are the domains other software sends to resolvers of
// its own: supplemental match domains of services that aren't overridden
// (another VPN's split DNS) and /etc/resolver files.
func (s *dynamicStore) otherResolvers() []string {
	var out []string
	keys, _ := s.st.keys(`State:/Network/Service/[^/]+/DNS`)
	for _, k := range keys {
		if _, ours := s.backup[k]; ours {
			continue
		}
		d, ok, err := s.st.get(k)
		if err != nil || !ok || isOverride(d) {
			continue
		}
		for _, dom := range d.array("SupplementalMatchDomains") {
			if dom != "" {
				out = append(out, dom)
			}
		}
	}
	if entries, err := os.ReadDir(resolverDir); err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), ".") {
				out = append(out, e.Name())
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// primaryOriginal is the primary service's servers as the system has
// them: set by hand, else published; called with mu held.
func (s *dynamicStore) primaryOriginal() []netip.Addr {
	addrs, _ := primaryServers(s.st, s.backup)
	return addrs
}

func (s *dynamicStore) watch(every time.Duration) {
	defer close(s.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.check()
		}
	}
}

// check overrides again what the system published since, and tells
// cfg.Upstreams when the primary service's own servers changed.
func (s *dynamicStore) check() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.err = s.apply()
	primary := s.primaryOriginal()
	changed := !slices.Equal(primary, s.primary)
	s.primary = primary
	tell := s.cfg.Upstreams
	s.mu.Unlock()
	if changed && tell != nil {
		tell(primary)
	}
}

func (s *dynamicStore) Update(c SystemConfig) error {
	if len(c.Servers) == 0 {
		return errors.New("dns: no resolver address to point the system at")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	s.err = s.apply()
	return s.err
}

func (s *dynamicStore) Problem() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.err != nil:
		return fmt.Errorf("%w: %v", ErrUnprotected, s.err)
	case len(s.others) > 0:
		return fmt.Errorf("%w: other resolvers take the names under %d domains", ErrUnprotected, len(s.others))
	}
	return nil
}

func (s *dynamicStore) Restore() error {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stop)
	}
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restore()
}

// restore puts every original back; called with mu held (or before the
// watcher started).
func (s *dynamicStore) restore() error {
	if len(s.backup) == 0 {
		return nil
	}
	var errs []error
	for _, k := range sortedKeys(s.backup) {
		if err := s.putBack(k); err != nil {
			errs = append(errs, err)
		}
	}
	if err := writeBackup(s.st, s.backup); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func restoreBackup(st store) error {
	backup, err := readBackup(st)
	if err != nil {
		return err
	}
	s := &dynamicStore{st: st, backup: backup}
	return s.restore()
}

// primaryServers are the primary service's DNS servers as the system has
// them, the originals where the node overrode them.
func primaryServers(st store, backup map[string]original) ([]netip.Addr, error) {
	g, ok, err := st.get("State:/Network/Global/IPv4")
	if err != nil {
		return nil, err
	}
	id := g.strs["PrimaryService"]
	if !ok || id == "" {
		if g6, ok6, err := st.get("State:/Network/Global/IPv6"); err == nil && ok6 {
			id = g6.strs["PrimaryService"]
		}
	}
	if id == "" {
		return nil, errors.New("dns: no primary network service")
	}
	for _, k := range []string{"Setup:/Network/Service/" + id + "/DNS", "State:/Network/Service/" + id + "/DNS"} {
		d, present, err := st.get(k)
		if err != nil {
			return nil, err
		}
		if present && isOverride(d) {
			o, kept := backup[k]
			if !kept || !o.Present {
				continue
			}
			d = o.dict()
		} else if !present {
			continue
		}
		if servers := parseAddrs(d.array("ServerAddresses")); len(servers) > 0 {
			return servers, nil
		}
	}
	return nil, nil
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.WithZone("").Unmap())
		}
	}
	return out
}

func systemUpstreams(st store, exclude []netip.Addr) ([]netip.Addr, error) {
	backup, err := readBackup(st)
	if err != nil {
		return nil, err
	}
	servers, err := primaryServers(st, backup)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range servers {
		if !slices.Contains(exclude, a) && !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	return out, nil
}
