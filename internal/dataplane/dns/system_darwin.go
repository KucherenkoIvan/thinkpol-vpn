package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
// Setup:/Network/Service/<id>/DNS, which wins over it.
//
// The node's resolver is published as a service of its own (resolverKey):
// a DNS dictionary whose supplemental match domain is empty, which configd
// turns into an additional default resolver, asked before the services'
// own (SearchOrder below their 200000), and unscoped. It has no IPv4 or
// IPv6 entity on purpose: configd copies such an entity's InterfaceName
// onto the service's resolver, and mDNSResponder sends to a resolver of an
// interface bound to it (IP_BOUND_IF). That is what broke the first device
// run, whose override sat on en0's service: a query bound to en0 can't
// reach the overlay address, which only the utun routes. Tailscale's
// tailscaled publishes the same key.
//
// Failing closed, every active service's State: DNS key is overridden with
// the node's resolver too, so the services' own resolvers (asked after the
// node's, or for questions scoped to an interface) lead nowhere but the
// node. Setup: keys are never written: they are configd's copy of the
// network preferences, republished from them whenever the preferences
// change. A service with DNS set by hand (its Setup: key wins over State:)
// keeps its own servers as a fallback: Problem says so.
//
// The originals are kept in the store itself (backupKey), which, like the
// overrides, lives until the machine restarts: a node that crashed puts
// them back when it starts again (RestoreSystem), and a reboot has the
// system publish its own again. Supplemental resolvers other software adds
// (another VPN's per-domain DNS or its own default, /etc/resolver files)
// still take the names under their domains: Problem says so too.
const (
	backupKey  = "State:/Network/thinkpol/DNS"
	backupProp = "Originals"
	// resolverKey is the node's own service's DNS: a fixed id of
	// thinkpol's, no other service's.
	resolverKey = "State:/Network/Service/8E3C1F52-6B0D-4E7A-9C25-0D4B7A61F3E9/DNS"
	// resolverOrder puts the node's resolver ahead of the services'
	// (configd's default order is 200000).
	resolverOrder = "100000"
	// overrideProp marks a DNS dictionary as the node's.
	overrideProp = "ThinkpolOverride"
	// The overrides are checked whenever the store says a service's keys
	// changed (DHCP renewing a lease, the user editing DNS settings, a new
	// network service publish the system's configuration over them), and
	// every backstop anyway; every checkEvery while the store can't be
	// watched.
	checkEvery = 2 * time.Second
	backstop   = 30 * time.Second
	// settle gathers a burst of the store's notifications into one check.
	settle = 100 * time.Millisecond
)

var (
	serviceStatePattern = `State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)`
	serviceDNSPattern   = `State:/Network/Service/[^/]+/DNS`
	// serviceSetupDNSPattern is the Setup: twin of serviceDNSPattern:
	// watched, and listed when counting the services whose DNS was set
	// by hand.
	serviceSetupDNSPattern = `Setup:/Network/Service/[^/]+/DNS`
	globalIPv4Key          = "State:/Network/Global/IPv4"
	globalIPv6Key          = "State:/Network/Global/IPv6"
	// globalIPPattern is both globals, globalIPv4Key and globalIPv6Key:
	// watched for the primary service.
	globalIPPattern = `State:/Network/Global/IPv[46]`
	serviceKey      = regexp.MustCompile(`^(State|Setup):/Network/Service/([^/]+)/(IPv4|IPv6|DNS)$`)
	resolverDir     = "/etc/resolver"
)

// errNoPrimary is the absence of a primary network service (offline): an
// empty answer, not a failed read.
var errNoPrimary = errors.New("dns: no primary network service")

// SetSystem points the OS resolver at c.Servers, searching c.Search
// only, until Restore; it keeps doing so as the system republishes its
// own configuration.
func SetSystem(c SystemConfig) (System, error) {
	sc := scutil{path: scutilPath}
	return setDynamicStore(sc, c, sc.watch, checkEvery)
}

// RestoreSystem puts back what a node that died while connected left
// overridden. Call it when the node starts.
func RestoreSystem() error { return restoreBackup(scutil{path: scutilPath}) }

// SystemUpstreams are the resolvers the OS uses on its own: the primary
// service's DNS servers (set by hand, else published), as they were
// before the node overrode them. Addresses in exclude are left out.
func SystemUpstreams(exclude []netip.Addr) ([]netip.Addr, error) {
	return systemUpstreams(scutil{path: scutilPath}, exclude)
}

// original is a DNS key as the system had it before the override.
type original struct {
	Key     string              `json:"key"`
	Present bool                `json:"present"`
	Strs    map[string]string   `json:"strs,omitempty"`
	Arrays  map[string][]string `json:"arrays,omitempty"`
	// Unrestorable: scutil couldn't set the original back as it was
	// (nested values, values with spaces); it is put back by removing
	// the key, so the system publishes its own again (State: at the next
	// DHCP renewal or network change, Setup: when the network settings
	// are saved again or at reboot), resolving nothing meanwhile rather
	// than through the overlay's resolver. Only its servers are kept.
	Unrestorable bool `json:"unrestorable,omitempty"`
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

	mu     sync.Mutex
	cfg    SystemConfig
	backup map[string]original
	err    error // the last check's failure
	others []string
	// manual counts the active services whose DNS was set by hand
	// (Setup:), which can't be overridden.
	manual  int
	stopped bool
	stop    chan struct{}
	done    chan struct{}
	// primary is the primary service's original servers, last told to
	// cfg.Upstreams.
	primary []netip.Addr
	// primaryFailed marks a read of the primary service's servers that
	// failed at the last check: warned about once, not at every check,
	// and it drives Problem's ErrUpstreamsStale.
	primaryFailed bool
	// untold: the first good read is still owed (startsUntold).
	untold bool
}

// storeWatch subscribes to changes of the store's keys matching patterns;
// nil (tests) or a failure leaves polling alone.
type storeWatch func(ctx context.Context, patterns []string) (<-chan struct{}, error)

// watchedKeys are what a check depends on.
var watchedKeys = []string{serviceStatePattern, serviceSetupDNSPattern, globalIPPattern}

func setDynamicStore(st store, c SystemConfig, notify storeWatch, every time.Duration) (*dynamicStore, error) {
	if len(c.Servers) == 0 {
		return nil, errors.New("dns: no resolver address to point the system at")
	}
	backup, err := readBackup(st)
	if err != nil {
		return nil, err
	}
	s := &dynamicStore{st: st, cfg: c, backup: backup, stop: make(chan struct{}), done: make(chan struct{}),
		untold: startsUntold(c)}
	s.mu.Lock()
	err = s.apply()
	primary, read := s.primaryOriginal()
	s.primary = primary
	s.err = err
	untold := s.untold
	// A good read now is the first one the caller hears of: told below
	// whatever a later read finds.
	tellNow := untold && read
	if tellNow {
		s.untold = false
	}
	tell := s.cfg.Upstreams
	s.mu.Unlock()
	if err != nil && len(s.backup) == 0 {
		_ = s.restore()
		return nil, err // nothing points at the node
	}
	// Some services may still resolve elsewhere: Problem says so, and
	// every check tries again.
	ctx, cancel := context.WithCancel(context.Background())
	var events <-chan struct{}
	if notify != nil {
		events, _ = notify(ctx, watchedKeys)
	}
	if events != nil && every < backstop {
		every = backstop
	}
	go func() {
		defer cancel()
		// Upstreams is told from this goroutine only.
		switch {
		case tellNow:
			tell(primary)
		case untold:
			s.check() // the first check is now, not a backstop later
		}
		s.watch(events, every)
	}()
	return s, nil
}

// resolver is the node's own service's DNS dictionary: an unscoped
// default resolver, asked first.
func (s *dynamicStore) resolver() dict {
	d := newDict()
	for _, a := range s.cfg.Servers {
		d.arrays["ServerAddresses"] = append(d.arrays["ServerAddresses"], a.WithZone("").String())
	}
	d.arrays["SupplementalMatchDomains"] = []string{""}
	d.strs["SearchOrder"] = resolverOrder
	d.strs[overrideProp] = "1"
	return d
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

// targets are the DNS keys to write: every active service's State key,
// then the node's own service's (published last so a crash mid-apply
// never leaves only the supplemental resolver); manual counts the active
// services whose DNS was set by hand.
func (s *dynamicStore) targets() (out []string, manual int, err error) {
	keys, err := s.st.keys(serviceStatePattern)
	if err != nil {
		return nil, 0, err
	}
	setup, err := s.st.keys(serviceSetupDNSPattern)
	if err != nil {
		return nil, 0, err
	}
	active := map[string]bool{}
	for _, k := range keys {
		if m := serviceKey.FindStringSubmatch(k); m != nil && m[3] != "DNS" {
			active[m[2]] = true
		}
	}
	if len(active) == 0 {
		return nil, 0, nil
	}
	for _, id := range sortedKeys(active) {
		out = append(out, "State:/Network/Service/"+id+"/DNS")
		if slices.Contains(setup, "Setup:/Network/Service/"+id+"/DNS") {
			manual++
		}
	}
	out = append(out, resolverKey)
	return out, manual, nil
}

// restoreKeys orders backup keys for teardown: drop the supplemental
// resolver before putting the services' overrides back.
func restoreKeys(backup map[string]original) []string {
	var rest []string
	for k := range backup {
		if k != resolverKey {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	if _, ok := backup[resolverKey]; ok {
		return append([]string{resolverKey}, rest...)
	}
	return rest
}

// apply overrides every target that isn't overridden yet, taking what is
// there as its original (written to the backup before it is replaced),
// and puts back the targets that are gone from the list. Called with mu
// held.
func (s *dynamicStore) apply() error {
	targets, manual, err := s.targets()
	if err != nil {
		return fmt.Errorf("dns: reading the system's network services: %w", err)
	}
	if len(targets) == 0 {
		return errors.New("dns: no active network service to point at the resolver")
	}
	s.manual = manual
	override, resolver := s.override(), s.resolver()
	type change struct {
		key  string
		want dict
	}
	var changes []change
	var errs []error
	for _, k := range targets {
		want := override
		if k == resolverKey {
			want = resolver
		}
		have, present, err := s.st.get(k)
		if err != nil {
			errs = append(errs, fmt.Errorf("dns: reading %s: %w", k, err))
			continue
		}
		if present && isOverride(have) {
			if !have.equal(want) {
				changes = append(changes, change{k, want}) // Update's new servers
			}
			continue
		}
		o := originalOf(k, have, present)
		if present && !restorable(k, have) {
			// Overridden all the same (fail closed); put back by removal.
			o = original{Key: k, Present: true, Unrestorable: true,
				Arrays: map[string][]string{"ServerAddresses": have.array("ServerAddresses")}}
		}
		s.backup[k] = o
		changes = append(changes, change{k, want})
	}
	if len(changes) > 0 {
		if err := writeBackup(s.st, s.backup); err != nil {
			return errors.Join(append(errs, fmt.Errorf("dns: keeping the system's configuration: %w", err))...)
		}
	}
	for _, c := range changes {
		if err := s.st.set(c.key, c.want); err != nil {
			errs = append(errs, fmt.Errorf("dns: overriding %s: %w", c.key, err))
			continue
		}
		// Read back: a write the store took differently is no override.
		got, ok, err := s.st.get(c.key)
		if err != nil {
			errs = append(errs, fmt.Errorf("dns: reading back %s: %w", c.key, err))
			continue
		}
		if !ok || !isOverride(got) {
			errs = append(errs, fmt.Errorf("dns: %s doesn't hold the override after setting it", c.key))
		}
	}
	// Services that went (or went inactive): theirs goes back.
	putBack := false
	for _, k := range restoreKeys(s.backup) {
		if !slices.Contains(targets, k) {
			putBack = true
			if err := s.putBack(k); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if putBack {
		if err := writeBackup(s.st, s.backup); err != nil {
			errs = append(errs, fmt.Errorf("dns: keeping the system's configuration: %w", err))
		}
	}
	if others, err := s.otherResolvers(); err != nil {
		errs = append(errs, err)
	} else {
		s.others = others
	}
	return errors.Join(errs...)
}

// putBack restores one key's original if the override is still there
// (the system may have published its own since), and forgets it.
func (s *dynamicStore) putBack(k string) error {
	o := s.backup[k]
	have, present, err := s.st.get(k)
	if err != nil {
		return fmt.Errorf("dns: reading %s: %w", k, err)
	}
	if present && isOverride(have) {
		if o.Present && !o.Unrestorable {
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
// (another VPN's split DNS) and /etc/resolver files. A failed read is an
// error, not an empty answer: what can't be read may hold a resolver.
func (s *dynamicStore) otherResolvers() ([]string, error) {
	var out []string
	keys, err := s.st.keys(serviceDNSPattern)
	if err != nil {
		return nil, fmt.Errorf("dns: listing the network services' DNS states: %w", err)
	}
	for _, k := range keys {
		if _, ours := s.backup[k]; ours {
			continue
		}
		d, ok, err := s.st.get(k)
		if err != nil {
			return nil, fmt.Errorf("dns: reading %s: %w", k, err)
		}
		if !ok || isOverride(d) {
			continue
		}
		for _, dom := range d.array("SupplementalMatchDomains") {
			if dom == "" {
				dom = "(every name: another default resolver)"
			}
			out = append(out, dom)
		}
	}
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("dns: reading %s: %w", resolverDir, err)
		}
	} else {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), ".") {
				out = append(out, e.Name())
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// primaryOriginal is the primary service's servers as the system has
// them: set by hand, else published; read is false when reading them
// failed. A failed read is not an empty answer: the last one is kept and
// the failure logged once, so one unreadable scutil answer doesn't wipe
// the direct upstreams; no primary network service (offline) is a real
// empty answer and is told as such. Called with mu held.
func (s *dynamicStore) primaryOriginal() (addrs []netip.Addr, read bool) {
	if s.cfg.Upstreams == nil {
		// The system's servers aren't used as the direct upstreams
		// (-dns-upstream set): never read, and never stale.
		s.primaryFailed, s.untold = false, false
		return nil, true
	}
	addrs, err := primaryServers(s.st, s.backup)
	if err != nil && !errors.Is(err, errNoPrimary) {
		// While untold, the caller warned already: one warning for the
		// episode.
		if !s.primaryFailed && !s.untold && s.cfg.Log != nil {
			s.cfg.Log.Warn("DNS: reading the primary service's DNS servers failed; keeping the previous upstreams", "err", err)
		}
		s.primaryFailed = true
		return s.primary, false
	}
	s.primaryFailed = false
	if errors.Is(err, errNoPrimary) {
		return nil, true
	}
	return addrs, true
}

func (s *dynamicStore) watch(events <-chan struct{}, every time.Duration) {
	defer close(s.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		case _, ok := <-events:
			if !ok {
				// The subscription ended: poll as often as without one.
				events = nil
				t.Reset(checkEvery)
				continue
			}
			select {
			case <-s.stop:
				return
			case <-time.After(settle):
			}
		}
		s.check()
	}
}

// check overrides again what the system published since, and tells
// cfg.Upstreams when the primary service's own servers changed, or at
// the first good read while it has none.
func (s *dynamicStore) check() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.err = s.apply()
	primary, read := s.primaryOriginal()
	changed := !slices.Equal(primary, s.primary) || (read && s.untold)
	if read {
		s.untold = false
	}
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
	var errs []error
	switch {
	case s.err != nil:
		errs = append(errs, fmt.Errorf("%w: %v", ErrUnprotected, s.err))
	case len(s.others) > 0:
		errs = append(errs, fmt.Errorf("%w: other resolvers take the names under %d domains", ErrUnprotected, len(s.others)))
	case s.manual > 0:
		errs = append(errs, fmt.Errorf("%w: %d network services have DNS set by hand, which stays their resolver (asked after the node's, and for questions scoped to their interface)", ErrUnprotected, s.manual))
	}
	// Not instead of the unprotected cause above but with it:
	// Unprotected sorts a joined problem back out.
	if err := staleUpstreams(s.untold); err != nil {
		errs = append(errs, err)
	} else if s.primaryFailed {
		errs = append(errs, fmt.Errorf("%w: reading the primary service's DNS servers failed at the last check", ErrUpstreamsStale))
	}
	return errors.Join(errs...)
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
	for _, k := range restoreKeys(s.backup) {
		if err := s.putBack(k); err != nil {
			errs = append(errs, err)
		}
	}
	if err := writeBackup(s.st, s.backup); err != nil {
		errs = append(errs, fmt.Errorf("dns: keeping the system's configuration: %w", err))
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
	g, ok, err := st.get(globalIPv4Key)
	if err != nil {
		return nil, fmt.Errorf("dns: reading %s: %w", globalIPv4Key, err)
	}
	id := g.strs["PrimaryService"]
	if !ok || id == "" {
		g6, ok6, err := st.get(globalIPv6Key)
		if err != nil {
			return nil, fmt.Errorf("dns: reading %s: %w", globalIPv6Key, err)
		}
		if ok6 {
			id = g6.strs["PrimaryService"]
		}
	}
	if id == "" {
		return nil, errNoPrimary
	}
	for _, k := range []string{"Setup:/Network/Service/" + id + "/DNS", "State:/Network/Service/" + id + "/DNS"} {
		d, present, err := st.get(k)
		if err != nil {
			return nil, fmt.Errorf("dns: reading %s: %w", k, err)
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
	if err != nil && !errors.Is(err, errNoPrimary) {
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
