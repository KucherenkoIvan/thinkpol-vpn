package dns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SystemConfig is how the OS should resolve while the node runs.
type SystemConfig struct {
	// Interface is the overlay TUN: systemd-resolved configures it as the
	// link every name is resolved through.
	Interface string
	// Servers are the resolver's addresses.
	Servers []netip.Addr
	// Search are domains short names are tried in (the space's zone); the
	// OS's own search domains are left out while the node runs, so a
	// name is never retried under a domain the rules send elsewhere.
	Search []string
	// Upstreams, if set, is told the resolvers the OS would use on its
	// own whenever another program changes them while the node runs (a
	// DHCP client rewriting resolv.conf, resolved's uplink servers). It is
	// called from the configuration's own goroutine.
	Upstreams func([]netip.Addr)
	// UpstreamsUnknown says the caller's own read of the OS's resolvers
	// failed, so it has none: the first good read tells Upstreams, and
	// until then Problem reports ErrUpstreamsStale. Read when the
	// configuration is first set.
	UpstreamsUnknown bool
	// Log receives warnings from configuration watchers.
	Log *slog.Logger
}

// System is the OS's resolver configuration while the node points it at
// its own resolver. Its methods are safe from any goroutine.
type System interface {
	// Update points the OS at a new configuration, over the current one:
	// there is no moment the OS's own configuration is back.
	Update(SystemConfig) error
	// Problem says why names may still be resolved outside the node's
	// resolver (another link's domains in systemd-resolved, a rewrite that
	// failed), nil when the OS resolves through it only. It may also
	// report ErrUpstreamsStale, which is not unprotected.
	Problem() error
	// Restore puts back what was there before.
	Restore() error
}

// ErrUnprotected marks the Problems where the OS doesn't resolve only
// through the node's resolver. A System's Problem may instead report
// ErrUpstreamsStale, which is not unprotected; Unprotected tells the
// two apart.
var ErrUnprotected = errors.New("dns: names may be resolved outside the node")

// ErrUpstreamsStale marks a Problem where the last read of the OS's own
// resolvers failed: the direct upstreams are the ones read before, so
// `direct` names may not resolve. The OS still resolves through the
// node, so on its own it is not unprotected; Unprotected sorts a joined
// Problem. Wrap a cause in it with %v: a %w'd cause is a part of its own,
// and an untagged part is unprotected.
var ErrUpstreamsStale = errors.New("dns: the direct upstreams may be stale")

// staleUpstreams is the Problem while no read of the OS's own resolvers
// has worked since the first one failed (UpstreamsUnknown); nil once one
// has.
func staleUpstreams(untold bool) error {
	if !untold {
		return nil
	}
	return fmt.Errorf("%w: no read of the system's resolvers has worked since the first one failed", ErrUpstreamsStale)
}

// startsUntold says a new configuration starts untold: the caller's own
// read of the OS's resolvers failed (UpstreamsUnknown) and it has none
// of its own, so its first good read is told whatever it found.
func startsUntold(c SystemConfig) bool {
	return c.UpstreamsUnknown && c.Upstreams != nil
}

// Unprotected says whether a Problem leaves names resolving outside the
// node's resolver: an ErrUnprotected problem, or anything else — a
// System that reports a problem it doesn't name must read as
// unprotected, never as protected. Only nil and a problem whose every
// part is ErrUpstreamsStale are not: a joined problem is unprotected if
// any of its parts is, so an untagged part beside a stale one isn't
// hidden by it.
func Unprotected(problem error) bool {
	if problem == nil {
		return false
	}
	if errors.Is(problem, ErrUnprotected) {
		return true
	}
	switch e := problem.(type) {
	case interface{ Unwrap() []error }:
		parts := 0
		for _, part := range e.Unwrap() {
			if part == nil {
				continue
			}
			parts++
			if Unprotected(part) {
				return true
			}
		}
		if parts > 0 {
			return false
		}
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); inner != nil {
			return Unprotected(inner)
		}
	}
	return !errors.Is(problem, ErrUpstreamsStale)
}

// A resolv.conf the node manages starts with resolvConfHeader and keeps
// what it replaced in comment lines, so it can be put back even after a
// crash or a reboot, with nothing kept anywhere else.
const (
	resolvConfHeader = "# thinkpol: generated while the node runs; the original below is put back when it stops."
	originalLine     = "#thinkpol-original "
	originalLink     = "#thinkpol-original-symlink "
)

// managedResolvConf is a parsed resolv.conf: what the node wrote, and the
// original it replaced.
type managedResolvConf struct {
	managed  bool
	original []byte
	symlink  string // the original was a symlink to this
}

func parseResolvConf(content []byte) managedResolvConf {
	if !bytes.HasPrefix(content, []byte(resolvConfHeader+"\n")) {
		return managedResolvConf{original: content}
	}
	m := managedResolvConf{managed: true}
	var orig bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if target, ok := strings.CutPrefix(line, originalLink); ok {
			m.symlink = target
		} else if text, ok := strings.CutPrefix(line, originalLine); ok {
			orig.WriteString(text + "\n")
		}
	}
	m.original = orig.Bytes()
	return m
}

// render is the resolv.conf pointing at c.Servers, searching c.Search
// only, keeping the original's options, and the original itself in
// comments.
func render(c SystemConfig, original []byte, symlink string) []byte {
	var b bytes.Buffer
	b.WriteString(resolvConfHeader + "\n")
	for _, s := range c.Servers {
		fmt.Fprintf(&b, "nameserver %s\n", s.WithZone(""))
	}
	var options []string
	for _, f := range directives(original) {
		if f[0] == "options" {
			options = append(options, f[1:]...)
		}
	}
	if len(c.Search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(c.Search, " "))
	}
	if len(options) > 0 {
		fmt.Fprintf(&b, "options %s\n", strings.Join(options, " "))
	}
	if symlink != "" {
		b.WriteString(originalLink + symlink + "\n")
	}
	sc := bufio.NewScanner(bytes.NewReader(original))
	for sc.Scan() {
		b.WriteString(originalLine + sc.Text() + "\n")
	}
	return b.Bytes()
}

// directives are a resolv.conf's lines split in fields, comments left out.
func directives(content []byte) [][]string {
	var out [][]string
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// nameservers are a resolv.conf's servers.
func nameservers(content []byte) []netip.Addr {
	var out []netip.Addr
	for _, f := range directives(content) {
		if f[0] != "nameserver" || len(f) < 2 {
			continue
		}
		if a, err := netip.ParseAddr(f[1]); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// originalResolvConf is the resolv.conf at path as it was before the node
// managed it.
func originalResolvConf(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseResolvConf(content).original, nil
}

// resolvConf manages a resolv.conf file: Set replaces it, a watcher puts
// it back if something else rewrites it, Restore puts the original back.
type resolvConf struct {
	path   string
	uplink string // systemd-resolved uplink resolv.conf for stub fallback

	mu       sync.Mutex
	cfg      SystemConfig
	original []byte // the last original seen
	seen     bool   // original is set
	err      error  // the last apply's
	// untold: cfg.Upstreams has no servers yet, its caller's own read
	// having failed (UpstreamsUnknown). The first good read tells it,
	// whether or not the original changed; until then Problem reports
	// ErrUpstreamsStale.
	untold  bool
	stop    chan struct{}
	stopped chan struct{}
}

// resolvConfCheck is how often a managed resolv.conf is checked for
// another program having rewritten it, besides the change notifications.
const resolvConfCheck = 2 * time.Second

func setResolvConf(path string, uplink string, c SystemConfig) (*resolvConf, error) {
	r := &resolvConf{path: path, uplink: uplink, cfg: c, stop: make(chan struct{}), stopped: make(chan struct{}),
		untold: startsUntold(c)}
	r.mu.Lock()
	tell, err := r.apply()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go r.watch(tell)
	return r, nil
}

// apply writes the managed resolv.conf over whatever is there, keeping it
// as the original unless it is the node's own (left by a crash). It
// returns what to tell the caller, run after unlocking, or nil. r.mu is
// held.
func (r *resolvConf) apply() (tell func(), err error) {
	defer func() { r.err = err }()
	fi, err := os.Lstat(r.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var current []byte
	symlink := ""
	read := false // the OS's own resolvers were read
	switch {
	case err != nil: // the file isn't there: nothing was read
	case fi.Mode()&fs.ModeSymlink != 0:
		if symlink, err = os.Readlink(r.path); err != nil {
			return nil, err
		}
		var rerr error
		if current, rerr = os.ReadFile(r.path); rerr == nil { // a dangling link is no original content
			read = true
		}
	case fi.Mode().IsRegular():
		if current, err = os.ReadFile(r.path); err != nil {
			return nil, err
		}
		read = true
	default:
		return nil, fmt.Errorf("dns: %s is not a file", r.path)
	}
	m := parseResolvConf(current)
	if m.managed {
		symlink = m.symlink
		if len(m.original) == 0 {
			// Taken over while the file was missing: what the OS used
			// before is unknown, not an empty answer.
			read = false
		}
	}
	content := render(r.cfg, m.original, symlink)
	// Upstreams is told when the original changed, and at the first good
	// read while the caller has none (untold), whatever it found.
	firstGoodRead := read && r.untold
	changed := r.seen && !bytes.Equal(r.original, m.original)
	if read {
		r.untold = false
	}
	r.original, r.seen = m.original, true
	upstreams := r.cfg.Upstreams
	if upstreams != nil && (changed || firstGoodRead) {
		ups := upstreamsFromContent(m.original, r.uplink, r.cfg.Servers)
		switch {
		case len(ups) > 0:
			tell = func() { upstreams(ups) }
		case firstGoodRead:
			// The first good read is told whatever it found: the caller
			// has no upstreams of its own until one.
			tell = func() { upstreams(nil) }
		case r.cfg.Log != nil:
			log := r.cfg.Log
			tell = func() { log.Warn("DNS: no upstream to ask; set one with -dns-upstream") }
		}
	}
	if string(content) == string(current) {
		return tell, nil
	}
	if fi != nil && fi.Mode().IsRegular() {
		return tell, writeFile(r.path, content)
	}
	return tell, replace(r.path, func(tmp string) error { return writeNew(tmp, content) })
}

func (r *resolvConf) watch(first func()) {
	defer close(r.stopped)
	if first != nil {
		first()
	}
	changes, closeWatch := watchFile(r.path)
	defer closeWatch()
	t := time.NewTicker(resolvConfCheck)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-changes:
		case <-t.C:
		}
		r.mu.Lock()
		tell, _ := r.apply()
		r.mu.Unlock()
		if tell != nil {
			tell()
		}
	}
}

func (r *resolvConf) Update(c SystemConfig) error {
	r.mu.Lock()
	r.cfg = c
	tell, err := r.apply()
	r.mu.Unlock()
	if tell != nil {
		tell()
	}
	return err
}

func (r *resolvConf) Problem() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	if r.err != nil {
		errs = append(errs, fmt.Errorf("%w: rewriting %s: %v", ErrUnprotected, r.path, r.err))
	}
	if err := staleUpstreams(r.untold); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Restore puts the original back, as a file or the symlink it was. A
// resolv.conf another program wrote since is left alone.
func (r *resolvConf) Restore() error {
	select {
	case <-r.stop:
		return nil
	default:
	}
	close(r.stop)
	<-r.stopped
	r.mu.Lock()
	defer r.mu.Unlock()
	return restoreResolvConf(r.path)
}

// restoreResolvConf puts back the original a managed resolv.conf holds;
// any other file is left alone.
func restoreResolvConf(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m := parseResolvConf(content)
	switch {
	case !m.managed:
		return nil
	case m.symlink != "":
		return replace(path, func(tmp string) error { return os.Symlink(m.symlink, tmp) })
	}
	return writeFile(path, m.original)
}

// writeFile replaces a file's content atomically: a new file, synced, then
// renamed over it. A file that can't be renamed over (a bind mount, as
// /etc/resolv.conf often is in containers: EBUSY, EXDEV) is rewritten in
// place and synced.
func writeFile(path string, content []byte) error {
	err := replace(path, func(tmp string) error { return writeNew(tmp, content) })
	if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
		return writeInPlace(path, content)
	}
	return err
}

// writeNew writes a new file and syncs it.
func writeNew(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeInPlace rewrites a file's content without replacing the file, and
// syncs it.
func writeInPlace(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// replace puts what create makes at a temporary name next to path in its
// place, atomically, and syncs the directory.
func replace(path string, create func(tmp string) error) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".thinkpol")
	_ = os.Remove(tmp)
	if err := create(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// resolvedStubs are systemd-resolved's local stub listeners.
var resolvedStubs = []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("127.0.0.54")}

func onlyStubs(servers []netip.Addr) bool {
	return len(servers) > 0 && !slices.ContainsFunc(servers, func(a netip.Addr) bool { return !slices.Contains(resolvedStubs, a) })
}

// upstreamsFromContent are the servers a resolv.conf names, with the same
// stub filtering and uplink fallback as upstreamsFrom.
func upstreamsFromContent(content []byte, uplink string, exclude []netip.Addr) []netip.Addr {
	servers := nameservers(content)
	if onlyStubs(servers) {
		if b, err := os.ReadFile(uplink); err == nil {
			servers = nameservers(b)
		}
	}
	return slices.DeleteFunc(servers, func(a netip.Addr) bool {
		return slices.Contains(exclude, a) || slices.Contains(resolvedStubs, a)
	})
}

// upstreamsFrom are the servers the resolv.conf at etc named before the
// node managed it or, if those are systemd-resolved's stub, the servers
// in resolved's own list at uplink; never the stub or exclude.
func upstreamsFrom(etc, uplink string, exclude []netip.Addr) ([]netip.Addr, error) {
	content, err := originalResolvConf(etc)
	if err != nil {
		return nil, err
	}
	return upstreamsFromContent(content, uplink, exclude), nil
}
