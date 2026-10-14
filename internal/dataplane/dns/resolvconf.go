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
	// failed), nil when the OS resolves through it only.
	Problem() error
	// Restore puts back what was there before.
	Restore() error
}

// ErrUnprotected wraps every Problem: the OS doesn't resolve only through
// the node's resolver.
var ErrUnprotected = errors.New("dns: names may be resolved outside the node")

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
	stop     chan struct{}
	stopped  chan struct{}
}

// resolvConfCheck is how often a managed resolv.conf is checked for
// another program having rewritten it, besides the change notifications.
const resolvConfCheck = 2 * time.Second

func setResolvConf(path string, uplink string, c SystemConfig) (*resolvConf, error) {
	r := &resolvConf{path: path, uplink: uplink, cfg: c, stop: make(chan struct{}), stopped: make(chan struct{})}
	r.mu.Lock()
	err := r.apply()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go r.watch()
	return r, nil
}

// apply writes the managed resolv.conf over whatever is there, keeping it
// as the original unless it is the node's own (left by a crash). r.mu is
// held.
func (r *resolvConf) apply() (err error) {
	defer func() { r.err = err }()
	fi, err := os.Lstat(r.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var current []byte
	symlink := ""
	switch {
	case err != nil:
	case fi.Mode()&fs.ModeSymlink != 0:
		if symlink, err = os.Readlink(r.path); err != nil {
			return err
		}
		current, _ = os.ReadFile(r.path) // a dangling link is no original content
	case fi.Mode().IsRegular():
		if current, err = os.ReadFile(r.path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("dns: %s is not a file", r.path)
	}
	m := parseResolvConf(current)
	if m.managed {
		symlink = m.symlink
	}
	content := render(r.cfg, m.original, symlink)
	if string(content) == string(current) {
		return nil
	}
	if r.seen && !bytes.Equal(r.original, m.original) && r.cfg.Upstreams != nil {
		ups := upstreamsFromContent(m.original, r.uplink, r.cfg.Servers)
		if len(ups) == 0 {
			if r.cfg.Log != nil {
				r.cfg.Log.Warn("DNS: no upstream to ask; set one with -dns-upstream")
			}
		} else {
			r.cfg.Upstreams(ups)
		}
	}
	r.original, r.seen = m.original, true
	if fi != nil && fi.Mode().IsRegular() {
		return writeFile(r.path, content)
	}
	return replace(r.path, func(tmp string) error { return writeNew(tmp, content) })
}

func (r *resolvConf) watch() {
	defer close(r.stopped)
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
		_ = r.apply()
		r.mu.Unlock()
	}
}

func (r *resolvConf) Update(c SystemConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = c
	return r.apply()
}

func (r *resolvConf) Problem() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return fmt.Errorf("%w: rewriting %s: %v", ErrUnprotected, r.path, r.err)
	}
	return nil
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
