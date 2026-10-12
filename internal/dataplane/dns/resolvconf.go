package dns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// SystemConfig is how the OS should resolve while the node runs.
type SystemConfig struct {
	// Interface is the overlay TUN: systemd-resolved configures it as the
	// link every name is resolved through.
	Interface string
	// Servers are the resolver's addresses.
	Servers []netip.Addr
	// Search are domains short names are tried in (the space's zone).
	Search []string
}

// System is the OS's resolver configuration while the node points it at
// its own resolver.
type System interface {
	// Restore puts back what was there before.
	Restore() error
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

// render is the resolv.conf pointing at c.Servers, keeping the original's
// search domains (after c.Search) and options, and the original itself in
// comments.
func render(c SystemConfig, original []byte, symlink string) []byte {
	var b bytes.Buffer
	b.WriteString(resolvConfHeader + "\n")
	for _, s := range c.Servers {
		fmt.Fprintf(&b, "nameserver %s\n", s.WithZone(""))
	}
	search := slices.Clone(c.Search)
	var options []string
	for _, f := range directives(original) {
		switch f[0] {
		case "search", "domain":
			for _, d := range f[1:] {
				if !slices.Contains(search, d) {
					search = append(search, d)
				}
			}
		case "options":
			options = append(options, f[1:]...)
		}
	}
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
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
	path string
	cfg  SystemConfig

	mu      sync.Mutex
	stop    chan struct{}
	stopped chan struct{}
}

// resolvConfCheck is how often a managed resolv.conf is checked for
// another program having rewritten it.
const resolvConfCheck = 2 * time.Second

func setResolvConf(path string, c SystemConfig) (*resolvConf, error) {
	r := &resolvConf{path: path, cfg: c, stop: make(chan struct{}), stopped: make(chan struct{})}
	if err := r.apply(); err != nil {
		return nil, err
	}
	go r.watch()
	return r, nil
}

// apply writes the managed resolv.conf over whatever is there, keeping it
// as the original unless it is the node's own (left by a crash).
func (r *resolvConf) apply() error {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		if string(render(r.cfg, m.original, symlink)) == string(current) {
			return nil
		}
	}
	content := render(r.cfg, m.original, symlink)
	if fi != nil && fi.Mode().IsRegular() {
		return writeInPlace(r.path, content)
	}
	return replace(r.path, func(tmp string) error { return os.WriteFile(tmp, content, 0o644) })
}

func (r *resolvConf) watch() {
	defer close(r.stopped)
	t := time.NewTicker(resolvConfCheck)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			_ = r.apply()
		}
	}
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
	return writeInPlace(path, m.original)
}

// writeInPlace rewrites a file's content without replacing the file:
// /etc/resolv.conf is often a bind mount (containers), which a rename
// can't replace.
func writeInPlace(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// replace puts what create makes at a temporary name next to path in its
// place, atomically.
func replace(path string, create func(tmp string) error) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".thinkpol")
	_ = os.Remove(tmp)
	if err := create(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// resolvedStubs are systemd-resolved's local stub listeners.
var resolvedStubs = []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("127.0.0.54")}

func onlyStubs(servers []netip.Addr) bool {
	return len(servers) > 0 && !slices.ContainsFunc(servers, func(a netip.Addr) bool { return !slices.Contains(resolvedStubs, a) })
}

// upstreamsFrom are the servers the resolv.conf at etc named before the
// node managed it or, if those are systemd-resolved's stub, the servers
// in resolved's own list at uplink; never the stub or exclude.
func upstreamsFrom(etc, uplink string, exclude []netip.Addr) ([]netip.Addr, error) {
	content, err := originalResolvConf(etc)
	if err != nil {
		return nil, err
	}
	servers := nameservers(content)
	if onlyStubs(servers) {
		if b, err := os.ReadFile(uplink); err == nil {
			servers = nameservers(b)
		}
	}
	return slices.DeleteFunc(servers, func(a netip.Addr) bool {
		return slices.Contains(exclude, a) || slices.Contains(resolvedStubs, a)
	}), nil
}
