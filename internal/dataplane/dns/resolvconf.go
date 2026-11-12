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
	// DHCP client rewriting resolv.conf, resolved's uplink servers). It
	// is called without the configuration's lock held, from the
	// configuration's own goroutine or from Update's caller.
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
	// there is no moment the OS's own configuration is back. Where
	// another program's write of the configuration is settling (Linux's
	// resolv.conf), the new one is applied when it settles, and a failure
	// then shows in Problem, not here.
	Update(SystemConfig) error
	// Problem says why names may still be resolved outside the node's
	// resolver (another link's domains in systemd-resolved, a rewrite that
	// failed, another program's write not taken back within the settle),
	// nil when the OS resolves through it only. It may also report
	// ErrUpstreamsStale or ErrNoSystemUpstream, which are not unprotected.
	Problem() error
	// Restore puts back what was there before.
	Restore() error
}

// Deferred says s holds a configuration it hasn't applied yet: its last
// Update waits for another program's write of the OS's configuration to
// settle (System.Update). Problem may be nil meanwhile.
func Deferred(s System) bool {
	d, ok := s.(interface{ deferred() bool })
	return ok && d.deferred()
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

// ErrNoSystemUpstream marks a Problem where the last good read of the
// OS's own resolvers named none: the resolver keeps asking the previous
// direct upstreams, which the OS no longer names. Like ErrUpstreamsStale
// it is not unprotected.
var ErrNoSystemUpstream = errors.New("dns: the system names no resolver")

// staleUpstreams is the Problem while a good read of the OS's own
// resolvers is owed: the first one failed (UpstreamsUnknown) or, on the
// resolv.conf path, the read of a change failed; nil once one has worked.
func staleUpstreams(untold bool) error {
	if !untold {
		return nil
	}
	return fmt.Errorf("%w: no read of the system's resolvers has worked since one failed", ErrUpstreamsStale)
}

// startsUntold says a new configuration starts untold: the caller's own
// read of the OS's resolvers failed (UpstreamsUnknown) and it has none
// of its own, so its first good read is told whatever it found, and
// until then Problem reports ErrUpstreamsStale.
func startsUntold(c SystemConfig) bool {
	return c.UpstreamsUnknown && c.Upstreams != nil
}

// Unprotected says whether a Problem leaves names resolving outside the
// node's resolver: an ErrUnprotected problem, or anything else — a
// System that reports a problem it doesn't name must read as
// unprotected, never as protected. Only nil and a problem whose every
// part is ErrUpstreamsStale or ErrNoSystemUpstream are not: a joined problem is unprotected if
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
	return !errors.Is(problem, ErrUpstreamsStale) && !errors.Is(problem, ErrNoSystemUpstream)
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

// originalEqual says two originals are the same configuration: an
// original parsed back from the managed file always ends in a newline,
// one read from a file may not, and that is not a change.
func originalEqual(a, b []byte) bool {
	return string(originalLines(a)) == string(originalLines(b))
}

// originalLines are an original's lines joined back, so it is the same
// with and without a trailing newline.
func originalLines(b []byte) []byte {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return []byte(strings.Join(lines, "\n"))
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
	timing resolvConfTiming

	mu       sync.Mutex
	cfg      SystemConfig
	original []byte // the last original seen
	seen     bool   // original is set
	err      error  // the last apply's
	// untold: the first good read is still owed (startsUntold), told
	// whatever it finds.
	untold bool
	// owed: a change's read failed and a good read is owed; one that
	// names no server keeps the previous upstreams, as on a change.
	owed bool
	// noServer: the last good read named no server (with Upstreams set),
	// so the previous upstreams are kept though the OS names none.
	noServer bool
	// written is what the last apply left at path, and writtenInfo the
	// file it left it in: any other content is another program's write.
	written     []byte
	writtenInfo fs.FileInfo
	// writeFailed: the last rewrite failed, so what is at path may be part
	// of it, not written followed by another program's lines; no appended
	// lines are taken until a rewrite succeeds.
	writeFailed bool
	// rewrite puts content at path (rewriteResolvConf; a field so tests can
	// make a write fail partway).
	rewrite func(path string, f resolvConfFile, content []byte) error
	// foreign is another program's write that may still be going on,
	// while the watch waits for it to settle; nil when there is none. Update
	// leaves the rewrite to the watch meanwhile.
	foreign *foreignWrite
	// contended: a settle's cap forced the file back at takenBack, so
	// another program may be writing it again and again; Problem reports
	// unprotected until the node's file has stood for a settle.
	contended bool
	takenBack time.Time
	restored  bool          // Restore ran: there is no watch any more
	wake      chan struct{} // Update began a settle the watch must time
	stop      chan struct{}
	stopped   chan struct{}
}

// foreignWrite is another program's write being settled.
type foreignWrite struct {
	began time.Time // when the settle began; it never runs past began+settleMax
	last  fileState // the file as last read
}

// resolvConfTiming is how a managed resolv.conf is watched.
type resolvConfTiming struct {
	// check is how often the file is read for another program having
	// rewritten it, besides the change notifications.
	check time.Duration
	// settle is how long another program's write into the file in place
	// must stay quiet (no change event, the same file state) before it is
	// read: an in-place writer truncates the file, then appends to it (the
	// package doc's "Linux: /etc/resolv.conf").
	settle time.Duration
	// settleMax bounds a settle from its start: a writer that never goes
	// quiet is taken back anyway.
	settleMax time.Duration
}

var resolvConfTimes = resolvConfTiming{check: 2 * time.Second, settle: 500 * time.Millisecond, settleMax: 2 * time.Second}

// errRestored is Update's error once Restore has run.
var errRestored = errors.New("dns: resolv.conf was restored")

// setResolvConf manages the resolv.conf at path with the product's
// timings.
func setResolvConf(path string, uplink string, c SystemConfig) (*resolvConf, error) {
	return setResolvConfTimed(path, uplink, c, resolvConfTimes)
}

// setResolvConfTimed is setResolvConf with the given timings. The first
// take-over reads the file as it is: with nothing written yet there is
// no telling another program's write in progress from a finished one
// (RESIDUAL-RISKS.md RR5).
func setResolvConfTimed(path, uplink string, c SystemConfig, timing resolvConfTiming) (*resolvConf, error) {
	r := &resolvConf{path: path, uplink: uplink, timing: timing, cfg: c, untold: startsUntold(c), rewrite: rewriteResolvConf,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{})}
	r.mu.Lock()
	tell, err := r.apply(readResolvConfFile(r.path))
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go r.watch(tell)
	return r, nil
}

// apply writes the managed resolv.conf over f, what a read of it found
// (ferr its error), keeping f as the original unless it is the node's
// own (left by a crash). Lines appended to the node's own file are
// another program's (an in-place writer still appending after its settle
// ended, or a hand edit) and join the original, unless the node's last
// rewrite failed (writeFailed). It returns what to tell
// the caller, run after unlocking, or nil. r.mu is held.
func (r *resolvConf) apply(f resolvConfFile, ferr error) (tell func(), err error) {
	defer func() { r.err = err }()
	if ferr != nil {
		return nil, ferr
	}
	m := parseResolvConf(f.content)
	symlink, read := f.symlink, f.read
	if appended, ok := bytes.CutPrefix(f.content, r.written); ok && !r.writeFailed && len(r.written) > 0 && len(appended) > 0 {
		m = parseResolvConf(r.written)
		m.original = append(slices.Clip(m.original), appended...)
	}
	if m.managed {
		symlink = m.symlink
		if len(m.original) == 0 {
			// Taken over while the file was missing, or over an empty
			// one — a missing and an empty original look the same in the
			// managed file: what the OS used before is unknown, not an
			// empty answer.
			read = false
			if b, ok := r.linkedOriginal(symlink); ok {
				m.original, read = b, true
			}
		}
	}
	content := render(r.cfg, m.original, symlink)
	tell = r.recordOriginal(m.original, read)
	if err := r.rewrite(r.path, f, content); err != nil {
		r.writeFailed = true
		return tell, err
	}
	r.written, r.writeFailed = content, false
	if fi, err := os.Lstat(r.path); err == nil {
		r.writtenInfo = fi
	}
	return tell, nil
}

// resolvConfFile is what is at a resolv.conf's path.
type resolvConfFile struct {
	info    fs.FileInfo // nil: there is no file
	content []byte
	symlink string // the file is a symlink to this
	read    bool   // content was read: the OS's own resolvers
}

// readResolvConfFile reads the resolv.conf at path, a file or a symlink.
// A missing file and a dangling link are no content, not an error.
func readResolvConfFile(path string) (resolvConfFile, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return resolvConfFile{}, nil // the file isn't there: nothing was read
	}
	if err != nil {
		return resolvConfFile{}, err
	}
	f := resolvConfFile{info: fi}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		if f.symlink, err = os.Readlink(path); err != nil {
			return f, err
		}
		var rerr error
		if f.content, rerr = os.ReadFile(path); rerr == nil { // a dangling link is no original content
			f.read = true
		}
	case fi.Mode().IsRegular():
		if f.content, err = os.ReadFile(path); err != nil {
			return f, err
		}
		f.read = true
	default:
		return f, fmt.Errorf("dns: %s is not a file", path)
	}
	return f, nil
}

// linkedOriginal is the original behind the link a managed file with no
// original content names: while untold, the original may have been a
// link whose target reads now (a dangling link's target may have
// appeared since). A target that reads back as the node's own managed
// file (a link to itself, directly or through another link) holds no
// original, and an empty target is no read: the managed file can't tell
// an empty original from a missing one, so taking it would end the
// retries for good. r.mu is held.
func (r *resolvConf) linkedOriginal(symlink string) ([]byte, bool) {
	if !r.untold || symlink == "" {
		return nil, false
	}
	target := symlink
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(r.path), target)
	}
	b, err := os.ReadFile(target)
	if err != nil || len(b) == 0 || parseResolvConf(b).managed {
		return nil, false
	}
	return b, true
}

// recordOriginal keeps original as the last one seen and returns what to
// tell Upstreams about it, or nil; read says original is the OS's own
// resolvers, read just now. r.mu is held.
func (r *resolvConf) recordOriginal(original []byte, read bool) (tell func()) {
	var ups []netip.Addr
	ok := true // nothing read: no answer to lose
	if read {
		var uerr error
		ups, uerr = upstreamsFromContent(original, r.uplink, r.cfg.Servers)
		ok = uerr == nil
	}
	// Upstreams is told when the original changed, and at the first good
	// read while one is owed (untold, owed). Behind the stub, an
	// unreadable or empty uplink file is a failed read: no answer was had,
	// so while untold it clears nothing, and on a change it makes a read
	// owed: the changed original is recorded below, so no later tick sees
	// it change.
	firstGoodRead := read && ok && r.untold
	owedRead := read && ok && r.owed
	changed := r.seen && !originalEqual(r.original, original)
	switch {
	case read && ok:
		r.untold, r.owed = false, false
		r.noServer = r.cfg.Upstreams != nil && len(ups) == 0
	case read && changed && r.cfg.Upstreams != nil:
		r.owed = true
	}
	r.original, r.seen = original, true
	upstreams := r.cfg.Upstreams
	if upstreams != nil && (changed || firstGoodRead || owedRead) {
		switch {
		case len(ups) > 0:
			tell = func() { upstreams(ups) }
		case firstGoodRead:
			tell = func() { upstreams(nil) }
		case r.cfg.Log != nil && !r.untold && !r.owed:
			log := r.cfg.Log
			tell = func() { log.Warn("DNS: no upstream to ask; set one with -dns-upstream") }
		}
	}
	return tell
}

// rewriteResolvConf puts content at path unless f, what is there, holds
// it already: in place of a regular file, else (no file, a symlink) as a
// new file replacing what is there.
func rewriteResolvConf(path string, f resolvConfFile, content []byte) error {
	if string(content) == string(f.content) {
		return nil
	}
	if f.info != nil && f.info.Mode().IsRegular() {
		return writeFile(path, content)
	}
	return replace(path, func(tmp string) error { return writeNew(tmp, content) })
}

// watch takes the file back whenever another program writes it: a file
// renamed into the path at once, any other write once it settles
// (resolvConfTiming).
func (r *resolvConf) watch(first func()) {
	defer close(r.stopped)
	if first != nil {
		first()
	}
	changes, closeWatch := watchFile(r.path)
	defer closeWatch()
	poll := time.NewTicker(r.timing.check)
	defer poll.Stop()
	// quiet fires once a settling write has been quiet for the settle, or
	// at the settle's cap.
	quiet := time.NewTimer(r.timing.settle)
	quiet.Stop()
	for {
		changed, renamed, quietEnded := false, false, false
		select {
		case <-r.stop:
			return
		case renamed = <-changes:
			changed = true
		case <-r.wake:
			changed = true
		case <-poll.C:
		case <-quiet.C:
			quietEnded = true
		}
		// Read under r.mu: an apply on a bind mount rewrites in place, and
		// its half-written file must not look like another program's.
		r.mu.Lock()
		f, ferr := readResolvConfFile(r.path)
		if !r.decide(f, ferr, event{changed: changed, renamed: renamed, quietEnded: quietEnded}, quiet) {
			r.mu.Unlock()
			continue
		}
		r.foreign = nil
		quiet.Stop()
		prev := r.err
		tell, err := r.apply(f, ferr)
		log := r.cfg.Log
		r.mu.Unlock()
		if err != nil && log != nil && (prev == nil || prev.Error() != err.Error()) {
			log.Error("DNS: taking back resolv.conf failed: names may be resolved outside the node", "path", r.path, "err", err)
		}
		if tell != nil {
			tell()
		}
	}
}

// event is what woke the watch.
type event struct {
	changed    bool // a change event, or Update's wake
	renamed    bool // the change events were renames into the path only
	quietEnded bool // the quiet timer fired
}

// decide says whether the watch takes the file back now. It starts or
// moves the quiet timer of a write still settling. r.mu is held.
func (r *resolvConf) decide(f resolvConfFile, ferr error, ev event, quiet *time.Timer) bool {
	now := stateOf(f, ferr)
	switch kind := r.classify(f, ferr, ev.renamed); {
	case kind == ownFile:
		// Applied again all the same: it writes nothing unless a settle
		// that ends this way held an Update's configuration, and it
		// retries a read that is owed (the uplink behind the stub).
		return true
	case kind == wholeWrite:
		return true
	case r.foreign == nil: // a write begins
		r.beginForeign(now)
		quiet.Reset(r.quietFor())
		if log := r.cfg.Log; log != nil {
			log.Debug("DNS: another program is writing resolv.conf; taking it back once the write settles", "path", r.path)
		}
		return false
	case time.Since(r.foreign.began) >= r.timing.settleMax: // past the cap
		r.contended, r.takenBack = true, time.Now()
		return true
	case ev.changed || now != r.foreign.last: // still being written
		r.foreign.last = now
		quiet.Reset(r.quietFor())
		return false
	case !ev.quietEnded: // a poll during a quiet settle
		return false
	}
	r.contended = false
	return true // settled
}

// beginForeign begins settling another program's write, found as now. A
// writer the cap forced back is still contending if it began again
// within a settle of being taken back. r.mu is held.
func (r *resolvConf) beginForeign(now fileState) {
	if time.Since(r.takenBack) >= r.timing.settle {
		r.contended = false
	}
	r.foreign = &foreignWrite{began: time.Now(), last: now}
}

// fileKind is whose write a read of the managed path found.
type fileKind int

const (
	// ownFile is what the node last wrote.
	ownFile fileKind = iota
	// wholeWrite is another program's file, complete: one renamed into
	// the path (a change event says so), or one that can't be read, which
	// gives nothing to wait for.
	wholeWrite
	// inPlaceWrite is another program's write that may still be going on:
	// into the file the node wrote, or into a file created at the path
	// (created at the open, before its first write), or one whose kind
	// can't be told (the poll and Update have no event; no file).
	inPlaceWrite
)

// classify says whose write f is; renamed says the change events since
// the last read were renames into the path only. On a bind mount every
// write is in place, so every write there settles. r.mu is held.
func (r *resolvConf) classify(f resolvConfFile, ferr error, renamed bool) fileKind {
	switch {
	case ferr != nil:
		return wholeWrite
	case f.read && bytes.Equal(f.content, r.written):
		return ownFile
	case renamed && f.info != nil && r.writtenInfo != nil && !os.SameFile(f.info, r.writtenInfo):
		return wholeWrite
	}
	return inPlaceWrite
}

// quietFor is how long the settling write must stay quiet, never past
// the settle's cap. r.mu is held.
func (r *resolvConf) quietFor() time.Duration {
	return max(0, min(r.timing.settle, time.Until(r.foreign.began.Add(r.timing.settleMax))))
}

// fileState is what a read of a resolv.conf found, to tell whether a
// write settled.
type fileState struct {
	exists  bool
	mode    fs.FileMode // the type bits
	symlink string
	read    bool
	content string
	err     string
}

func stateOf(f resolvConfFile, err error) fileState {
	if err != nil {
		return fileState{err: err.Error()}
	}
	if f.info == nil {
		return fileState{}
	}
	return fileState{exists: true, mode: f.info.Mode().Type(), symlink: f.symlink, read: f.read, content: string(f.content)}
}

// Update writes c over the managed file, unless another program may be
// writing the file: then c is written once that write settles, and a
// failure then shows in Problem, not here.
func (r *resolvConf) Update(c SystemConfig) error {
	r.mu.Lock()
	if r.restored {
		r.mu.Unlock()
		return errRestored
	}
	r.cfg = c
	f, ferr := readResolvConfFile(r.path)
	if r.foreign == nil && r.classify(f, ferr, false) == inPlaceWrite {
		r.beginForeign(stateOf(f, ferr))
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
	if r.foreign != nil {
		r.mu.Unlock()
		return nil
	}
	tell, err := r.apply(f, ferr)
	r.mu.Unlock()
	if tell != nil {
		tell()
	}
	return err
}

// deferred says r holds a configuration it hasn't written yet: Update
// left it to the watch while another program's write settles.
func (r *resolvConf) deferred() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.foreign != nil
}

func (r *resolvConf) Problem() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	if r.err != nil {
		errs = append(errs, fmt.Errorf("%w: rewriting %s: %v", ErrUnprotected, r.path, r.err))
	}
	switch {
	case r.contended && (r.foreign != nil || time.Since(r.takenBack) < r.timing.settle):
		errs = append(errs, fmt.Errorf("%w: another program keeps writing %s; taken back only at the settle's cap", ErrUnprotected, r.path))
	case r.foreign != nil && time.Since(r.foreign.began) > r.timing.settle:
		errs = append(errs, fmt.Errorf("%w: another program's write of %s has not settled in %v", ErrUnprotected, r.path, time.Since(r.foreign.began).Round(time.Millisecond)))
	}
	if err := staleUpstreams(r.untold || r.owed); err != nil {
		errs = append(errs, err)
	}
	if r.noServer && r.cfg.Upstreams != nil {
		errs = append(errs, fmt.Errorf("%w: the last read of %s named none", ErrNoSystemUpstream, r.path))
	}
	return errors.Join(errs...)
}

// Restore puts the original back, as a file or the symlink it was. A
// resolv.conf another program wrote since is left alone. Update fails
// after it.
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
	r.restored = true
	return restoreResolvConf(r.path)
}

// restoreResolvConf puts back the original a managed resolv.conf holds;
// any other file is left alone, and so is none at all: nothing to put
// back.
func restoreResolvConf(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
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

// readUplink reads resolved's uplink resolv.conf. A missing or unreadable
// file is an error, and so is an empty one: a zero-byte read cannot be
// told from a half-written file, and resolved's own writer writes its
// header comment even with no servers and replaces the file atomically,
// so an empty uplink is never an answer with no upstreams.
func readUplink(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dns: reading resolved's uplink %s: %w", path, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("dns: resolved's uplink %s is empty", path)
	}
	return b, nil
}

// upstreamsFromContent are the servers a resolv.conf names, with the
// same stub filtering and uplink fallback as upstreamsFrom. A conf that
// names only resolved's stub is decided by the uplink file's read
// (readUplink): a missing, unreadable or empty uplink is a failed read,
// and the error names the cause.
func upstreamsFromContent(content []byte, uplink string, exclude []netip.Addr) ([]netip.Addr, error) {
	servers := nameservers(content)
	if onlyStubs(servers) {
		b, err := readUplink(uplink)
		if err != nil {
			return nil, err
		}
		servers = nameservers(b)
	}
	return slices.DeleteFunc(servers, func(a netip.Addr) bool {
		return slices.Contains(exclude, a) || slices.Contains(resolvedStubs, a)
	}), nil
}

// upstreamsFrom are the servers the resolv.conf at etc named before the
// node managed it or, if those are systemd-resolved's stub, the servers
// in resolved's own list at uplink; never the stub or exclude. A missing,
// unreadable or empty uplink behind the stub is a failed read, not an
// empty answer (readUplink).
func upstreamsFrom(etc, uplink string, exclude []netip.Addr) ([]netip.Addr, error) {
	content, err := originalResolvConf(etc)
	if err != nil {
		return nil, err
	}
	return upstreamsFromContent(content, uplink, exclude)
}
