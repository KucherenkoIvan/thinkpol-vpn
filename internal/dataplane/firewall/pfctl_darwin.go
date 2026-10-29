package firewall

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The guard's pf objects. The anchor hangs under Apple's own hook (the
// main ruleset's `anchor "com.apple/*"`, from /etc/pf.conf, which the
// system loads at boot without enabling pf), so /etc/pf.conf is never
// edited. Its name sorts before Apple's own anchors there (200.AirDrop,
// 250.ApplicationFirewall), which pf evaluates in name order: none of
// theirs runs first. The table is the anchor's own.
const (
	GuardAnchor = "com.apple/000.thinkpol"
	exemptTable = "thinkpol_exempt6"
	// appleHook is the main ruleset's anchor rule that evaluates every
	// anchor under com.apple, ours included.
	appleHook = `"com.apple/*"`
	// appleAnchor is the anchor the hook evaluates the children of.
	appleAnchor = "com.apple"
)

// pfctlPath is pfctl, by its absolute path: the guard never looks it up.
const pfctlPath = "/sbin/pfctl"

// pfctlTimeout bounds every pfctl run; a country-sized table loads in well
// under it.
const pfctlTimeout = 15 * time.Second

// pfOutput is what one pfctl run printed, and its process id (a token
// from -E names the process that took it).
type pfOutput struct {
	stdout, stderr []byte
	pid            int
}

// pfctl runs pfctl with args, stdin (nil: none) as its input. A failure
// that means there is no pfctl at all wraps routetable.ErrGuardUnsupported.
// A failed run's output is returned with the error.
type pfctl interface {
	run(ctx context.Context, stdin []byte, args ...string) (pfOutput, error)
}

// execPfctl runs the real pfctl at path, each run bounded by timeout.
type execPfctl struct {
	path    string
	timeout time.Duration
}

func (x execPfctl) run(ctx context.Context, stdin []byte, args ...string) (pfOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, x.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, x.path, args...)
	cmd.Env = []string{"LC_ALL=C"} // the output parsed below is the C locale's
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	name := "pfctl " + strings.Join(args, " ")
	if err := cmd.Start(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return pfOutput{}, fmt.Errorf("%w: %s: %w", routetable.ErrGuardUnsupported, x.path, err)
		}
		return pfOutput{}, fmt.Errorf("firewall: %s: %w", name, err)
	}
	out := pfOutput{pid: cmd.Process.Pid}
	err := cmd.Wait()
	out.stdout, out.stderr = stdout.Bytes(), stderr.Bytes()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return out, fmt.Errorf("firewall: %s: no answer within %v", name, x.timeout)
	case err != nil:
		return out, fmt.Errorf("firewall: %s: %w%s", name, err, detail(out.stderr))
	}
	return out, nil
}

// inputLine is how pfctl names a line of its input, "stdin:5:": two
// colons around a number, which redacting an error's addresses would
// take for an IPv6 address.
var inputLine = regexp.MustCompile(`\bstdin:([0-9]+):`)

// detail is what pfctl said on stderr, but its ALTQ chatter, as one line,
// a line of its input named "stdin line N:".
func detail(stderr []byte) string {
	l := lines(stderr)
	if len(l) == 0 {
		return ""
	}
	s := inputLine.ReplaceAllString(strings.Join(l, "; "), "stdin line $1:")
	if len(s) > detailMax {
		// Back to a space: a word cut through (an address) would escape
		// the redaction of addresses whoever logs this does.
		s = s[:detailMax]
		s = s[:max(strings.LastIndexByte(s, ' '), 0)] + "..."
	}
	return ": " + s
}

// detailMax is how much of pfctl's stderr an error quotes.
const detailMax = 300

// lines are b's non-empty lines, trimmed, without pfctl's ALTQ chatter
// (altqChatter), whichever stream it lands on; a listing cut short by a
// line too long to read ends there (readLines says so).
func lines(b []byte) []string {
	l, _ := readLines(b)
	return l
}

// readLines is lines, and an error if a line was too long to read: the
// listing is cut there.
func readLines(b []byte) ([]string, error) {
	return scanLines(b, true)
}

// rawLines is readLines with only each line's "\n" taken off: a line
// keeps the white space it ends in, a `\r` included (a "\n" in what
// pfctl printed ends a line all the same).
func rawLines(b []byte) ([]string, error) {
	return scanLines(b, false)
}

// scanLines reads b's lines, but blank ones and ALTQ chatter, each
// trimmed if trim.
func scanLines(b []byte, trim bool) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	sc.Split(scanLF)
	for sc.Scan() {
		l := sc.Text()
		if t := strings.TrimSpace(l); t != "" && !altqChatter(t) {
			if trim {
				l = t
			}
			out = append(out, l)
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("firewall: pfctl's listing cut at line %d: %w", len(out)+1, err)
	}
	return out, nil
}

// scanLF is bufio.ScanLines without its dropping a `\r` before the "\n".
func scanLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// altqChatter says l, trimmed, is one of the two lines pfctl prints when
// the kernel has no ALTQ, exactly: a rule's label, an anchor's or a
// process's name may hold "ALTQ" and is no chatter.
func altqChatter(l string) bool {
	return l == "No ALTQ support in kernel" || l == "ALTQ related functions disabled"
}

// pfctl's answers of absence, each a line alone on its stream (ALTQ
// chatter aside); all but answerNoRuleset recorded on a Mac
// (testdata/pfctl/recorded-*).
const (
	// answerNoAnchor: `-a ANCHOR -s rules` of an anchor that doesn't
	// exist, on stderr.
	answerNoAnchor = "pfctl: DIOCGETRULES: Invalid argument"
	// answerNoTable: `-t TABLE -T show` of a table that doesn't exist
	// (ESRCH), a missing anchor's included, on stderr.
	answerNoTable = "pfctl: Table does not exist."
	// answerNoRuleset: pfctl's words for ENOENT of a table command, on
	// stderr (from pfctl's source; unrecorded).
	answerNoRuleset = "pfctl: Anchor or Ruleset does not exist."
	// answerNoReferences: all `-s References` prints while pf holds no
	// reference, in place of its header, on stdout.
	answerNoReferences = "No pf starter references held"
)

// answerNoAnchors is what `-a PATH -s Anchors` answers on stderr for an
// anchor that doesn't exist (DIOCGETRULESETS's EINVAL), the path as given.
// From pfctl's source, which then exits 0; both unrecorded (TP-096).
func answerNoAnchors(path string) string {
	return "Anchor '" + path + "' not found."
}

// onlyLine says b is the line want and nothing else, pfctl's ALTQ chatter
// and blank lines aside; a listing cut short isn't.
func onlyLine(b []byte, want string) bool {
	l, err := readLines(b)
	return err == nil && len(l) == 1 && l[0] == want
}

// AnchorMissing says pfctl's stderr for `-a ANCHOR -s rules` (recorded)
// or `-a ANCHOR -s rules -v` (the same DIOCGETRULES; unrecorded) is its
// answer about an anchor that doesn't exist, and nothing else (ALTQ
// chatter aside): such an anchor holds no rules. Any other failure, an
// "Invalid argument" of another ioctl included, isn't that answer.
func AnchorMissing(stderr []byte) bool {
	return onlyLine(stderr, answerNoAnchor)
}

// noTable says pfctl's stderr for a table command is its answer about a
// table that doesn't exist, and nothing else (ALTQ chatter aside):
// answerNoTable (ESRCH, which macOS answers for a missing anchor's table
// too) or answerNoRuleset (ENOENT). Any other failure, an "Invalid
// argument" included, isn't.
func noTable(stderr []byte) bool {
	return onlyLine(stderr, answerNoTable) || onlyLine(stderr, answerNoRuleset)
}

// hook is what the main ruleset does for the guard's anchor.
type hook int

const (
	hookMissing hook = iota // no `anchor "com.apple/*"` that every outgoing packet reaches
	// hookBypassed: a `pass ... quick` above it can end evaluation first.
	// Only InspectIPv6Guard's GuardCheck tells it from hookOK, and says
	// nothing of the anchors above the hook (TP-151); checkBypass judges
	// what gets past the hook.
	hookBypassed
	hookOK
)

// hooked reads the main ruleset's rules (`pfctl -s rules`): the anchor is
// evaluated for every outgoing IPv6 packet if a line `anchor
// "com.apple/*"`, alone or with `all` (as pfctl prints the stock
// /etc/pf.conf's), is there (isHook), and no rule above it is a quick pass
// that could match one (endsEvaluation). One narrowed (`in`, `on en0`,
// `inet`) or another kind (`scrub-anchor`) doesn't count. What the anchors
// above the hook hold is checkBypass's (anchorWalk).
func hooked(rules []byte) hook {
	bypassed := false
	for _, l := range lines(rules) {
		f := strings.Fields(l)
		if isHook(f) {
			if bypassed {
				return hookBypassed
			}
			return hookOK
		}
		if endsEvaluation(f, false) {
			bypassed = true
		}
	}
	return hookMissing
}

// isHook says f, a rule's fields, is the hook: `anchor "com.apple/*"`,
// alone or with `all`.
func isHook(f []string) bool {
	return len(f) >= 2 && f[0] == "anchor" && f[1] == appleHook && (len(f) == 2 || len(f) == 3 && f[2] == "all")
}

// reachesIPv6Out says a rule could match an outgoing IPv6 packet: its
// direction, which pfctl prints at f[at] (after the action, or after an
// anchor's name), isn't `in`, and it isn't `inet` only. pfctl prints the
// family before the protocol and the addresses (`proto`, `from`, `to`,
// `all`); a word after them (an unquoted `tag inet`), or inside
// parentheses before them (`log (all, to pflog1)`), is no family.
func reachesIPv6Out(f []string, at int) bool {
	if len(f) > at && f[at] == "in" {
		return false
	}
	depth := 0
	for _, w := range f {
		if depth == 0 {
			switch w {
			case "inet":
				return false
			case "inet6", "proto", "from", "to", "all":
				return true
			}
		}
		depth += strings.Count(w, "(") - strings.Count(w, ")")
	}
	return true
}

// endsEvaluation says f, a rule's fields, is a pass that ends pf's
// evaluation for an outgoing IPv6 packet it matches: a quick one, or,
// inside a quick anchor (inQuick), any one, since pf stops after a quick
// anchor once a rule in it matched.
func endsEvaluation(f []string, inQuick bool) bool {
	return len(f) >= 2 && f[0] == "pass" && (inQuick || slices.Contains(f, "quick")) && reachesIPv6Out(f, 1)
}

// anchorRule reads l, a rule as pfctl lists it, as an anchor rule (`anchor
// "name" out quick all`): the name as pfctl prints it, "" for an anonymous
// anchor (printed without one) or a name the guard can't read, and the
// rule's fields after the name (none for a name it can't read). pfctl
// prints a name between `"`s as it is, a `"` in it included (`anchor
// 'a"b'` lists as `anchor "a"b" all`), and nothing quoted after it: a
// closing `"` not followed by a space, or a `"` in a later field, is a
// name the guard can't read. So is an anchor call with a label (`label
// "x"`), which fails closed (whether Apple's pfctl prints a label on an
// anchor call is unverified). Other kinds (`scrub-anchor`, `nat-anchor`)
// evaluate no pass.
func anchorRule(l string) (name string, rest []string, ok bool) {
	after, ok := strings.CutPrefix(l, "anchor")
	if !ok || after != "" && after[0] != ' ' && after[0] != '\t' {
		return "", nil, false
	}
	after = strings.TrimLeft(after, " \t")
	quoted, found := strings.CutPrefix(after, `"`)
	if !found {
		return "", strings.Fields(after), true
	}
	name, tail, closed := strings.Cut(quoted, `"`)
	if !closed || tail != "" && tail[0] != ' ' && tail[0] != '\t' {
		return "", nil, true
	}
	rest = strings.Fields(tail)
	if slices.ContainsFunc(rest, func(w string) bool { return strings.Contains(w, `"`) }) {
		return "", nil, true
	}
	return name, rest, true
}

// anchorCall is where an anchor rule leads: the anchor at path (absolute,
// no leading `/`), or with wildcard (`/*`) each of its children in turn.
type anchorCall struct {
	path     string
	wildcard bool
}

// resolveAnchor reads name, an anchor rule's as pfctl lists it in the
// ruleset at base ("" for the main ruleset): pf prints it relative to
// that ruleset (one `../` per level up), or absolute after a `/`, with
// `/*` (`*` alone below the main ruleset) when the rule evaluates the
// children (OpenBSD's pf_anchor_copyout, which XNU's pf has; unverified on
// a Mac, TP-096). ok is false for a name it can't place: no name, `../`
// above the main ruleset, or a path that isn't nameable.
func resolveAnchor(base, name string) (c anchorCall, ok bool) {
	if name == "*" && base != "" {
		name, c.wildcard = "", true
	} else if n, cut := strings.CutSuffix(name, "/*"); cut {
		name, c.wildcard = n, true
	}
	if abs, cut := strings.CutPrefix(name, "/"); cut {
		c.path = abs
	} else {
		for {
			up, cut := strings.CutPrefix(name, "../")
			if !cut {
				break
			}
			if base == "" {
				return anchorCall{}, false
			}
			base, name = base[:max(strings.LastIndexByte(base, '/'), 0)], up
		}
		if name == "" && (base == "" || !c.wildcard) {
			return anchorCall{}, false
		}
		c.path = strings.Trim(base+"/"+name, "/")
	}
	if !nameable(c.path) {
		return anchorCall{}, false
	}
	return c, true
}

// nameable says `pfctl -a path` reads the anchor at path: no component is
// empty or dotted, holds a `*`, or ends in white space. pf's names may
// (only a trailing `/*` is a wildcard), but pfctl takes a trailing `*`
// off -a's name and reads another anchor; and `-s Anchors` ends a line
// right after the name, so white space there may be the name's or the
// listing's, which the guard can't tell apart.
func nameable(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || strings.Contains(part, "*") ||
			strings.TrimRightFunc(part, unicode.IsSpace) != part {
			return false
		}
	}
	return true
}

// childAnchors reads `pfctl -a PATH -s Anchors`, out: the anchors under
// path, a line each ("  PATH/child"), in the order pf keeps and evaluates
// them (sorted by path). pfctl's answer for an anchor that doesn't exist
// (answerNoAnchors, alone, whatever the exit status) is none; any other
// failure, a line that isn't one of path's children after pfctl's
// two-space indent, or anything else on stderr is an error. Only the
// indent and the line's "\n" come off: a child's name may hold spaces, end
// in other white space, or hold a `*`, which the walk can't read
// (nameable): it is listed as it is, for the walk to judge. A newline in
// a name can't be kept: it ends the line, and what follows reads as a
// blank line, ALTQ chatter (both dropped) or a line not under path (an
// error). So a child is listed as it is, twice included, and the walk
// takes a repeat as a name it can't read (listed).
func childAnchors(path string, out pfOutput, runErr error) ([]string, error) {
	listed, err := rawLines(out.stdout)
	if err == nil && len(listed) == 0 && onlyLine(out.stderr, answerNoAnchors(path)) {
		return nil, nil
	}
	if runErr != nil {
		return nil, runErr
	}
	if err != nil {
		return nil, err
	}
	if said, err := readLines(out.stderr); err != nil || len(said) > 0 {
		return nil, fmt.Errorf("firewall: pfctl -a %s -s Anchors: unexpected stderr%s", path, detail(out.stderr))
	}
	var children []string
	for _, l := range listed {
		p, indented := strings.CutPrefix(l, "  ")
		child, ok := strings.CutPrefix(p, path+"/")
		if !indented || !ok || child == "" || strings.Contains(child, "/") {
			return nil, fmt.Errorf("firewall: pfctl -a %s -s Anchors lists %q, not an anchor under it", path, l)
		}
		children = append(children, p)
	}
	return children, nil
}

// skippedNames reads `pfctl -s Interfaces -v`, one interface (or name
// `set skip on` gave) a line, "(skip)" after a skipped one, as every
// skipped name: pf evaluates no rule for a skipped interface's packets,
// and `-s rules` doesn't show it.
func skippedNames(ifaces []byte) ([]string, error) {
	ls, err := readLines(ifaces)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range ls {
		f := strings.Fields(l)
		if len(f) == 2 && f[1] == "(skip)" {
			out = append(out, f[0])
		}
	}
	return out, nil
}

// mainUpToHook is the main ruleset's lines up to the hook, the evidence
// of hooked's verdict: all of them without one.
func mainUpToHook(rules []byte) []string {
	ls := lines(rules)
	for i, l := range ls {
		if isHook(strings.Fields(l)) {
			return ls[:i+1]
		}
	}
	return ls
}

// anchorsBefore reads `pfctl -a com.apple -s Anchors` (childAnchors) as
// the anchors under com.apple whose path sorts before the guard's: the
// hook evaluates them in that order (pf keeps them sorted by path), so
// theirs run first, and a quick pass in one ends evaluation before the
// guard's.
func anchorsBefore(out pfOutput, runErr error) ([]string, error) {
	children, err := childAnchors(appleAnchor, out, runErr)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(children, func(c string) bool { return c >= GuardAnchor }), nil
}

// tokenLine is how `pfctl -E` prints the reference it took.
var tokenLine = regexp.MustCompile(`^Token\s*:\s*([0-9]+)$`)

// parseToken finds the token in what `pfctl -E` printed (on either
// stream): exactly one "Token : <number>" line.
func parseToken(out pfOutput) (uint64, error) {
	var found []uint64
	for _, l := range append(lines(out.stdout), lines(out.stderr)...) {
		if m := tokenLine.FindStringSubmatch(l); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil || v == 0 {
				return 0, fmt.Errorf("firewall: pfctl -E: bad token %q", m[1])
			}
			found = append(found, v)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("firewall: pfctl -E: %d tokens in its output, want 1", len(found))
	}
	return found[0], nil
}

// parseEnabled reads `pfctl -s info`: its "Status: Enabled ..." or
// "Status: Disabled ..." line.
func parseEnabled(info []byte) (bool, error) {
	ls, err := readLines(info)
	if err != nil {
		return false, err
	}
	for _, l := range ls {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "Status:" {
			switch f[1] {
			case "Enabled":
				return true, nil
			case "Disabled":
				return false, nil
			}
		}
	}
	return false, errors.New("firewall: pfctl -s info: no Status line")
}

// pfReference is one line of `pfctl -s References`.
type pfReference struct {
	pid   int
	token uint64
}

// parseReferences reads `pfctl -s References`, out, by the columns its
// header names ("PID  Process Name  TOKEN  TIMESTAMP"): each line after
// it is a pid in the first field and the token where the header's TOKEN
// starts, whatever the process name (spaces included) and the timestamp
// look like, e.g. "618      socketfilterfw               9813589183660731843
// 0 days 00:03:31". understood says the listing is one the guard can
// read: a header, and every line after it a reference so read, one at
// least; or pfctl's answer while pf holds no reference,
// answerNoReferences alone on stdout, without a header, and nothing but
// ALTQ chatter on stderr (as a Mac printed it: a warning there could be
// about a listing that failed). Not understood (no header otherwise, a
// header with no reference under it, which a Mac doesn't print, a line
// out of its columns, a listing cut short), the absence of a reference
// proves nothing.
func parseReferences(out pfOutput) (refs []pfReference, understood bool) {
	if onlyLine(out.stdout, answerNoReferences) {
		said, err := readLines(out.stderr)
		return nil, err == nil && len(said) == 0
	}
	tokenAt := -1
	sc := bufio.NewScanner(bytes.NewReader(out.stdout))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \t\r")
		switch {
		case strings.TrimSpace(l) == "" || altqChatter(strings.TrimSpace(l)):
		case tokenAt < 0:
			f := strings.Fields(l)
			if len(f) > 0 && f[0] == "PID" && slices.Contains(f, "TOKEN") {
				tokenAt = strings.Index(l, "TOKEN")
			}
		default:
			r, ok := referenceAt(l, tokenAt)
			if !ok {
				return nil, false
			}
			refs = append(refs, r)
		}
	}
	return refs, tokenAt >= 0 && len(refs) > 0 && sc.Err() == nil
}

// referenceAt reads a References line: its first field the pid, the field
// starting at the header's TOKEN column the token.
func referenceAt(l string, tokenAt int) (pfReference, bool) {
	f := strings.Fields(l)
	if len(f) == 0 || len(l) <= tokenAt || l[tokenAt] == ' ' || l[tokenAt] == '\t' ||
		tokenAt > 0 && l[tokenAt-1] != ' ' && l[tokenAt-1] != '\t' {
		return pfReference{}, false
	}
	t := strings.Fields(l[tokenAt:])
	pid, err1 := strconv.Atoi(f[0])
	token, err2 := strconv.ParseUint(t[0], 10, 64)
	if err1 != nil || err2 != nil || pid <= 0 || strings.Index(l, f[0]) >= tokenAt {
		return pfReference{}, false
	}
	return pfReference{pid: pid, token: token}, true
}

// reference is what `pfctl -s References` says of a token.
type reference int

const (
	refGone    reference = iota // not listed: released, or dropped by pfctl -d
	refOurs                     // listed, taken by the process the record names
	refForeign                  // listed, but taken by another process: the value was reused
)

// referenced finds t in refs: its token is listed as taken by its pid.
// A kernel token is an address's hash, so a released token's value can
// come back as someone else's; a pid can be reused too, so both matching
// is the best pf can tell.
func referenced(refs []pfReference, t pfToken) reference {
	for _, r := range refs {
		if r.token == t.value {
			if r.pid == t.pid {
				return refOurs
			}
			return refForeign
		}
	}
	return refGone
}

// byPid finds the token pid took: exactly one reference listed for it.
func byPid(refs []pfReference, pid int) (uint64, bool) {
	var found []uint64
	for _, r := range refs {
		if r.pid == pid {
			found = append(found, r.token)
		}
	}
	if len(found) != 1 || found[0] == 0 {
		return 0, false
	}
	return found[0], true
}

// parseTable reads `pfctl -t <table> -T show`: one address or prefix a
// line (a host without its /128). Anything else, a negated entry
// included, is an error: what the guard can't read isn't what it put
// there.
func parseTable(show []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	ls, err := readLines(show)
	if err != nil {
		return nil, err
	}
	for _, l := range ls {
		var p netip.Prefix
		var err error
		if strings.Contains(l, "/") {
			p, err = netip.ParsePrefix(l)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(l); err == nil && a.Zone() == "" {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() {
			return nil, fmt.Errorf("firewall: the guard's table holds %q", l)
		}
		out = append(out, p)
	}
	return sortedPrefixes(out), nil
}

func sortedPrefixes(ps []netip.Prefix) []netip.Prefix {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(ps)
}

// parseStateAddrs reads `pfctl -s states`, one state a line ("ALL tcp
// 2001:db8::10[51000] -> 2001:db8:ab::7[443]  ESTABLISHED:ESTABLISHED"),
// as the IPv6 addresses each line names (its ends, and a translation's in
// parentheses), whatever their order. Lines naming none are skipped.
func parseStateAddrs(states []byte) ([][]netip.Addr, error) {
	ls, err := readLines(states)
	if err != nil {
		return nil, err
	}
	var out [][]netip.Addr
	for _, l := range ls {
		var addrs []netip.Addr
		for _, f := range strings.Fields(l) {
			f = strings.Trim(f, "(),")
			if i := strings.IndexByte(f, '['); i > 0 {
				f = f[:i]
			}
			if a, err := netip.ParseAddr(f); err == nil && a.Is6() && !a.Is4In6() {
				addrs = append(addrs, a.WithZone(""))
			}
		}
		if len(addrs) > 0 {
			out = append(out, addrs)
		}
	}
	return out, nil
}

// exemptPrefixes is the main table's content for e, as the fewest
// prefixes: the IPv6 part of Direct (the direct destinations and the
// links' endpoints) and LinkScoped, merged. IPv4 isn't the guard's (the
// kill switch's, TP-048), and Mark means nothing to pf: the links' and the
// direct upstream's sockets are bound to the physical interface (ifbind).
func exemptPrefixes(e routetable.Exempt) []netip.Prefix {
	var b lists.Builder
	for _, r := range e.Ranges6() {
		_ = b.AddRange(r.First, r.Last) // IPv6 already, outside ::ffff:0:0/96
	}
	s, _ := b.Build()
	var out []netip.Prefix
	for _, p := range s.Prefixes() {
		if p.Addr().Is6() {
			out = append(out, p)
		}
	}
	return out
}

// upstreamTargets are the direct DNS upstreams the guard passes DNS to,
// each on its own port (the resolver asks plain DNS, UDP then TCP, no
// DoT): the IPv6 ones but link-local ones, which the exempt table passes
// whole (they never leave the link) and pf couldn't name without their
// interface. Only DNS to them is exempt, not the whole address.
func upstreamTargets(e routetable.Exempt) []netip.AddrPort {
	var out []netip.AddrPort
	for _, ap := range e.Upstreams {
		a := ap.Addr().Unmap().WithZone("")
		if a.Is6() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() && ap.Port() != 0 {
			out = append(out, netip.AddrPortFrom(a, ap.Port()))
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(out)
}

// validInterface: an interface name pf's grammar takes as a word and the
// kernel could have (IFNAMSIZ is 16 with its NUL), nothing that could
// end the rule early.
var validInterface = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// guardRule is one rule of the anchor: its text, and the words pfctl's
// listing of each rule it expands into must hold (a list such as
// `icmp6-type { 130, 131 }` expands into one rule per item, n).
type guardRule struct {
	text  string
	n     int
	words []string
}

// guardRules are the anchor's rules for tun and the upstreams, in order:
//
//	pass out quick on lo0 inet6 all no state
//	pass out quick on <utun> inet6 all no state
//	pass out quick inet6 from any to <thinkpol_exempt6> no state
//	pass out quick inet6 proto { tcp, udp } from any to <upstream> port <its port> no state   (each upstream)
//	pass out quick inet6 proto ipv6-icmp from any to <upstream> icmp6-type { 135, 136 } no state   (each upstream address)
//	pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state
//	block return out quick inet6 all
//
// IPv6 only (IPv4's decisions stay whoever else's), outgoing only,
// stateless (a pass with state would put every tunnelled connection in
// pf's state table, whose limit is 10000 by default). Neighbour discovery
// needs no rule of its own: its destinations are link-local unicast and
// multicast, in the exempt table, and one to a global address leaves only
// if that address is exempt, or is an upstream's: an on-link upstream's
// unicast neighbour probes (solicitations 135, advertisements 136), which
// for an upstream off the link are two ICMPv6 types a router could
// forward, nothing more. MLD reports go to their group, any multicast
// scope; pf can't match a hop limit (Linux requires 1), so the multicast
// destination is what keeps them on the link.
func guardRules(tun string, upstreams []netip.AddrPort) []guardRule {
	with := func(w ...string) []string { return append([]string{"pass", "out", "quick", "inet6"}, w...) }
	rules := []guardRule{
		{"pass out quick on lo0 inet6 all no state", 1, with("on", "lo0")},
		{"pass out quick on " + tun + " inet6 all no state", 1, with("on", tun)},
		{"pass out quick inet6 from any to <" + exemptTable + "> no state", 1, with("<" + exemptTable + ">")},
	}
	for _, u := range upstreams {
		a, p := u.Addr().String(), strconv.Itoa(int(u.Port()))
		rules = append(rules, guardRule{"pass out quick inet6 proto { tcp, udp } from any to " + a + " port " + p + " no state", 2, with(a, "port", p)})
	}
	var addrs []netip.Addr
	for _, u := range upstreams {
		addrs = append(addrs, u.Addr())
	}
	for _, a := range slices.Compact(addrs) {
		rules = append(rules, guardRule{"pass out quick inet6 proto ipv6-icmp from any to " + a.String() + " icmp6-type { 135, 136 } no state", 2, with(a.String(), "icmp6-type")})
	}
	return append(rules,
		guardRule{"pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state", 4, with("ff00::/8", "icmp6-type")},
		guardRule{"block return out quick inet6 all", 1, []string{"block", "return", "out", "quick", "inet6"}},
	)
}

// anchorText is what the guard loads into its anchor: the table, with its
// content, and the rules. One load is one pf transaction, so the rules
// and the table they look up change together; a table defined with a
// list of addresses gets exactly that list on every load (pf.conf(5)).
// Not `const`: that would keep pfctl -T from changing the table, but
// OpenBSD's pf refuses to change a const table in place, and a reload
// that can't replace it would leave a wider exempt set behind; the
// guard's poll undoes a `-T add` instead.
func anchorText(tun string, exempt []netip.Prefix, upstreams []netip.AddrPort) string {
	var b strings.Builder
	b.WriteString("table <" + exemptTable + "> persist {")
	for i, p := range exempt {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(" \\\n\t" + p.String())
	}
	b.WriteString(" }\n")
	for _, r := range guardRules(tun, upstreams) {
		b.WriteString(r.text + "\n")
	}
	return b.String()
}

// saneRules checks the anchor's rules as pfctl lists them right after a
// load: one listed rule per rule pfctl expands ours into, in order, each
// with the words it must hold, every pass stateless. pfctl prints a rule
// its own way (protocol and ICMPv6 type names, implied options), so this
// is no comparison of text; the listing it accepts is kept, and every
// later check compares the anchor with it exactly. A refusal quotes the
// rule as pf listed it, on purpose: its order and shape are what tell why
// pf holds other than what was loaded (an optimizer reordering the
// rules). It can name an upstream's address: whoever logs this error must
// redact its addresses.
func saneRules(listed []string, tun string, upstreams []netip.AddrPort) error {
	i := 0
	for _, r := range guardRules(tun, upstreams) {
		for range r.n {
			if i >= len(listed) {
				return fmt.Errorf("firewall: pf lists %d rules in the guard's anchor, want more", len(listed))
			}
			f := strings.Fields(listed[i])
			for _, w := range r.words {
				if !slices.Contains(f, w) {
					return fmt.Errorf("firewall: pf lists the guard's rule %d as %q, without %q", i+1, listed[i], w)
				}
			}
			if f[0] == "pass" && !strings.Contains(" "+listed[i]+" ", " no state ") {
				return fmt.Errorf("firewall: pf lists the guard's rule %d as %q, not stateless", i+1, listed[i])
			}
			i++
		}
	}
	if i != len(listed) {
		return fmt.Errorf("firewall: pf lists %d rules in the guard's anchor, want %d", len(listed), i)
	}
	return nil
}
