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

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The guard's pf objects. The anchor hangs under Apple's own hook (the
// main ruleset's `anchor "com.apple/*"`, from /etc/pf.conf, which the
// system loads at boot without enabling pf), so /etc/pf.conf is never
// edited; the table is the anchor's own.
const (
	GuardAnchor = "com.apple/thinkpol"
	guardTable  = "thinkpol_exempt6"
	// appleHook is the main ruleset's anchor rule that evaluates every
	// anchor under com.apple, ours included.
	appleHook = `"com.apple/*"`
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

// detail is what pfctl said on stderr, but its ALTQ chatter, as one line.
func detail(stderr []byte) string {
	var keep []string
	for _, l := range lines(stderr) {
		if !strings.Contains(l, "ALTQ") {
			keep = append(keep, l)
		}
	}
	if len(keep) == 0 {
		return ""
	}
	s := strings.Join(keep, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return ": " + s
}

// lines are b's non-empty lines, trimmed.
func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// hooked reports whether the main ruleset's rules (`pfctl -s rules`)
// evaluate the anchors under com.apple for every outgoing packet: a line
// `anchor "com.apple/*"`, alone or with `all` (as pfctl prints the stock
// /etc/pf.conf's). One narrowed (`in`, `on en0`, `inet`) or another kind
// (`scrub-anchor`) doesn't count.
func hooked(rules []byte) bool {
	for _, l := range lines(rules) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "anchor" && f[1] == appleHook &&
			(len(f) == 2 || len(f) == 3 && f[2] == "all") {
			return true
		}
	}
	return false
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
	for _, l := range lines(info) {
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

// reference is what `pfctl -s References` says of a token.
type reference int

const (
	refGone    reference = iota // not listed: released, or invalidated by pfctl -d
	refOurs                     // listed, taken by the process the record names
	refForeign                  // listed, but taken by another process: the value was reused
)

// referenced finds t in `pfctl -s References` (pid, process name, token,
// timestamp per line): a line with the token's value as a field after the
// first is its; it is t only if its first field is the pid of the pfctl
// that took t. A kernel token is an address's hash, so a released token's
// value can come back as someone else's.
func referenced(refs []byte, t pfToken) reference {
	value, pid := strconv.FormatUint(t.value, 10), strconv.Itoa(t.pid)
	for _, l := range lines(refs) {
		f := strings.Fields(l)
		if len(f) < 2 || !slices.Contains(f[1:], value) {
			continue
		}
		if f[0] == pid {
			return refOurs
		}
		return refForeign
	}
	return refGone
}

// parseTable reads `pfctl -t <table> -T show`: one address or prefix a
// line (a host without its /128). Anything else, a negated entry
// included, is an error: what the guard can't read isn't what it put
// there.
func parseTable(show []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, l := range lines(show) {
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

// exemptTable is the table's content for e, as the fewest prefixes: the
// IPv6 part of Direct, the IPv6 upstreams, and LinkScoped, merged.
// IPv4 isn't the guard's (the kill switch's, TP-048), and Mark means
// nothing to pf: the links' and the direct upstream's sockets are bound
// to the physical interface (ifbind), so they are exempt by destination.
func exemptTable(e routetable.Exempt) []netip.Prefix {
	var b lists.Builder
	for _, r := range e.Ranges6() {
		_ = b.AddRange(r.First, r.Last) // IPv6 already, outside ::ffff:0:0/96
	}
	for _, a := range e.Upstreams {
		if a = a.Unmap().WithZone(""); a.Is6() {
			_ = b.AddPrefix(netip.PrefixFrom(a, 128)) // refused only inside ::ffff:0:0/96, which Unmap leaves empty
		}
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

// validInterface: an interface name pf's grammar takes as a word and the
// kernel could have (IFNAMSIZ is 16 with its NUL), nothing that could
// end the rule early.
var validInterface = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// guardRule is one rule of the anchor: its text, and the words pfctl's
// listing of each rule it expands into must hold (a list such as
// `icmp6-type { 133, 134 }` expands into one rule per item, n).
type guardRule struct {
	text  string
	n     int
	words []string
}

// guardRules are the anchor's rules for tun, in order:
//
//	pass out quick on lo0 inet6 all no state
//	pass out quick on <utun> inet6 all no state
//	pass out quick inet6 from any to <thinkpol_exempt6> no state
//	pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state
//	pass out quick inet6 proto ipv6-icmp all icmp6-type { 130, 131, 132, 143 } no state
//	block return out quick inet6 all
//
// IPv6 only (IPv4's decisions stay whoever else's), outgoing only,
// stateless (a pass with state would put every tunnelled connection in
// pf's state table, whose limit is 10000 by default). pf can't match a
// hop limit, so neighbour discovery (133-137) and MLD (130-132, 143) pass
// whatever their hop limit, unlike on Linux.
func guardRules(tun string) []guardRule {
	pass := []string{"pass", "out", "quick", "inet6"}
	with := func(w ...string) []string { return append(slices.Clone(pass), w...) }
	return []guardRule{
		{"pass out quick on lo0 inet6 all no state", 1, with("on", "lo0")},
		{"pass out quick on " + tun + " inet6 all no state", 1, with("on", tun)},
		{"pass out quick inet6 from any to <" + guardTable + "> no state", 1, with("<" + guardTable + ">")},
		{"pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state", 5, with("icmp6-type")},
		{"pass out quick inet6 proto ipv6-icmp all icmp6-type { 130, 131, 132, 143 } no state", 4, with("icmp6-type")},
		{"block return out quick inet6 all", 1, []string{"block", "return", "out", "quick", "inet6"}},
	}
}

// anchorText is what the guard loads into its anchor: the table, with its
// content, and the rules. One load is one pf transaction, so the rules
// and the table they look up change together; a table defined with a
// list of addresses gets exactly that list on every load (pf.conf(5)).
// `const`: pfctl -T can't change it, only a load.
func anchorText(tun string, table []netip.Prefix) string {
	var b strings.Builder
	b.WriteString("table <" + guardTable + "> const persist {")
	for i, p := range table {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(" \\\n\t" + p.String())
	}
	b.WriteString(" }\n")
	for _, r := range guardRules(tun) {
		b.WriteString(r.text + "\n")
	}
	return b.String()
}

// saneRules checks the anchor's rules as pfctl lists them right after a
// load: one listed rule per rule pfctl expands ours into, in order, each
// with the words it must hold. pfctl prints a rule its own way (protocol
// and ICMPv6 type names, implied options), so this is no comparison of
// text; the listing it accepts is kept, and every later check compares the
// anchor with it exactly.
func saneRules(listed []string, tun string) error {
	i := 0
	for _, r := range guardRules(tun) {
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
			i++
		}
	}
	if i != len(listed) {
		return fmt.Errorf("firewall: pf lists %d rules in the guard's anchor, want %d", len(listed), i)
	}
	return nil
}
