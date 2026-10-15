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
// edited. Its name sorts before Apple's own anchors there (200.AirDrop,
// 250.ApplicationFirewall), which pf evaluates in name order: none of
// theirs runs first. The tables are the anchor's own.
const (
	GuardAnchor   = "com.apple/000.thinkpol"
	exemptTable   = "thinkpol_exempt6"
	upstreamTable = "thinkpol_upstream6"
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

// detail is what pfctl said on stderr, but its ALTQ chatter, as one line.
func detail(stderr []byte) string {
	l := lines(stderr)
	if len(l) == 0 {
		return ""
	}
	s := strings.Join(l, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return ": " + s
}

// lines are b's non-empty lines, trimmed, without pfctl's ALTQ chatter
// ("No ALTQ support in kernel", "ALTQ related functions disabled"),
// whichever stream it lands on.
func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.Contains(l, "ALTQ") {
			out = append(out, l)
		}
	}
	return out
}

// invalidArgument: pfctl's answer about an anchor that doesn't exist
// (`DIOCGETRULES: Invalid argument`), which holds nothing.
func invalidArgument(out pfOutput) bool {
	return bytes.Contains(out.stderr, []byte("Invalid argument"))
}

// noTable: pfctl's answer about a table that doesn't exist.
func noTable(out pfOutput) bool {
	return bytes.Contains(out.stderr, []byte("does not exist")) || invalidArgument(out)
}

// hook is what the main ruleset does for the guard's anchor.
type hook int

const (
	hookMissing  hook = iota // no `anchor "com.apple/*"` that every outgoing packet reaches
	hookBypassed             // a `pass ... quick` above it can end evaluation first
	hookOK
)

// hooked reads the main ruleset's rules (`pfctl -s rules`): the anchor is
// evaluated for every outgoing IPv6 packet if a line `anchor
// "com.apple/*"`, alone or with `all` (as pfctl prints the stock
// /etc/pf.conf's), is there, and no rule above it is a quick pass that
// could match one (not `in` only, not `inet` only). One narrowed (`in`,
// `on en0`, `inet`) or another kind (`scrub-anchor`) doesn't count. A
// quick pass inside an anchor above the hook isn't seen.
func hooked(rules []byte) hook {
	bypassed := false
	for _, l := range lines(rules) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "anchor" && f[1] == appleHook &&
			(len(f) == 2 || len(f) == 3 && f[2] == "all") {
			if bypassed {
				return hookBypassed
			}
			return hookOK
		}
		if len(f) >= 2 && f[0] == "pass" && slices.Contains(f, "quick") && f[1] != "in" &&
			(!slices.Contains(f, "inet") || slices.Contains(f, "inet6")) {
			bypassed = true
		}
	}
	return hookMissing
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

// referenceLine is one reference in `pfctl -s References`: the enabler's
// pid, its process name (one word), the token, then the timestamp, e.g.
// "618 socketfilterfw 9813589183660731843 0 days 00:03:31".
var referenceLine = regexp.MustCompile(`^([0-9]+)\s+\S+\s+([0-9]+)\s+`)

// pfReference is one line of `pfctl -s References`.
type pfReference struct {
	pid   int
	token uint64
}

// parseReferences reads `pfctl -s References`. understood says the
// listing is one the guard can read: a reference line, or the header
// ("PID ... TOKEN ...") of an empty list. Not understood, the absence of
// a reference proves nothing.
func parseReferences(out []byte) (refs []pfReference, understood bool) {
	for _, l := range lines(out) {
		if m := referenceLine.FindStringSubmatch(l); m != nil {
			pid, err1 := strconv.Atoi(m[1])
			token, err2 := strconv.ParseUint(m[2], 10, 64)
			if err1 == nil && err2 == nil {
				refs = append(refs, pfReference{pid: pid, token: token})
				understood = true
			}
			continue
		}
		if f := strings.Fields(l); slices.Contains(f, "PID") && slices.Contains(f, "TOKEN") {
			understood = true
		}
	}
	return refs, understood
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

// parseStateAddrs reads `pfctl -s states`, one state a line ("ALL tcp
// 2001:db8::10[51000] -> 2001:db8:ab::7[443]  ESTABLISHED:ESTABLISHED"),
// as the IPv6 addresses each line names (its ends, and a translation's in
// parentheses), whatever their order. Lines naming none are skipped.
func parseStateAddrs(states []byte) [][]netip.Addr {
	var out [][]netip.Addr
	for _, l := range lines(states) {
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
	return out
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

// upstreamPrefixes and upstreamPorts are the upstream table's content
// for e, the IPv6 direct DNS upstreams' addresses, and the ports DNS to
// them may use: only that is exempt, not the whole address (the resolver
// asks plain DNS, UDP then TCP, no DoT).
func upstreamPrefixes(e routetable.Exempt) []netip.Prefix {
	var out []netip.Prefix
	for _, ap := range e.Upstreams {
		if a := ap.Addr().Unmap().WithZone(""); a.Is6() && ap.Port() != 0 {
			out = append(out, netip.PrefixFrom(a, 128))
		}
	}
	return sortedPrefixes(out)
}

func upstreamPorts(e routetable.Exempt) []uint16 {
	var out []uint16
	for _, ap := range e.Upstreams {
		if ap.Addr().Unmap().Is6() && ap.Port() != 0 {
			out = append(out, ap.Port())
		}
	}
	slices.Sort(out)
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

// guardRules are the anchor's rules for tun and the upstreams' ports
// (none: no upstream rule), in order:
//
//	pass out quick on lo0 inet6 all no state
//	pass out quick on <utun> inet6 all no state
//	pass out quick inet6 from any to <thinkpol_exempt6> no state
//	pass out quick inet6 proto { tcp, udp } from any to <thinkpol_upstream6> port { <ports> } no state
//	pass out quick inet6 proto ipv6-icmp from any to <thinkpol_upstream6> icmp6-type { 135, 136 } no state
//	pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state
//	block return out quick inet6 all
//
// IPv6 only (IPv4's decisions stay whoever else's), outgoing only,
// stateless (a pass with state would put every tunnelled connection in
// pf's state table, whose limit is 10000 by default). Neighbour discovery
// needs no rule of its own: its destinations are link-local unicast and
// multicast, in the exempt table, and one to a global address leaves only
// if that address is exempt, or is an upstream's (an on-link upstream's
// unicast neighbour probes, solicitations 135 and advertisements 136). MLD reports go to their group, any multicast
// scope; pf can't match a hop limit (Linux requires 1), so the multicast
// destination is what keeps them on the link.
func guardRules(tun string, ports []uint16) []guardRule {
	with := func(w ...string) []string { return append([]string{"pass", "out", "quick", "inet6"}, w...) }
	rules := []guardRule{
		{"pass out quick on lo0 inet6 all no state", 1, with("on", "lo0")},
		{"pass out quick on " + tun + " inet6 all no state", 1, with("on", tun)},
		{"pass out quick inet6 from any to <" + exemptTable + "> no state", 1, with("<" + exemptTable + ">")},
	}
	if len(ports) > 0 {
		ps := make([]string, len(ports))
		for i, p := range ports {
			ps[i] = strconv.Itoa(int(p))
		}
		rules = append(rules,
			guardRule{"pass out quick inet6 proto { tcp, udp } from any to <" + upstreamTable + "> port { " + strings.Join(ps, ", ") + " } no state",
				2 * len(ports), with("<"+upstreamTable+">", "port")},
			guardRule{"pass out quick inet6 proto ipv6-icmp from any to <" + upstreamTable + "> icmp6-type { 135, 136 } no state",
				2, with("<"+upstreamTable+">", "icmp6-type")})
	}
	return append(rules,
		guardRule{"pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state", 4, with("ff00::/8", "icmp6-type")},
		guardRule{"block return out quick inet6 all", 1, []string{"block", "return", "out", "quick", "inet6"}},
	)
}

// anchorText is what the guard loads into its anchor: the tables, with
// their content, and the rules. One load is one pf transaction, so the
// rules and the tables they look up change together; a table defined
// with a list of addresses gets exactly that list on every load, `{ }`
// included (pf.conf(5)). Not `const`: that would keep pfctl -T from
// changing the tables, but OpenBSD's pf refuses to change a const table
// in place, and a reload that can't replace them would leave a wider
// exempt set behind; the guard's poll undoes a `-T add` instead.
func anchorText(tun string, exempt, upstreams []netip.Prefix, ports []uint16) string {
	var b strings.Builder
	table := func(name string, ps []netip.Prefix) {
		b.WriteString("table <" + name + "> persist {")
		for i, p := range ps {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(" \\\n\t" + p.String())
		}
		b.WriteString(" }\n")
	}
	table(exemptTable, exempt)
	table(upstreamTable, upstreams)
	for _, r := range guardRules(tun, ports) {
		b.WriteString(r.text + "\n")
	}
	return b.String()
}

// saneRules checks the anchor's rules as pfctl lists them right after a
// load: one listed rule per rule pfctl expands ours into, in order, each
// with the words it must hold, every pass stateless. pfctl prints a rule
// its own way (protocol and ICMPv6 type names, implied options), so this
// is no comparison of text; the listing it accepts is kept, and every
// later check compares the anchor with it exactly.
func saneRules(listed []string, tun string, ports []uint16) error {
	i := 0
	for _, r := range guardRules(tun, ports) {
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
