package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// fakePF is pf as pfctl shows it: the main ruleset's listing, anchors
// with rules and tables, enable references, states. It lists rules its
// own way, as pfctl does (one rule per list item, ICMPv6 types by name,
// `port = 53`), so a guard comparing the listing with the text it loaded
// fails here as it would on a Mac. No test here runs the real pfctl.
type fakePF struct {
	mu      sync.Mutex
	main    []string
	anchors map[string]*fakeAnchor
	refs    []fakeRef
	plainOn bool // `pfctl -e`: on without a reference
	next    uint64
	pid     int
	states  []fakeState
	calls   [][]string
	// fail fails every run whose args hold the key (words joined by
	// spaces).
	fail map[string]error
	// noToken: -E takes a reference but prints no token.
	noToken bool
	// reuse: the next -E's token has this value.
	reuse uint64
	// keepRefs: pfctl -d leaves the references listed (and -X fails
	// while off); forcedOff is pf off that way.
	keepRefs, forcedOff bool
	// flushMissingOK: -F of an anchor that doesn't exist succeeds;
	// otherwise it answers `Invalid argument`, as listing one does.
	flushMissingOK bool
	// oddReferences: -s References prints a layout the guard can't read.
	oddReferences bool
	// loadHook, if set, changes what a load puts in place.
	loadHook func(*fakeAnchor)
	// skip: the names `set skip on` gave, listed by -s Interfaces whether
	// an interface has the name or not (pfctl's source; unverified on a
	// Mac, TP-096).
	skip []string
	// hits are packets each rule of the guard's anchor matched, by index,
	// as `-s rules -v` counts them.
	hits map[int]uint64
}

type fakeRef struct {
	pfToken
	name string
}

type fakeAnchor struct {
	rules  []string
	tables map[string][]string // as loaded
	consts map[string]bool
}

func (a *fakeAnchor) clone() *fakeAnchor {
	c := &fakeAnchor{rules: slices.Clone(a.rules), tables: map[string][]string{}, consts: map[string]bool{}}
	for k, v := range a.tables {
		c.tables[k] = slices.Clone(v)
	}
	for k, v := range a.consts {
		c.consts[k] = v
	}
	return c
}

// fakeState is a state: the host's end, the other end, who opened it.
type fakeState struct {
	proto         string
	local, remote netip.AddrPort
	out           bool
}

// stockMain is the main ruleset as macOS loads it from /etc/pf.conf.
var stockMain = []string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`}

// stockApple are the anchors under com.apple that macOS loads from
// /etc/pf.anchors/com.apple, and a stock Mac lists.
var stockApple = []string{"com.apple/200.AirDrop", "com.apple/250.ApplicationFirewall"}

// fakeInterfaces are the host's interfaces as pf knows them.
var fakeInterfaces = []string{"all", "en0", "en1", "lo0", "utun7"}

func newFakePF() *fakePF {
	f := &fakePF{main: stockMain, anchors: map[string]*fakeAnchor{}, next: 9000000000000000001, pid: 4000, fail: map[string]error{}}
	for _, name := range stockApple {
		f.anchors[name] = &fakeAnchor{tables: map[string][]string{}, consts: map[string]bool{}}
	}
	return f
}

func (f *fakePF) on() bool { return !f.forcedOff && (len(f.refs) > 0 || f.plainOn) }

// disable is `pfctl -d`: off, every reference dropped, or with keepRefs
// only marked off.
func (f *fakePF) disable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keepRefs {
		f.forcedOff = true
		return
	}
	f.refs, f.plainOn = nil, false
}

// takeRef is another program's `pfctl -E` (the Application Firewall's).
func (f *fakePF) takeRef() pfToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pid++
	t := pfToken{value: f.next, pid: f.pid}
	f.next += 7
	f.refs = append(f.refs, fakeRef{t, "socketfilterfw"})
	return t
}

func (f *fakePF) set(fn func(f *fakePF)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakePF) anchor(name string) *fakeAnchor {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.anchors[name]
	if a == nil {
		return &fakeAnchor{tables: map[string][]string{}, consts: map[string]bool{}}
	}
	return a.clone()
}

func (f *fakePF) setAnchor(name string, a *fakeAnchor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchors[name] = a
}

func (f *fakePF) references() []pfToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []pfToken
	for _, r := range f.refs {
		out = append(out, r.pfToken)
	}
	return out
}

func (f *fakePF) isOn() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on()
}

func (f *fakePF) stateList() []fakeState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.states)
}

// ran counts the runs whose args hold key (words, joined by spaces)
// since the last forget.
func (f *fakePF) ran(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(" "+strings.Join(c, " ")+" ", " "+key+" ") {
			n++
		}
	}
	return n
}

func (f *fakePF) forget() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakePF) failOn(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.fail, key)
	} else {
		f.fail[key] = err
	}
}

var errFake = errors.New("exit status 1")

const altq = "No ALTQ support in kernel\nALTQ related functions disabled\n"

// reorderLikeBasic reproduces only the reordering pfctl's default rule
// optimizer, "basic", makes of the guard's rules on a Mac: the multicast
// icmp6 rules first, the rest in order. "basic" reorders the ruleset pf
// evaluates, not just its listing, and can do more than this (merge
// rules into a table).
func reorderLikeBasic(rules []string) []string {
	var multi, rest []string
	for _, r := range rules {
		if strings.Contains(r, "ff00::/8") {
			multi = append(multi, r)
		} else {
			rest = append(rest, r)
		}
	}
	return append(multi, rest...)
}

func (f *fakePF) run(ctx context.Context, stdin []byte, args ...string) (pfOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return pfOutput{}, err
	}
	f.calls = append(f.calls, args)
	f.pid++
	out := pfOutput{pid: f.pid, stderr: []byte(altq)}
	fail := func(msg string) (pfOutput, error) {
		out.stderr = append(out.stderr, msg+"\n"...)
		return out, fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), errFake, msg)
	}
	joined := " " + strings.Join(args, " ") + " "
	for k, err := range f.fail {
		if strings.Contains(joined, " "+k+" ") {
			return fail("pfctl: " + err.Error())
		}
	}
	// pfctl's options: the optimizer's level decides the order of the
	// rules a load puts in (none: as written; anything else: "basic"
	// reordered).
	optimize := ""
	rest := slices.Clone(args)
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] == "-o" {
			optimize, rest = rest[i+1], append(rest[:i:i], rest[i+2:]...)
			break
		}
	}
	anchor := ""
	if len(rest) >= 2 && rest[0] == "-a" {
		anchor, rest = rest[1], rest[2:]
	}
	args = rest
	a := f.anchors[anchor]
	var b strings.Builder
	switch {
	case slices.Equal(args, []string{"-s", "rules"}) && anchor == "":
		for _, l := range f.main {
			b.WriteString(l + "\n")
		}
	case slices.Equal(args, []string{"-s", "rules"}):
		if a == nil {
			return fail("pfctl: DIOCGETRULES: Invalid argument")
		}
		for _, l := range a.rules {
			b.WriteString(l + "\n")
		}
	case slices.Equal(args, []string{"-s", "rules", "-v"}) && anchor != "":
		// The counters' layout is pfctl's source's (pfctl_print_rule_counters),
		// as testdata/pfctl/rules-v.txt has it.
		if a == nil {
			return fail("pfctl: DIOCGETRULES: Invalid argument")
		}
		for i, l := range a.rules {
			n := f.hits[i]
			fmt.Fprintf(&b, "%s\n  [ Evaluations: %-8d  Packets: %-8d  Bytes: %-10d  States: %-6d]\n  [ Inserted: uid 0 pid %d ]\n", l, n+40, n, n*84, 0, 4000)
		}
	case slices.Equal(args, []string{"-s", "Interfaces", "-v"}) && anchor == "":
		for _, name := range slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(fakeInterfaces), f.skip...)))) {
			if slices.Contains(f.skip, name) {
				name += " (skip)"
			}
			b.WriteString(name + "\n")
		}
	case slices.Equal(args, []string{"-s", "Anchors"}) && anchor == appleAnchor:
		var children []string
		for name := range f.anchors {
			if child, ok := strings.CutPrefix(name, appleAnchor+"/"); ok && !strings.Contains(child, "/") {
				children = append(children, child)
			}
		}
		slices.Sort(children)
		for _, c := range children {
			b.WriteString("  " + appleAnchor + "/" + c + "\n")
		}
	case slices.Equal(args, []string{"-s", "info"}):
		status := "Disabled"
		if f.on() {
			status = "Enabled"
		}
		fmt.Fprintf(&b, "Status: %s for 0 days 00:01:02           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                        %d\n", status, len(f.states))
	case slices.Equal(args, []string{"-s", "References"}):
		if f.oddReferences {
			for _, r := range f.refs {
				fmt.Fprintf(&b, "token=%d by %s(%d)\n", r.value, r.name, r.pid)
			}
			break
		}
		b.WriteString("TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n")
		for _, r := range f.refs {
			fmt.Fprintf(&b, "%-8d %-28s %-21d 0 days 00:00:05\n", r.pid, r.name, r.value)
		}
	case slices.Equal(args, []string{"-s", "states"}):
		for _, s := range f.states {
			arrow := "->"
			if !s.out {
				arrow = "<-"
			}
			fmt.Fprintf(&b, "ALL %s %s %s %s       ESTABLISHED:ESTABLISHED\n", s.proto, fakeHost(s.local), arrow, fakeHost(s.remote))
		}
	case slices.Equal(args, []string{"-E"}):
		v := f.next
		f.next += 7
		if f.reuse != 0 {
			v, f.reuse = f.reuse, 0
		}
		f.refs = append(f.refs, fakeRef{pfToken{value: v, pid: out.pid}, "pfctl"})
		f.forcedOff = false
		out.stderr = append(out.stderr, "pf enabled\n"...)
		if !f.noToken {
			fmt.Fprintf(&b, "Token : %d\n", v)
		}
	case len(args) == 2 && args[0] == "-X":
		if !f.on() {
			return fail("pfctl: DIOCSTOPREF: No such file or directory")
		}
		v, _ := strconv.ParseUint(args[1], 10, 64)
		i := slices.IndexFunc(f.refs, func(r fakeRef) bool { return r.value == v })
		if i < 0 {
			return fail("pfctl: DIOCSTOPREF: No such process")
		}
		f.refs = slices.Delete(f.refs, i, i+1)
	case len(args) == 2 && args[0] == "-k" || len(args) == 4 && args[0] == "-k" && args[2] == "-k":
		src, err := fakeNet(args[1])
		if err != nil {
			return fail("pfctl: invalid host " + args[1])
		}
		dst := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		if src.Addr().Is4() {
			dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		if len(args) == 4 {
			if dst, err = fakeNet(args[3]); err != nil || dst.Addr().Is4() != src.Addr().Is4() {
				return fail("pfctl: invalid host " + args[3])
			}
		}
		// As XNU's DIOCKILLSTATES: a state's source is who opened it.
		killed := 0
		f.states = slices.DeleteFunc(f.states, func(s fakeState) bool {
			from, to := s.local.Addr(), s.remote.Addr()
			if !s.out {
				from, to = to, from
			}
			if from.Is4() != src.Addr().Is4() || !src.Contains(from) || !dst.Contains(to) {
				return false
			}
			killed++
			return true
		})
		out.stderr = fmt.Appendf(out.stderr, "killed %d states from 1 sources and 0 destinations\n", killed)
	case anchor != "" && slices.Equal(rest, []string{"-f", "-"}):
		loaded, err := fakeLoad(string(stdin))
		if err != nil {
			return fail("pfctl: " + err.Error())
		}
		if optimize != "none" {
			// The fake's ruleset is its listing: what pf evaluates.
			loaded.rules = reorderLikeBasic(loaded.rules)
		}
		if f.loadHook != nil {
			f.loadHook(loaded)
		}
		// OpenBSD's pf refuses to change an active const table in place.
		if a != nil {
			for name, entries := range loaded.tables {
				if a.consts[name] && !slices.Equal(a.tables[name], entries) {
					return fail("pfctl: DIOCXCOMMIT: Operation not permitted")
				}
			}
		}
		f.anchors[anchor] = loaded
	case anchor != "" && slices.Equal(args, []string{"-F", "rules"}):
		if a == nil {
			if f.flushMissingOK {
				break
			}
			return fail("pfctl: DIOCBEGINRULES: Invalid argument")
		}
		a.rules = nil
	case anchor != "" && slices.Equal(args, []string{"-F", "Tables"}):
		if a == nil {
			if f.flushMissingOK {
				break
			}
			return fail("pfctl: DIOCRCLRTABLES: Invalid argument")
		}
		a.tables, a.consts = map[string][]string{}, map[string]bool{}
		if len(a.rules) == 0 {
			delete(f.anchors, anchor)
		}
	case anchor != "" && len(args) == 4 && args[0] == "-t" && args[2] == "-T" && args[3] == "show":
		if a == nil {
			return fail("pfctl: DIOCRGETADDRS: Invalid argument")
		}
		entries, ok := a.tables[args[1]]
		if !ok {
			return fail("pfctl: Table does not exist.")
		}
		for _, e := range entries {
			b.WriteString("   " + strings.TrimSuffix(e, "/128") + "\n")
		}
	default:
		return fail(fmt.Sprintf("fake pfctl: unexpected %q", args))
	}
	out.stdout = []byte(b.String())
	return out, nil
}

func fakeHost(ap netip.AddrPort) string {
	if ap.Addr().Is4() {
		return ap.String()
	}
	return fmt.Sprintf("%s[%d]", ap.Addr(), ap.Port())
}

func fakeNet(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// icmp6Names are the names pfctl lists some ICMPv6 types by: the first
// entry for the number in its icmp6 type table, which names 130-132
// twice (groupqry/listqry, grouprep/listenrep, groupterm/listendone)
// and has no name for 143.
var icmp6Names = map[string]string{"130": "groupqry", "131": "grouprep", "132": "groupterm", "133": "routersol", "134": "routeradv", "135": "neighbrsol", "136": "neighbradv", "137": "redir"}

var portNumber = regexp.MustCompile(`\bport ([0-9]+)\b`)

// fakeLoad parses an anchor's text as far as the guard writes it: tables
// with lists, then rules, each listed as pfctl would.
func fakeLoad(text string) (*fakeAnchor, error) {
	text = strings.ReplaceAll(text, "\\\n", " ")
	a := &fakeAnchor{tables: map[string][]string{}, consts: map[string]bool{}}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "table <"):
			m := regexp.MustCompile(`^table <([a-z0-9_]+)> ((?:const |persist )+)\{(.*)\}$`).FindStringSubmatch(l)
			if m == nil {
				return nil, fmt.Errorf("stdin: syntax error in %q", l)
			}
			a.tables[m[1]] = strings.FieldsFunc(m[3], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
			a.consts[m[1]] = strings.Contains(m[2], "const")
		case strings.HasPrefix(l, "pass ") || strings.HasPrefix(l, "block "):
			for _, t := range regexp.MustCompile(`<([a-z0-9_]+)>`).FindAllStringSubmatch(l, -1) {
				if _, ok := a.tables[t[1]]; !ok {
					return nil, fmt.Errorf("stdin: table <%s> not defined", t[1])
				}
			}
			a.rules = append(a.rules, fakeExpand(l)...)
		default:
			return nil, fmt.Errorf("stdin: syntax error in %q", l)
		}
	}
	return a, nil
}

// fakeExpand is one rule as pfctl lists it: one rule per item of each
// `{ ... }` list, `port = N`, ICMPv6 types by name, `from any to` kept
// as pfctl lists it.
func fakeExpand(rule string) []string {
	i := strings.Index(rule, "{ ")
	if i < 0 {
		rule = portNumber.ReplaceAllString(rule, "port = $1")
		if j := strings.Index(rule, "icmp6-type "); j >= 0 {
			f := strings.Fields(rule[j:])
			if name := icmp6Names[f[1]]; name != "" {
				rule = rule[:j] + "icmp6-type " + name + rule[j+len("icmp6-type ")+len(f[1]):]
			}
		}
		return []string{rule}
	}
	j := strings.Index(rule[i:], " }") + i
	var out []string
	for _, item := range strings.Split(rule[i+2:j], ", ") {
		out = append(out, fakeExpand(rule[:i]+item+rule[j+2:])...)
	}
	return out
}
