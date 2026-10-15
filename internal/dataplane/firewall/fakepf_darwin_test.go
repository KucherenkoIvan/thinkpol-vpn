package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// fakePF is pf as pfctl shows it: the main ruleset's listing, anchors
// with rules and a table, enable references. It lists rules its own way,
// as pfctl does (one rule per ICMPv6 type, by name), so a guard comparing
// the listing with the text it loaded fails here as it would on a Mac.
// No test here runs the real pfctl.
type fakePF struct {
	mu      sync.Mutex
	main    []string
	anchors map[string]*fakeAnchor
	refs    []pfToken
	plainOn bool // `pfctl -e`: on without a reference
	next    uint64
	pid     int
	calls   [][]string
	// fail fails every run whose args hold the key (joined by spaces).
	fail map[string]error
	// noToken: -E takes a reference but prints no token.
	noToken bool
	// reuse: the next -E's token has this value.
	reuse uint64
}

type fakeAnchor struct {
	rules []string
	table []string // as loaded
}

// stockMain is the main ruleset as macOS loads it from /etc/pf.conf.
var stockMain = []string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`}

func newFakePF() *fakePF {
	return &fakePF{main: stockMain, anchors: map[string]*fakeAnchor{}, next: 9000000000000000001, pid: 4000, fail: map[string]error{}}
}

func (f *fakePF) on() bool { return len(f.refs) > 0 || f.plainOn }

// disable is `pfctl -d`: off, every reference dropped.
func (f *fakePF) disable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs, f.plainOn = nil, false
}

// takeRef is another program's `pfctl -E`.
func (f *fakePF) takeRef() pfToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pid++
	t := pfToken{value: f.next, pid: f.pid}
	f.next += 7
	f.refs = append(f.refs, t)
	return t
}

func (f *fakePF) anchor(name string) *fakeAnchor {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.anchors[name]
	if a == nil {
		return &fakeAnchor{}
	}
	return &fakeAnchor{rules: slices.Clone(a.rules), table: slices.Clone(a.table)}
}

func (f *fakePF) setAnchor(name string, a *fakeAnchor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchors[name] = a
}

func (f *fakePF) references() []pfToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.refs)
}

func (f *fakePF) isOn() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on()
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

// fakeLoadHook, if set, changes what a load puts in place.
var fakeLoadHook func(*fakeAnchor)

func (f *fakePF) run(ctx context.Context, stdin []byte, args ...string) (pfOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return pfOutput{}, err
	}
	f.calls = append(f.calls, args)
	f.pid++
	out := pfOutput{pid: f.pid, stderr: []byte("No ALTQ support in kernel\nALTQ related functions disabled\n")}
	joined := " " + strings.Join(args, " ") + " "
	for k, err := range f.fail {
		if strings.Contains(joined, " "+k+" ") {
			return out, fmt.Errorf("pfctl %s: %w", strings.Join(args, " "), err)
		}
	}
	anchor := ""
	if len(args) >= 2 && args[0] == "-a" {
		anchor, args = args[1], args[2:]
	}
	var b strings.Builder
	switch {
	case slices.Equal(args, []string{"-s", "rules"}) && anchor == "":
		for _, l := range f.main {
			b.WriteString(l + "\n")
		}
	case slices.Equal(args, []string{"-s", "rules"}):
		a := f.anchors[anchor]
		if a == nil {
			return out, fmt.Errorf("pfctl: DIOCGETRULES: Invalid argument: %w", errFake)
		}
		for _, l := range a.rules {
			b.WriteString(l + "\n")
		}
	case slices.Equal(args, []string{"-s", "info"}):
		status := "Disabled"
		if f.on() {
			status = "Enabled"
		}
		fmt.Fprintf(&b, "Status: %s for 0 days 00:01:02           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                        0\n", status)
	case slices.Equal(args, []string{"-s", "References"}):
		b.WriteString("TOKENS:\nPID      Process Name                 TOKEN                 TIMESTAMP\n")
		for _, t := range f.refs {
			fmt.Fprintf(&b, "%-8d %-28s %-21d 0 days 00:00:05\n", t.pid, "pfctl", t.value)
		}
	case slices.Equal(args, []string{"-E"}):
		v := f.next
		f.next += 7
		if f.reuse != 0 {
			v, f.reuse = f.reuse, 0
		}
		f.refs = append(f.refs, pfToken{value: v, pid: out.pid})
		out.stderr = append(out.stderr, "pf enabled\n"...)
		if !f.noToken {
			fmt.Fprintf(&b, "Token : %d\n", v)
		}
	case len(args) == 2 && args[0] == "-X":
		v, _ := strconv.ParseUint(args[1], 10, 64)
		i := slices.IndexFunc(f.refs, func(t pfToken) bool { return t.value == v })
		if i < 0 {
			return out, fmt.Errorf("pfctl: DIOCSTOPREF: No such process: %w", errFake)
		}
		f.refs = slices.Delete(f.refs, i, i+1)
	case anchor != "" && slices.Equal(args, []string{"-f", "-"}):
		a, err := fakeLoad(string(stdin))
		if err != nil {
			return out, err
		}
		if fakeLoadHook != nil {
			fakeLoadHook(a)
		}
		f.anchors[anchor] = a
	case anchor != "" && slices.Equal(args, []string{"-F", "rules"}):
		if a := f.anchors[anchor]; a != nil {
			a.rules = nil
		}
	case anchor != "" && slices.Equal(args, []string{"-F", "Tables"}):
		if a := f.anchors[anchor]; a != nil {
			a.table = nil
		}
	case anchor != "" && len(args) == 4 && args[0] == "-t" && args[2] == "-T" && args[3] == "show":
		a := f.anchors[anchor]
		if a == nil || a.table == nil || args[1] != guardTable {
			return out, fmt.Errorf("pfctl: Table does not exist: %w", errFake)
		}
		for _, e := range a.table {
			b.WriteString("   " + strings.TrimSuffix(e, "/128") + "\n")
		}
	default:
		return out, fmt.Errorf("fake pfctl: unexpected %q: %w", args, errFake)
	}
	out.stdout = []byte(b.String())
	return out, nil
}

// icmp6Names are pfctl's names for the ICMPv6 types the guard passes.
var icmp6Names = map[string]string{"133": "routersol", "134": "routeradv", "135": "neighbrsol", "136": "neighbradv", "137": "redir", "130": "listqry", "131": "listenrep", "132": "listendone"}

// fakeLoad parses an anchor's text as far as the guard writes it: one
// table with a list, then rules, each listed as pfctl would.
func fakeLoad(text string) (*fakeAnchor, error) {
	text = strings.ReplaceAll(text, "\\\n", " ")
	a := &fakeAnchor{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "table "):
			open, end := strings.Index(l, "{"), strings.LastIndex(l, "}")
			if open < 0 || end < open || !strings.HasPrefix(l, "table <"+guardTable+"> const persist {") {
				return nil, fmt.Errorf("stdin: syntax error in %q: %w", l, errFake)
			}
			a.table = append(a.table, strings.FieldsFunc(l[open+1:end], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })...)
			if a.table == nil {
				a.table = []string{}
			}
		case strings.HasPrefix(l, "pass ") || strings.HasPrefix(l, "block "):
			l = strings.Replace(l, "from any to", "to", 1)
			if i := strings.Index(l, "icmp6-type { "); i >= 0 {
				j := strings.Index(l[i:], "}") + i
				for _, ty := range strings.Split(l[i+len("icmp6-type { "):j], ", ") {
					name := icmp6Names[strings.TrimSpace(ty)]
					if name == "" {
						name = strings.TrimSpace(ty)
					}
					a.rules = append(a.rules, l[:i]+"icmp6-type "+name+l[j+1:])
				}
				continue
			}
			a.rules = append(a.rules, l)
		default:
			return nil, fmt.Errorf("stdin: syntax error in %q: %w", l, errFake)
		}
	}
	if a.table == nil {
		return nil, fmt.Errorf("stdin: no table: %w", errFake)
	}
	return a, nil
}
