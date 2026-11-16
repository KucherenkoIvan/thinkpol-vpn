//go:build lab

package lab_test

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// A matrix row runs all its cells in one lab, one after another, so each
// cell must start from the state the first one did: after a cell, the lab
// is reset to the state recorded when the row's lab came up (cleanLab),
// and the reset is checked. A cell whose reset didn't hold is an error,
// and so is every later cell of its row.

// nodeStateScript prints what a cell may leave behind in a node, one
// "<kind> <what>" line each: its processes (but the script's own), links,
// policy rules, nftables tables, NFQUEUE queues bound, and the entries of
// the directories transports and censord write to. /run/lab is the lab's
// own (the seal marker, Process pid files).
const nodeStateScript = `
ps -eo pid=,ppid=,args= | awk -v me=$$ '$1 != me && $2 != me { pid = $1; $1 = ""; $2 = ""; sub(/^ +/, ""); print "process " pid " " $0 }'
ip -br link show | awk '{ sub(/@.*/, "", $1); print "link " $1 }'
ip -4 rule show | sed 's/^/rule4 /'
ip -6 rule show | sed 's/^/rule6 /'
nft list tables | sed 's/^/nft /'
awk '{ print "queue " $1 }' /proc/net/netfilter/nfnetlink_queue 2>/dev/null
find /tmp /run /var/lib -mindepth 1 -maxdepth 1 ! -path /run/lab | sed 's/^/file /'
`

// nodeState is a node's nodeStateScript lines by kind, sorted.
type nodeState map[string][]string

func parseNodeState(out string) nodeState {
	s := nodeState{}
	for _, line := range strings.Split(out, "\n") {
		kind, what, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		s[kind] = append(s[kind], what)
	}
	for _, lines := range s {
		slices.Sort(lines)
	}
	return s
}

// diff is what now has that clean hasn't (extra), and what clean has that
// now lacks (missing), by kind.
func (clean nodeState) diff(now nodeState) (extra, missing nodeState) {
	extra, missing = nodeState{}, nodeState{}
	kinds := map[string]bool{}
	for k := range clean {
		kinds[k] = true
	}
	for k := range now {
		kinds[k] = true
	}
	for kind := range kinds {
		for _, w := range now[kind] {
			if !slices.Contains(clean[kind], w) {
				extra[kind] = append(extra[kind], w)
			}
		}
		for _, w := range clean[kind] {
			if !slices.Contains(now[kind], w) {
				missing[kind] = append(missing[kind], w)
			}
		}
	}
	return extra, missing
}

func (s nodeState) String() string {
	var b strings.Builder
	for _, kind := range slices.Sorted(maps.Keys(s)) {
		for _, w := range s[kind] {
			fmt.Fprintf(&b, "\n  %s %s", kind, w)
		}
	}
	return b.String()
}

// undo is the commands that remove what extra holds but processes (which
// the reset kills first): tables, links, policy rules, files.
func (extra nodeState) undo() [][]string {
	var cmds [][]string
	for _, table := range extra["nft"] {
		cmds = append(cmds, append([]string{"nft", "delete"}, strings.Fields(table)...))
	}
	for _, link := range extra["link"] {
		cmds = append(cmds, []string{"ip", "link", "del", link})
	}
	for _, f := range []struct{ flag, kind string }{{"-4", "rule4"}, {"-6", "rule6"}} {
		for _, rule := range extra[f.kind] {
			// "32765:	from all lookup 52"
			pref, spec, _ := strings.Cut(rule, ":")
			cmds = append(cmds, append([]string{"ip", f.flag, "rule", "del", "pref", pref}, strings.Fields(spec)...))
		}
	}
	if files := extra["file"]; len(files) > 0 {
		cmds = append(cmds, append([]string{"rm", "-rf", "--"}, files...))
	}
	return cmds
}

// pids is the process ids of a state's process lines.
func (s nodeState) pids() []string {
	var pids []string
	for _, p := range s["process"] {
		pid, _, _ := strings.Cut(p, " ")
		pids = append(pids, pid)
	}
	return pids
}

// TestNodeState: a node's state reads by kind, a cell's leftovers are
// extra, what it removed is missing, and the reset's commands undo the
// extras, a policy rule by its whole spec.
func TestNodeState(t *testing.T) {
	clean := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nlink lo\nlink eth0\n" +
		"rule4 0:\tfrom all lookup local\nnft table netdev tplab_eth0\nfile /tmp/camouflage\n")
	now := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nprocess 90 thinkpol up\nlink lo\nlink wg4\n" +
		"rule4 0:\tfrom all lookup local\nrule4 5208:\tfrom all fwmark 0x5 lookup 52\nnft table netdev tplab_eth0\nnft table inet censor\n" +
		"queue 100\nfile /tmp/camouflage\nfile /run/censor\nfile /var/lib/thinkpol\n")
	extra, missing := clean.diff(now)
	want := nodeState{"process": {"90 thinkpol up"}, "link": {"wg4"}, "rule4": {"5208:\tfrom all fwmark 0x5 lookup 52"},
		"nft": {"table inet censor"}, "queue": {"100"}, "file": {"/run/censor", "/var/lib/thinkpol"}}
	if !maps.EqualFunc(extra, want, slices.Equal) {
		t.Errorf("extra:%s\nwant:%s", extra, want)
	}
	if !maps.EqualFunc(missing, nodeState{"link": {"eth0"}}, slices.Equal) {
		t.Errorf("missing:%s", missing)
	}
	if got := extra.pids(); !slices.Equal(got, []string{"90"}) {
		t.Errorf("pids: %v", got)
	}
	got := extra.undo()
	wantCmds := [][]string{
		{"nft", "delete", "table", "inet", "censor"},
		{"ip", "link", "del", "wg4"},
		{"ip", "-4", "rule", "del", "pref", "5208", "from", "all", "fwmark", "0x5", "lookup", "52"},
		{"rm", "-rf", "--", "/run/censor", "/var/lib/thinkpol"},
	}
	if !slices.EqualFunc(got, wantCmds, slices.Equal) {
		t.Errorf("undo: %q\nwant %q", got, wantCmds)
	}
	if e, m := clean.diff(clean); len(e) > 0 || len(m) > 0 {
		t.Errorf("a state differs from itself: %s / %s", e, m)
	}
}

// matrixRow is a row's lab and the state each of its cells starts from.
type matrixRow struct {
	lab   *lab.Lab
	clean map[string]nodeState // by node name
	// broken is set once a reset didn't hold: the rest of the row can't
	// be trusted.
	broken error
}

// startRow brings up the row's lab: lab.Upstream, the camouflage site
// running for every cell (the prober, server-hello and the rows that
// splice to it start it in vain), and the router's conntrack empty; that
// is the clean state.
func startRow(t *testing.T) *matrixRow {
	l := lab.StartOwnSlot(t, lab.Upstream())
	lab.StartCamouflage(t, l)
	if _, err := execRead(l.Node(lab.Router), execTimeout, "censord", "-reset"); err != nil {
		t.Fatal(err)
	}
	row := &matrixRow{lab: l, clean: map[string]nodeState{}}
	states, err := row.states()
	if err != nil {
		t.Fatal(err)
	}
	row.clean = states
	return row
}

// states reads every node's state at once.
func (r *matrixRow) states() (map[string]nodeState, error) {
	nodes := r.lab.Nodes()
	out := make([]nodeState, len(nodes))
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Go(func() {
			s, err := execRead(n, pollTimeout, "sh", "-c", nodeStateScript)
			out[i], errs[i] = parseNodeState(s), err
		})
	}
	wg.Wait()
	states := map[string]nodeState{}
	for i, n := range nodes {
		states[n.Name] = out[i]
	}
	return states, errors.Join(errs...)
}

// eachNode runs f for every node at once.
func (r *matrixRow) eachNode(f func(n *lab.Node) error) error {
	nodes := r.lab.Nodes()
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Go(func() { errs[i] = f(n) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// reset puts the lab back in its clean state after a cell, whose own
// cleanups have stopped its processes and censord, and checks it held:
// it kills what still runs, then (nothing running to make new flows)
// removes the links, policy rules, tables and files the cell left,
// clears the router's censor table and conntrack (censord -reset), which
// also removes the verdict log, and reads every node back.
func (r *matrixRow) reset() error {
	if r.broken != nil {
		return r.broken
	}
	err := r.eachNode(func(n *lab.Node) error {
		extra, err := r.leftovers(n)
		if err != nil || len(extra["process"]) == 0 {
			return err
		}
		// A process may exit between the read and the kill: what still
		// runs after is what counts.
		if _, err := execRead(n, pollTimeout, append([]string{"sh", "-c", `kill -KILL "$@" 2>/dev/null; true`, "sh"}, extra.pids()...)...); err != nil {
			return err
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			extra, err := r.leftovers(n)
			switch {
			case err != nil:
				return err
			case len(extra["process"]) == 0:
				return nil
			case time.Now().After(deadline):
				return fmt.Errorf("%s: processes outlived SIGKILL:%s", n.Name, nodeState{"process": extra["process"]})
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	if err == nil {
		err = r.eachNode(func(n *lab.Node) error {
			extra, err := r.leftovers(n)
			if err != nil {
				return err
			}
			var errs []error
			for _, cmd := range extra.undo() {
				if _, err := execRead(n, pollTimeout, cmd...); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		})
	}
	if err == nil {
		_, err = execRead(r.lab.Node(lab.Router), pollTimeout, "censord", "-reset")
	}
	if err == nil {
		err = r.check()
	}
	if err != nil {
		r.broken = fmt.Errorf("an earlier cell's reset didn't hold: %w", err)
	}
	return err
}

// leftovers is what n has beyond its clean state.
func (r *matrixRow) leftovers(n *lab.Node) (nodeState, error) {
	out, err := execRead(n, pollTimeout, "sh", "-c", nodeStateScript)
	if err != nil {
		return nil, err
	}
	extra, _ := r.clean[n.Name].diff(parseNodeState(out))
	return extra, nil
}

var queueStatement = regexp.MustCompile(`(?m)^\s*(.*\s)?queue\s`)

// check is nil when every node is in its clean state, and the router has
// no censor table, no queue rule and no conntrack entry.
func (r *matrixRow) check() error {
	states, err := r.states()
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(states)) {
		extra, missing := r.clean[name].diff(states[name])
		if len(extra) > 0 {
			errs = append(errs, fmt.Errorf("%s: left after the cell:%s", name, extra))
		}
		if len(missing) > 0 {
			errs = append(errs, fmt.Errorf("%s: gone since the row's lab came up:%s", name, missing))
		}
	}
	router := r.lab.Node(lab.Router)
	for _, table := range states[lab.Router]["nft"] {
		if f := strings.Fields(table); strings.HasPrefix(f[len(f)-1], "censor") {
			errs = append(errs, fmt.Errorf("router: a censor table outlived the reset: %s", table))
		}
	}
	ruleset, err := execRead(router, pollTimeout, "nft", "list", "ruleset")
	if err != nil {
		errs = append(errs, err)
	} else if queueStatement.MatchString(ruleset) {
		errs = append(errs, fmt.Errorf("router: a queue rule outlived the reset:\n%s", ruleset))
	}
	count, err := execRead(router, pollTimeout, "cat", "/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		errs = append(errs, err)
	} else if n := strings.TrimSpace(count); n != "0" {
		errs = append(errs, fmt.Errorf("router: %s conntrack entries outlived the reset", n))
	}
	return errors.Join(errs...)
}
