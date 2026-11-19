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

// A matrix row runs its cells in one lab or a few (rowLabs), each lab's
// one after another, so each cell must start from the state the lab's
// first one did: after a cell, the lab is reset to the state recorded when
// it came up (cleanLab), and the reset is checked. A cell whose reset
// didn't hold is an error, and so is every later cell of its lab.

// nodeStateScript prints what a cell may leave behind in a node, one
// "<kind> <what>" line each: its processes (but the script's own), links,
// addresses, routes in every table, policy rules, nftables tables, NFQUEUE
// queues bound, and the entries of the directories transports and censord
// write to. /run/lab is the lab's own (the seal marker, Process pid
// files). Left out, as the kernel changes them on its own between cells:
// neighbour entries, route expiry times, a route's linkdown flag and
// routes learnt from router advertisements. A link's own routes come and
// go with it.
const nodeStateScript = `
ps -eo pid=,ppid=,args= | awk -v me=$$ '$1 != me && $2 != me { pid = $1; $1 = ""; $2 = ""; sub(/^ +/, ""); print "process " pid " " $0 }'
ip -br link show | awk '{ sub(/@.*/, "", $1); print "link " $1 }'
ip -br addr show | awk '{ sub(/@.*/, "", $1); for (i = 3; i <= NF; i++) print "addr " $1 " " $i }'
ip -4 route show table all | grep -v 'proto ra' | sed -e 's/ expires [^ ]*//' -e 's/ linkdown//' -e 's/ *$//' -e 's/^/route4 /'
ip -6 route show table all | grep -v 'proto ra' | sed -e 's/ expires [^ ]*//' -e 's/ linkdown//' -e 's/ *$//' -e 's/^/route6 /'
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
// the reset kills first) and routes and addresses (undoAddressing): tables,
// links, policy rules, files.
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

// undoAddressing is the commands that remove the routes and addresses
// extra holds. Read after undo's commands ran: the routes and addresses of
// a link they deleted are gone with it, and deleting them again would fail.
func (extra nodeState) undoAddressing() [][]string {
	var cmds [][]string
	for _, f := range []struct{ flag, kind string }{{"-4", "route4"}, {"-6", "route6"}} {
		for _, route := range extra[f.kind] {
			cmds = append(cmds, append([]string{"ip", f.flag, "route", "del"}, strings.Fields(route)...))
		}
	}
	for _, a := range extra["addr"] {
		if link, cidr, ok := strings.Cut(a, " "); ok {
			cmds = append(cmds, []string{"ip", "addr", "del", cidr, "dev", link})
		}
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
// extras, a policy rule and a route by their whole spec.
func TestNodeState(t *testing.T) {
	clean := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nlink lo\nlink eth0\n" +
		"rule4 0:\tfrom all lookup local\nnft table netdev tplab_eth0\nfile /tmp/camouflage\n")
	now := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nprocess 90 thinkpol up\nlink lo\nlink wg4\n" +
		"rule4 0:\tfrom all lookup local\nrule4 5208:\tfrom all fwmark 0x5 lookup 52\nnft table netdev tplab_eth0\nnft table inet censor\n" +
		"queue 100\nfile /tmp/camouflage\nfile /run/censor\nfile /var/lib/thinkpol\n" +
		"route4 default dev wg4 table 52 scope link\nroute6 2001:db8::/64 dev eth0 metric 1024 pref medium\naddr eth0 192.0.2.9/32\n")
	extra, missing := clean.diff(now)
	want := nodeState{"process": {"90 thinkpol up"}, "link": {"wg4"}, "rule4": {"5208:\tfrom all fwmark 0x5 lookup 52"},
		"nft": {"table inet censor"}, "queue": {"100"}, "file": {"/run/censor", "/var/lib/thinkpol"},
		"route4": {"default dev wg4 table 52 scope link"}, "route6": {"2001:db8::/64 dev eth0 metric 1024 pref medium"},
		"addr": {"eth0 192.0.2.9/32"}}
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
	gotAddressing := extra.undoAddressing()
	wantAddressing := [][]string{
		{"ip", "-4", "route", "del", "default", "dev", "wg4", "table", "52", "scope", "link"},
		{"ip", "-6", "route", "del", "2001:db8::/64", "dev", "eth0", "metric", "1024", "pref", "medium"},
		{"ip", "addr", "del", "192.0.2.9/32", "dev", "eth0"},
	}
	if !slices.EqualFunc(gotAddressing, wantAddressing, slices.Equal) {
		t.Errorf("undoAddressing: %q\nwant %q", gotAddressing, wantAddressing)
	}
	if e, m := clean.diff(clean); len(e) > 0 || len(m) > 0 {
		t.Errorf("a state differs from itself: %s / %s", e, m)
	}
}

// matrixRow is one of a row's labs and the state each of its cells starts
// from.
type matrixRow struct {
	lab   *lab.Lab
	clean map[string]nodeState // by node name
	// broken is set once a reset didn't hold: the rest of the row can't
	// be trusted.
	broken error
}

// startRow brings up the row's lab: lab.Upstream's router, device-a,
// server-1 and camouflage, the camouflage site running for every cell
// (the prober, server-hello and the rows that splice to it start it in
// vain), and the router's conntrack empty; that is the clean state.
//
// Those are the nodes the row's cells drive: device-a and server-1 are
// the transport's ends (the control rows' client and server, the
// reference VPNs' peers), the router runs censord, and the camouflage
// site is what the prober and server-hello compare every row's server
// with, what the relay-tcp and reality rows splice to, and, being outside
// the space and not the censor, where the thinkpol rows' maps are built.
// No cell reaches device-b, server-2 or internet, so they aren't started.
func startRow(t *testing.T) *matrixRow {
	begin := time.Now()
	var up, cellsDone time.Time
	// Registered first, so it runs last, after the lab's tear-down: what
	// the lab's start and tear-down cost next to its cells is what
	// splitting a row trades (transport.labs).
	t.Cleanup(func() {
		if !up.IsZero() && !cellsDone.IsZero() {
			t.Logf("lab: up in %v, cells %v, down in %v", up.Sub(begin).Round(time.Second), cellsDone.Sub(up).Round(time.Second), time.Since(cellsDone).Round(time.Second))
		}
	})
	l := lab.StartOwnSlot(t, lab.Upstream().Only(lab.Router, lab.DeviceA, lab.Server1, lab.Camouflage))
	t.Cleanup(func() { cellsDone = time.Now() })
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
	up = time.Now()
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
// it kills what still runs and aborts every TCP connection left (orphaned
// or held by a clean-state process), then (nothing left to make new
// flows) removes the links, policy rules, tables and files the cell left
// (the verdict log with /run/censor), then the routes and addresses left on
// the links that remain, clears the router's censor table and conntrack
// (censord -reset, clearRouter), and reads every node back.
func (r *matrixRow) reset(logf func(format string, args ...any)) error {
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
		// A killed process's TCP sockets live on as orphans, and a peer
		// left running (the camouflage site's nginx) keeps its end:
		// either retransmits for minutes, each time the censor dropped
		// it, and a retransmission after the router's flush makes a
		// conntrack entry the check finds (reality's handshakes with its
		// target, cut by ip-blocklist). An RST from the abort makes no
		// entry of its own.
		err = r.eachNode(func(n *lab.Node) error { return r.abortTCP(n, logf) })
	}
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
		err = r.eachNode(func(n *lab.Node) error {
			extra, err := r.leftovers(n)
			if err != nil {
				return err
			}
			var errs []error
			for _, cmd := range extra.undoAddressing() {
				if _, err := execRead(n, pollTimeout, cmd...); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		})
	}
	if err == nil {
		err = r.clearRouter()
	}
	if err == nil {
		err = r.check()
	}
	if err != nil {
		r.broken = fmt.Errorf("an earlier cell's reset didn't hold: %w", err)
	}
	return err
}

// abortTCP aborts every TCP connection n has (ss -K: the clean state has
// listeners only), logs the ones it aborted, and fails when one is left:
// ss -K exits 0 and kills nothing on a kernel without INET_DIAG_DESTROY.
func (r *matrixRow) abortTCP(n *lab.Node, logf func(format string, args ...any)) error {
	aborted, err := execRead(n, pollTimeout, "ss", "-K", "-H", "-n", "-t", "state", "connected")
	if err != nil {
		return err
	}
	left, err := execRead(n, pollTimeout, "ss", "-H", "-n", "-t", "state", "connected", "exclude", "time-wait")
	if err != nil {
		return err
	}
	return tcpAborted(n.Name, aborted, left, logf)
}

// tcpAborted logs the TCP connections ss -K aborted on node, which a
// transport that leaks them after its down shows there, and is an error
// listing the ones left. TIME-WAIT is left out: it sends nothing unless a
// FIN comes again, and its peer's end, the one that could, was aborted.
func tcpAborted(node, aborted, left string, logf func(format string, args ...any)) error {
	if a := strings.TrimSpace(aborted); a != "" {
		logf("%s: the reset aborted %d TCP connections:\n%s", node, len(strings.Split(a, "\n")), a)
	}
	if l := strings.TrimSpace(left); l != "" {
		return fmt.Errorf("%s: %d TCP connections outlived the reset's abort (ss -K):\n%s", node, len(strings.Split(l, "\n")), l)
	}
	return nil
}

// TestTCPAborted: what ss -K aborted is logged and passes; a connection
// left after it, as on a kernel that can't destroy sockets, fails the
// reset with the connections listed.
func TestTCPAborted(t *testing.T) {
	conn := "ESTAB 0 0 192.0.2.2:40000 192.0.2.3:443"
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	if err := tcpAborted("server-1", conn+"\n", "", logf); err != nil {
		t.Errorf("all aborted: %v", err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], conn) || !strings.Contains(logged[0], "server-1: the reset aborted 1 TCP") {
		t.Errorf("all aborted: logged %q, want the connection named", logged)
	}
	logged = nil
	if err := tcpAborted("router", "\n", "", logf); err != nil || len(logged) != 0 {
		t.Errorf("nothing to abort: %v, logged %q", err, logged)
	}
	err := tcpAborted("server-1", "", conn+"\n", logf)
	if err == nil || !strings.Contains(err.Error(), conn) || !strings.Contains(err.Error(), "server-1: 1 TCP connections outlived") {
		t.Errorf("one left: %v, want an error listing it", err)
	}
}

// conntrackCount and conntrackEntries read the router's conntrack: how
// many entries, and each (censord -conntrack).
func (r *matrixRow) conntrackCount() (string, error) {
	return execRead(r.lab.Node(lab.Router), pollTimeout, "cat", "/proc/sys/net/netfilter/nf_conntrack_count")
}

func (r *matrixRow) conntrackEntries() (string, error) {
	return execRead(r.lab.Node(lab.Router), pollTimeout, "censord", "-conntrack")
}

// conntrackLeft is the error for n entries left in the router's
// conntrack, listed by list.
func conntrackLeft(n, how string, list func() (string, error)) error {
	entries, err := list()
	if err != nil {
		entries = fmt.Sprintf("(couldn't list them: %v)", err)
	}
	return fmt.Errorf("router: %s conntrack entries %s:\n%s", n, how, strings.TrimSpace(entries))
}

// clearRouter clears the router's censor table and conntrack until no
// entry comes back (clearUntilEmpty), within 30 s.
func (r *matrixRow) clearRouter() error {
	router := r.lab.Node(lab.Router)
	return clearUntilEmpty(
		func() error {
			_, err := execRead(router, pollTimeout, "censord", "-reset")
			return err
		},
		r.conntrackCount,
		r.conntrackEntries,
		// A retransmission that would make a new entry is an absence no
		// watcher can see: the settle is a window, once per cell.
		time.Second, 30*time.Second)
}

// clearUntilEmpty clears, waits settle and reads the conntrack count, until
// the count is 0. A killed process's orphaned TCP sockets go on
// retransmitting for a while, and a cell whose censor dropped their
// packets leaves them unanswered until the censor table is gone, so one
// flush can race a last retransmission. A count still above 0 after
// timeout is a flow that keeps making entries: the error lists them.
func clearUntilEmpty(clear func() error, count, list func() (string, error), settle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := clear(); err != nil {
			return err
		}
		time.Sleep(settle)
		n, err := count()
		if err != nil {
			return err
		}
		if n = strings.TrimSpace(n); n == "0" {
			return nil
		}
		if time.Now().After(deadline) {
			return conntrackLeft(n, fmt.Sprintf("came back after every flush for %v", timeout), list)
		}
	}
}

// TestClearUntilEmpty: entries that come back after a flush are flushed
// again until none does, and entries that keep coming back past the
// timeout fail the reset with the entries listed.
func TestClearUntilEmpty(t *testing.T) {
	entry := "tcp\t6 src=192.0.2.2 dst=192.0.2.3 sport=40000 dport=443"
	list := func() (string, error) { return entry + "\n", nil }
	clears, reads := 0, 0
	clear := func() error { clears++; return nil }
	countdown := func() (string, error) {
		reads++
		if reads <= 3 {
			return "3\n", nil
		}
		return "0\n", nil
	}
	if err := clearUntilEmpty(clear, countdown, list, 0, time.Minute); err != nil {
		t.Fatal(err)
	}
	if clears != 4 {
		t.Errorf("%d flushes, want 4: one per read until the count read 0", clears)
	}

	stuck := func() (string, error) { return "1\n", nil }
	err := clearUntilEmpty(clear, stuck, list, time.Millisecond, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "1 conntrack entries") {
		t.Errorf("entries that never go: %v, want an error listing them", err)
	}
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
	count, err := r.conntrackCount()
	if err != nil {
		errs = append(errs, err)
	} else if n := strings.TrimSpace(count); n != "0" {
		errs = append(errs, conntrackLeft(n, "outlived the reset", r.conntrackEntries))
	}
	return errors.Join(errs...)
}
