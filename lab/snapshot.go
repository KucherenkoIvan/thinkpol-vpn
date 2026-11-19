package lab

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A lab that serves more than one user (a matrix row's cells, a pool's
// tests) is put back after each into the state recorded when it was clean
// (Snapshot), and the reset is checked (Lab.Reset): what the reset can't
// put back fails the check rather than being guessed at.

// nodeStateScript prints what a user may leave behind in a node, one
// "<kind> <what>" line each, and "error <kind>" for a kind it couldn't
// read: its processes (but the script's own), links and their index,
// flags, MTU, master and link-layer address, addresses, routes in every
// table, policy rules, permanent neighbour entries, the nftables ruleset
// (each line by table and block, a chain's rules numbered in order),
// NFQUEUE queues bound, mounts, xfrm states and policies, qdiscs, the
// network sysctls, and the filesystem but /usr (and /usr/local with it):
// every path by type, /etc's files by content, mode and owner, and the
// other regular files by mode, size and mtime, /var/log by name only (a
// clean state's nginx writes there). /run/lab is the lab's own (the seal
// marker, Process pid files, the snapshots' copies of /etc). Left out, as
// the kernel changes them on its own: neighbour entries but permanent ones
// and the TCP metrics cache (the reset flushes both), route expiry times,
// a route's linkdown flag, routes learnt from router advertisements, a
// qdisc's refcnt and the conntrack count (the reset empties conntrack and
// checks it apart). A link's own routes and sysctls come and go with it.
//
// Not read at all, so a test that changes any of these needs a fresh lab
// (Start): owners and modes of files and directories outside /etc,
// extended attributes, ACLs and file capabilities, /usr outside
// /usr/local, /dev (its shm and mqueue), /run/lab, what /var/log's files
// hold, sysctls outside net.*, IPv6 address flags and lifetimes, a link's
// txqlen and alias, tc filters and classes, nftables counters, quotas and
// set elements' state (timeouts, dynamic updates: -s leaves them out),
// mount options, the UTS hostname and ip nexthop objects. The image has no
// iptables-legacy or ipset, so neither can hold state.
const nodeStateScript = `
set -o pipefail
fail() { echo "error $1"; }
ps -eo pid=,ppid=,args= | awk -v me=$$ '$1 != me && $2 != me { pid = $1; $1 = ""; $2 = ""; sub(/^ +/, ""); print "process " pid " " $0 }' || fail process
ip -o link show | awk -F': ' '{ name = $2; sub(/@.*/, "", name); print "link " name; flags = ""; if (match($3, /<[^>]*>/)) flags = substr($3, RSTART, RLENGTH); n = split($3, f, " "); mtu = ""; master = ""; ll = ""; for (i = 1; i < n; i++) { if (f[i] == "mtu") mtu = f[i+1]; if (f[i] == "master") master = " master " f[i+1]; if (f[i] ~ /^link\// && f[i] != "link/none") ll = " " f[i] " " f[i+1] } print "linkattr " name " " flags " mtu " mtu master " ifindex " $1 ll }' || fail link
ip -br addr show | awk '{ sub(/@.*/, "", $1); for (i = 3; i <= NF; i++) print "addr " $1 " " $i }' || fail addr
{ ip -4 route show table all | { grep -v 'proto ra' || true; } | sed -e 's/ expires [^ ]*//' -e 's/ linkdown//' -e 's/ *$//' -e 's/^/route4 /'; } || fail route4
{ ip -6 route show table all | { grep -v 'proto ra' || true; } | sed -e 's/ expires [^ ]*//' -e 's/ linkdown//' -e 's/ *$//' -e 's/^/route6 /'; } || fail route6
ip -4 rule show | sed 's/^/rule4 /' || fail rule4
ip -6 rule show | sed 's/^/rule6 /' || fail rule6
ip neigh show nud permanent | sed -e 's/ *$//' -e 's/^/neigh /' || fail neigh
nft -s list ruleset 2>/dev/null | awk '/^table / { t = $2 " " $3; b = ""; print "nft table " t; next } /^[ \t]*}?[ \t]*$/ { next } /^\t[^\t]/ && /[{]$/ { b = $0; sub(/^\t/, "", b); sub(/ *[{]$/, "", b); i = 0; print "nftrule " t " " b; next } { sub(/^[ \t]+/, ""); if (b ~ /^chain /) print "nftrule " t " " b " #" ++i ": " $0; else print "nftrule " t " " b ": " $0 }' || fail nft
if [ -e /proc/net/netfilter/nfnetlink_queue ]; then awk '{ print "queue " $1 }' /proc/net/netfilter/nfnetlink_queue || fail queue; fi
awk '{ print "mount " $5 }' /proc/self/mountinfo || fail mount
{ ip xfrm state; ip xfrm policy; } | { grep -v '^$' || true; } | sed 's/^/xfrm /' || fail xfrm
tc qdisc show | sed -e 's/ refcnt [0-9]*//' -e 's/ *$//' -e 's/^/qdisc /' || fail qdisc
s=$(sysctl -a -r '^net\.' 2>/dev/null); if [ -n "$s" ]; then printf '%s\n' "$s" | { grep -v '^net\.netfilter\.nf_conntrack_count ' || true; } | sed 's/^/sysctl /'; else fail sysctl; fi
skip='( -path /proc -o -path /sys -o -path /dev -o -path /src -o -path /usr -o -path /run/lab )'
find / -xdev $skip -prune -o -printf 'path %y %p\n' || fail path
find /usr/local -xdev -printf 'path %y %p\n' || fail path
find / -xdev $skip -prune -o \( -path /etc -o -path /var/log \) -prune -o -type f -printf 'attr %m %s %T@ %p\n' || fail attr
find /usr/local -xdev -type f -printf 'attr %m %s %T@ %p\n' || fail attr
find /etc -xdev ! -type l -printf 'etcmode %m %U %G %p\n' || fail etcmode
find /etc -xdev -type l -printf 'etclink %p -> %l\n' || fail etclink
{ find /etc -xdev -type f -print0 | xargs -0 -r sha1sum; sha1sum /etc/hosts /etc/hostname /etc/resolv.conf; } | sort -u | sed 's/^\([0-9a-f]*\)  /etc \1 /' || fail etc
`

// nodeState is a node's nodeStateScript lines by kind, sorted. A line may
// repeat (two identical rules in one chain): the lines of a kind are a
// multiset.
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

// err is the kinds the script couldn't read.
func (s nodeState) err() error {
	if e := s["error"]; len(e) > 0 {
		return fmt.Errorf("couldn't read %s", strings.Join(e, ", "))
	}
	return nil
}

// diff is what now has that clean hasn't (extra), and what clean has that
// now lacks (missing), by kind, counting repeated lines.
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
		left := map[string]int{}
		for _, w := range clean[kind] {
			left[w]++
		}
		for _, w := range now[kind] {
			if left[w] > 0 {
				left[w]--
			} else {
				extra[kind] = append(extra[kind], w)
			}
		}
		for _, w := range clean[kind] {
			if left[w] > 0 {
				left[w]--
				missing[kind] = append(missing[kind], w)
			}
		}
	}
	for _, s := range []nodeState{extra, missing} {
		for _, lines := range s {
			slices.Sort(lines)
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

// pids is the process ids of a state's process lines.
func (s nodeState) pids() []string {
	var pids []string
	for _, p := range s["process"] {
		pid, _, _ := strings.Cut(p, " ")
		pids = append(pids, pid)
	}
	return pids
}

// paths is the paths of a state's path lines ("<type> <path>").
func (s nodeState) paths() []string {
	var paths []string
	for _, p := range s["path"] {
		if _, p, ok := strings.Cut(p, " "); ok {
			paths = append(paths, p)
		}
	}
	return paths
}

// topmost is paths without those under another of them.
func topmost(paths []string) []string {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	var out []string
	for _, p := range sorted {
		if len(out) > 0 {
			last := out[len(out)-1]
			if p == last || strings.HasPrefix(p, strings.TrimSuffix(last, "/")+"/") {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// undo is the commands that remove what extra holds and put back what
// missing lacks, for the first stage that has any: mounts, nftables
// tables, links, policy rules, paths and /etc first; then routes,
// addresses and permanent neighbour entries (read again after the first
// stage: a link's go with it); then
// sysctls and links' MTU and state (again after: forwarding writes reset
// other sysctls). Processes the reset kills before. What no command can
// put back (a clean table changed, a file outside /etc changed, a link
// gone) is left for the check to fail on. snap is the node's copy of /etc
// (Snapshot).
func undo(extra, missing nodeState, snap string) [][]string {
	if cmds := undoStructure(extra, missing, snap); len(cmds) > 0 {
		return cmds
	}
	if cmds := undoAddressing(extra, missing); len(cmds) > 0 {
		return cmds
	}
	return undoSettings(extra, missing)
}

func undoStructure(extra, missing nodeState, snap string) [][]string {
	var cmds [][]string
	// Unmounted first: a mount point (/run/netns/<name>) is removed below.
	for _, m := range slices.Backward(extra["mount"]) {
		cmds = append(cmds, []string{"umount", "-l", m})
	}
	// A table the clean state has stays: a rule changed in it is the
	// check's to fail on.
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
	if paths := topmost(extra.paths()); len(paths) > 0 {
		// --one-file-system: a mount point the umount above couldn't
		// release is not followed into what is mounted there.
		cmds = append(cmds, append([]string{"rm", "-rf", "--one-file-system", "--"}, paths...))
	}
	// /etc from the snapshot's copy: what's gone is extracted (a
	// directory with what it held), a file whose content changed is
	// written over in place (/etc/resolv.conf and /etc/hosts are bind
	// mounts, which tar would try to unlink), a mode or owner set back.
	var gone []string
	for _, p := range topmost(missing.paths()) {
		if strings.HasPrefix(p, "/etc/") {
			gone = append(gone, strings.TrimPrefix(p, "/"))
		}
	}
	if len(gone) > 0 {
		cmds = append(cmds, append([]string{"tar", "-C", "/", "-xpf", snap, "--"}, gone...))
	}
	missingPath := map[string]bool{}
	for _, p := range missing.paths() {
		missingPath[p] = true
	}
	for _, line := range extra["etc"] {
		if _, p, ok := strings.Cut(line, " "); ok && !missingPath[p] && hasLine(missing["etc"], p) {
			cmds = append(cmds, []string{"sh", "-c", `tar -xOf "$1" "${2#/}" > "$2"`, "sh", snap, p})
		}
	}
	for _, line := range missing["etcmode"] {
		// "<mode> <uid> <gid> <path>"
		f := strings.SplitN(line, " ", 4)
		if len(f) == 4 && !missingPath[f[3]] && hasLine(extra["etcmode"], f[3]) {
			cmds = append(cmds, []string{"chmod", f[0], f[3]}, []string{"chown", f[1] + ":" + f[2], f[3]})
		}
	}
	return cmds
}

// hasLine says whether lines has one ending in " "+p: a line about path p.
func hasLine(lines []string, p string) bool {
	return slices.ContainsFunc(lines, func(l string) bool { return strings.HasSuffix(l, " "+p) })
}

func undoAddressing(extra, missing nodeState) [][]string {
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
	for _, a := range missing["addr"] {
		if link, cidr, ok := strings.Cut(a, " "); ok {
			cmds = append(cmds, []string{"ip", "addr", "add", cidr, "dev", link})
		}
	}
	for _, e := range extra["neigh"] {
		// "192.0.2.9 dev eth0 lladdr 02:00:00:00:00:09 PERMANENT"
		if f := strings.Fields(e); len(f) >= 3 && f[1] == "dev" {
			cmds = append(cmds, []string{"ip", "neigh", "del", f[0], "dev", f[2]})
		}
	}
	for _, f := range []struct{ flag, kind string }{{"-4", "route4"}, {"-6", "route6"}} {
		for _, route := range missing[f.kind] {
			cmds = append(cmds, append([]string{"ip", f.flag, "route", "add"}, strings.Fields(route)...))
		}
	}
	return cmds
}

func undoSettings(extra, missing nodeState) [][]string {
	var cmds [][]string
	now := map[string]bool{}
	for _, line := range extra["sysctl"] {
		k, _, _ := strings.Cut(line, " = ")
		now[k] = true
	}
	for _, line := range missing["sysctl"] {
		// Only a key that still exists: one of a removed link is gone
		// with it.
		if k, v, ok := strings.Cut(line, " = "); ok && now[k] {
			cmds = append(cmds, []string{"sysctl", "-q", "-w", k + "=" + v})
		}
	}
	links := map[string][]string{}
	for _, line := range extra["linkattr"] {
		f := strings.Fields(line)
		links[f[0]] = f
	}
	for _, line := range missing["linkattr"] {
		// "<name> <FLAGS> mtu <n>[ master <m>] ifindex <i>[ link/<type> <address>]"
		f := strings.Fields(line)
		now, ok := links[f[0]]
		// A link whose state and MTU are as clean, but not its index or
		// address (made again, its address changed), is the check's to
		// fail on: nothing here sets them back.
		if len(f) < 4 || !ok || len(now) >= 4 && now[1] == f[1] && now[3] == f[3] {
			continue
		}
		state := "down"
		if slices.Contains(strings.Split(strings.Trim(f[1], "<>"), ","), "UP") {
			state = "up"
		}
		cmds = append(cmds, []string{"ip", "link", "set", "dev", f[0], "mtu", f[3], state})
	}
	return cmds
}

// Snapshot is the clean state of each of a lab's nodes, which Reset puts
// them back in.
type Snapshot struct {
	nodes map[string]nodeState
	etc   string // the nodes' copy of /etc, under /run/lab
}

var snapshots atomic.Int64

const (
	stateTimeout = 30 * time.Second // nodeStateScript under load
	resetExec    = 10 * time.Second // one of the reset's commands
)

// Snapshot records every node's state, and a copy of its /etc, as the
// state Reset puts the lab back in. Take it when nothing runs in the lab
// but what is meant to stay; it waits first until every node's command
// has started (it waits for the seal in a loop of its own, whose sleeps a
// snapshot must not record: Reset would kill the command for them).
func (l *Lab) Snapshot(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{nodes: map[string]nodeState{}, etc: fmt.Sprintf("/run/lab/snapshot-%d.tar", snapshots.Add(1))}
	err := l.eachNode(func(n *Node) error {
		if err := n.waitCommand(ctx); err != nil {
			return err
		}
		_, err := n.read(ctx, resetExec, "tar", "-C", "/", "-cf", s.etc, "etc")
		return err
	})
	if err != nil {
		return nil, err
	}
	states, err := l.states(ctx)
	if err != nil {
		return nil, err
	}
	s.nodes = states
	return s, nil
}

// DropSnapshot removes s's copies of /etc from the nodes, for a snapshot
// no Reset will use again.
func (l *Lab) DropSnapshot(ctx context.Context, s *Snapshot) error {
	return l.eachNode(func(n *Node) error {
		_, err := n.read(ctx, resetExec, "rm", "-f", s.etc)
		return err
	})
}

// waitCommand waits until no process of n is still the wait for the seal
// its command starts with (compose.go).
func (n *Node) waitCommand(ctx context.Context) error {
	for {
		out, err := n.read(ctx, resetExec, "ps", "-eo", "args=")
		if err != nil {
			return err
		}
		if !strings.Contains(out, sealWait) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: its command still waits for the seal: %w", n.Name, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// states reads every node's state at once.
func (l *Lab) states(ctx context.Context) (map[string]nodeState, error) {
	var mu sync.Mutex
	states := map[string]nodeState{}
	err := l.eachNode(func(n *Node) error {
		s, err := n.state(ctx)
		mu.Lock()
		states[n.Name] = s
		mu.Unlock()
		return err
	})
	return states, err
}

func (n *Node) state(ctx context.Context) (nodeState, error) {
	out, err := n.read(ctx, stateTimeout, "bash", "-c", nodeStateScript)
	if err != nil {
		return nil, err
	}
	s := parseNodeState(out)
	if err := s.err(); err != nil {
		return nil, fmt.Errorf("%s: %w", n.Name, err)
	}
	return s, nil
}

// read runs a command in the node, bounded by timeout, and returns its
// stdout.
func (n *Node) read(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := n.Exec(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("%w\nstdout:\n%s", err, res.Stdout)
	}
	return res.Stdout, nil
}

// eachNode runs f for every node at once.
func (l *Lab) eachNode(f func(n *Node) error) error {
	nodes := l.Nodes()
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Go(func() { errs[i] = f(n) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// undoRounds bounds the reset's rounds of reading what is left and undoing
// a stage of it (undo): three stages, and a round more for each that what
// it undid brought back (an address's routes).
const undoRounds = 6

// Reset puts the lab back in s's state and checks it held: it kills what
// still runs that s doesn't have, aborts every TCP connection left
// (orphaned or held by a clean-state process), then, with nothing left to
// make new state, undoes what the nodes have beyond s and puts back what
// they lack (undo), flushes the caches the state leaves out (routes' path
// MTUs, TCP metrics, neighbours), empties every node's conntrack until it
// stays empty, and reads every node back: nil only when every node is in
// s's state. logf gets, per node, the processes it killed, the TCP
// connections it aborted and what it found to undo, so a leftover the
// reset hid (an agent that outlived its test) is in the test's log.
func (l *Lab) Reset(ctx context.Context, s *Snapshot, logf func(format string, args ...any)) error {
	err := l.eachNode(func(n *Node) error { return n.killExtra(ctx, s.nodes[n.Name], logf) })
	if err == nil {
		// A killed process's TCP sockets live on as orphans, and a peer
		// left running (a camouflage site's nginx) keeps its end: either
		// retransmits for minutes, and a retransmission after conntrack's
		// flush makes an entry the check finds. An RST from the abort
		// makes no entry of its own.
		err = l.eachNode(func(n *Node) error { return n.abortTCP(ctx, logf) })
	}
	if err == nil {
		err = l.eachNode(func(n *Node) error { return n.undo(ctx, s.nodes[n.Name], s.etc, logf) })
	}
	if err == nil {
		// What the last user's traffic taught the kernel isn't in the
		// state: path MTUs (IPv6's route exceptions), TCP metrics (a
		// destination's RTT and cwnd, which a new connection starts
		// from) and neighbour entries but permanent ones (the state has
		// those). Nothing of the clean state depends on them.
		err = l.eachNode(func(n *Node) error {
			_, err := n.read(ctx, resetExec, "sh", "-ec", "ip -4 route flush cache; ip -6 route flush cache; ip tcp_metrics flush all; ip -4 neigh flush all; ip -6 neigh flush all")
			return err
		})
	}
	if err == nil {
		err = l.eachNode(func(n *Node) error { return n.clearConntrack(ctx) })
	}
	if err != nil {
		return err
	}
	return l.Check(ctx, s)
}

// killExtra kills the processes n has beyond clean, logs them, and waits
// until none is left.
func (n *Node) killExtra(ctx context.Context, clean nodeState, logf func(format string, args ...any)) error {
	now, err := n.state(ctx)
	if err != nil {
		return err
	}
	extra, _ := clean.diff(now)
	if len(extra["process"]) == 0 {
		return nil
	}
	logf("%s: the reset killed:%s", n.Name, nodeState{"process": extra["process"]})
	// A process may exit between the read and the kill: what still runs
	// after is what counts.
	if _, err := n.read(ctx, resetExec, append([]string{"sh", "-c", `kill -KILL "$@" 2>/dev/null; true`, "sh"}, extra.pids()...)...); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		now, err := n.state(ctx)
		if err != nil {
			return err
		}
		extra, _ := clean.diff(now)
		switch {
		case len(extra["process"]) == 0:
			return nil
		case time.Now().After(deadline):
			return fmt.Errorf("%s: processes outlived SIGKILL:%s", n.Name, nodeState{"process": extra["process"]})
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// undo runs undo's commands in rounds until nothing is left to undo, and
// logs what the first round found. A command that fails is no error of
// its own: the check says whether the state came back.
func (n *Node) undo(ctx context.Context, clean nodeState, snap string, logf func(format string, args ...any)) error {
	for round := range undoRounds {
		now, err := n.state(ctx)
		if err != nil {
			return err
		}
		extra, missing := clean.diff(now)
		if round == 0 {
			logUndone(n.Name, extra, missing, logf)
		}
		cmds := undo(extra, missing, snap)
		if len(cmds) == 0 {
			return nil
		}
		for _, cmd := range cmds {
			_, _ = n.read(ctx, resetExec, cmd...)
		}
	}
	return nil
}

// logUndone logs what a node had beyond its clean state (extra) and
// lacked (missing) when the reset began undoing it.
func logUndone(node string, extra, missing nodeState, logf func(format string, args ...any)) {
	if len(extra) > 0 {
		logf("%s: the reset undid what was left behind:%s", node, extra)
	}
	if len(missing) > 0 {
		logf("%s: the reset undid what was gone or changed:%s", node, missing)
	}
}

// abortTCP aborts every TCP connection n has (ss -K: a clean state has
// listeners only), logs the ones it aborted, and fails when one is left:
// ss -K exits 0 and kills nothing on a kernel without INET_DIAG_DESTROY.
func (n *Node) abortTCP(ctx context.Context, logf func(format string, args ...any)) error {
	aborted, err := n.read(ctx, resetExec, "ss", "-K", "-H", "-n", "-t", "state", "connected")
	if err != nil {
		return err
	}
	left, err := n.read(ctx, resetExec, "ss", "-H", "-n", "-t", "state", "connected", "exclude", "time-wait")
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

// clearConntrack empties n's conntrack until no entry comes back
// (clearUntilEmpty), within 30 s: every node has it on (Docker's DNS nat
// table; a censor's ct match; a server's masquerade), and an entry left
// from a flow of the last user would steer the next user's flow on the
// same addresses (a NAT mapping, a TCP state). censord -reset also removes
// a censor's table, should one be left.
func (n *Node) clearConntrack(ctx context.Context) error {
	return clearUntilEmpty(
		func() error {
			_, err := n.read(ctx, resetExec, "censord", "-reset")
			return err
		},
		func() (string, error) { return n.conntrackCount(ctx) },
		func() (string, error) { return n.read(ctx, resetExec, "censord", "-conntrack") },
		// A retransmission that would make a new entry is an absence no
		// watcher can see: the settle is a window, once per reset.
		time.Second, 30*time.Second, n.Name)
}

func (n *Node) conntrackCount(ctx context.Context) (string, error) {
	return n.read(ctx, resetExec, "sh", "-c", "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0")
}

// conntrackLeft is the error for n entries left in node's conntrack,
// listed by list.
func conntrackLeft(node, n, how string, list func() (string, error)) error {
	entries, err := list()
	if err != nil {
		entries = fmt.Sprintf("(couldn't list them: %v)", err)
	}
	return fmt.Errorf("%s: %s conntrack entries %s:\n%s", node, n, how, strings.TrimSpace(entries))
}

// clearUntilEmpty clears, waits settle and reads the conntrack count, until
// the count is 0. A killed process's orphaned TCP sockets go on
// retransmitting for a while, and a censor that dropped their packets
// leaves them unanswered until its table is gone, so one flush can race a
// last retransmission. A count still above 0 after timeout is a flow that
// keeps making entries: the error lists them.
func clearUntilEmpty(clear func() error, count, list func() (string, error), settle, timeout time.Duration, node string) error {
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
			return conntrackLeft(node, n, fmt.Sprintf("came back after every flush for %v", timeout), list)
		}
	}
}

// Check is nil when every node is in s's state and has no conntrack
// entry.
func (l *Lab) Check(ctx context.Context, s *Snapshot) error {
	states, err := l.states(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(states)) {
		extra, missing := s.nodes[name].diff(states[name])
		if len(extra) > 0 {
			errs = append(errs, fmt.Errorf("%s: left behind:%s", name, extra))
		}
		if len(missing) > 0 {
			errs = append(errs, fmt.Errorf("%s: gone or changed since the snapshot:%s", name, missing))
		}
	}
	err = l.eachNode(func(n *Node) error {
		c, err := n.conntrackCount(ctx)
		if err != nil {
			return err
		}
		if c = strings.TrimSpace(c); c != "0" {
			return conntrackLeft(n.Name, c, "outlived the reset", func() (string, error) { return n.read(ctx, resetExec, "censord", "-conntrack") })
		}
		return nil
	})
	return errors.Join(append(errs, err)...)
}
