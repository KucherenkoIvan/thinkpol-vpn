package lab

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestNodeState: a node's state reads by kind, a user's leftovers are
// extra, what it removed or changed is missing, a line repeated is
// counted, and the reset's commands undo the extras stage by stage: the
// structure first (a policy rule by its whole spec), then the addressing,
// then the settings.
func TestNodeState(t *testing.T) {
	clean := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nlink lo\nlink eth0\n" +
		"linkattr eth0 <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n" +
		"rule4 0:\tfrom all lookup local\nnft table netdev tplab_eth0\nnftrule netdev tplab_eth0: ether saddr 02:42:ac:11:00:01 drop\n" +
		"path d /tmp\npath d /etc\npath f /etc/resolv.conf\npath f /etc/group\netc 1111 /etc/resolv.conf\netc 2222 /etc/group\n" +
		"etcmode 644 0 0 /etc/group\nsysctl net.ipv4.ip_forward = 0\nsysctl net.ipv4.conf.eth0.rp_filter = 2\n" +
		"addr eth0 172.16.1.2/24\n")
	now := parseNodeState("process 1 /sbin/docker-init -- sh -c wait\nprocess 7 sleep infinity\nprocess 90 thinkpol up\nlink lo\nlink eth0\nlink wg4\n" +
		"linkattr eth0 <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400\nlinkattr wg4 <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n" +
		"rule4 0:\tfrom all lookup local\nrule4 5208:\tfrom all fwmark 0x5 lookup 52\nnft table netdev tplab_eth0\n" +
		"nftrule netdev tplab_eth0: ether saddr 02:42:ac:11:00:01 drop\nnftrule netdev tplab_eth0: ether saddr 02:42:ac:11:00:01 drop\n" +
		"nft table inet censor\nnftrule inet censor: chain queue {\nqueue 100\nmount /run/netns/space\n" +
		"path d /tmp\npath d /tmp/m0\npath f /tmp/m0/map.yaml\npath d /etc\npath f /etc/resolv.conf\npath f /etc/thinkpol.conf\n" +
		"etc 3333 /etc/resolv.conf\netc 4444 /etc/thinkpol.conf\netcmode 600 0 0 /etc/group\n" +
		"sysctl net.ipv4.ip_forward = 1\nsysctl net.ipv4.conf.eth0.rp_filter = 2\nsysctl net.ipv4.conf.wg4.rp_filter = 0\n" +
		"route4 default dev wg4 table 52 scope link\nroute6 2001:db8::/64 dev eth0 metric 1024 pref medium\naddr eth0 192.0.2.9/32\n")
	extra, missing := clean.diff(now)
	want := nodeState{"process": {"90 thinkpol up"}, "link": {"wg4"}, "rule4": {"5208:\tfrom all fwmark 0x5 lookup 52"},
		"linkattr": {"eth0 <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400", "wg4 <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420"},
		"nft":      {"table inet censor"}, "nftrule": {"inet censor: chain queue {", "netdev tplab_eth0: ether saddr 02:42:ac:11:00:01 drop"},
		"queue": {"100"}, "mount": {"/run/netns/space"},
		"path":    {"d /tmp/m0", "f /etc/thinkpol.conf", "f /tmp/m0/map.yaml"},
		"etc":     {"3333 /etc/resolv.conf", "4444 /etc/thinkpol.conf"},
		"etcmode": {"600 0 0 /etc/group"},
		"sysctl":  {"net.ipv4.conf.wg4.rp_filter = 0", "net.ipv4.ip_forward = 1"},
		"route4":  {"default dev wg4 table 52 scope link"}, "route6": {"2001:db8::/64 dev eth0 metric 1024 pref medium"},
		"addr": {"eth0 192.0.2.9/32"}}
	if !maps.EqualFunc(extra, want, slices.Equal) {
		t.Errorf("extra:%s\nwant:%s", extra, want)
	}
	wantMissing := nodeState{"linkattr": {"eth0 <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"}, "path": {"f /etc/group"},
		"etc": {"1111 /etc/resolv.conf", "2222 /etc/group"}, "etcmode": {"644 0 0 /etc/group"},
		"sysctl": {"net.ipv4.ip_forward = 0"}, "addr": {"eth0 172.16.1.2/24"}}
	if !maps.EqualFunc(missing, wantMissing, slices.Equal) {
		t.Errorf("missing:%s\nwant:%s", missing, wantMissing)
	}
	if got := extra.pids(); !slices.Equal(got, []string{"90"}) {
		t.Errorf("pids: %v", got)
	}

	const snap = "/run/lab/snapshot-1.tar"
	got := undo(extra, missing, snap)
	wantCmds := [][]string{
		{"umount", "-l", "/run/netns/space"},
		{"nft", "delete", "table", "inet", "censor"},
		{"ip", "link", "del", "wg4"},
		{"ip", "-4", "rule", "del", "pref", "5208", "from", "all", "fwmark", "0x5", "lookup", "52"},
		{"rm", "-rf", "--one-file-system", "--", "/etc/thinkpol.conf", "/tmp/m0"},
		{"tar", "-C", "/", "-xpf", snap, "--", "etc/group"},
		{"sh", "-c", `tar -xOf "$1" "${2#/}" > "$2"`, "sh", snap, "/etc/resolv.conf"},
	}
	if !slices.EqualFunc(got, wantCmds, slices.Equal) {
		t.Errorf("undo, structure: %q\nwant %q", got, wantCmds)
	}
	structural := []string{"mount", "nft", "link", "rule4", "rule6", "path", "etc", "etcmode"}
	for _, k := range structural {
		delete(extra, k)
		delete(missing, k)
	}
	got = undo(extra, missing, snap)
	wantCmds = [][]string{
		{"ip", "-4", "route", "del", "default", "dev", "wg4", "table", "52", "scope", "link"},
		{"ip", "-6", "route", "del", "2001:db8::/64", "dev", "eth0", "metric", "1024", "pref", "medium"},
		{"ip", "addr", "del", "192.0.2.9/32", "dev", "eth0"},
		{"ip", "addr", "add", "172.16.1.2/24", "dev", "eth0"},
	}
	if !slices.EqualFunc(got, wantCmds, slices.Equal) {
		t.Errorf("undo, addressing: %q\nwant %q", got, wantCmds)
	}
	for _, k := range []string{"route4", "route6", "addr"} {
		delete(extra, k)
		delete(missing, k)
	}
	got = undo(extra, missing, snap)
	wantCmds = [][]string{
		{"sysctl", "-q", "-w", "net.ipv4.ip_forward=0"},
		{"ip", "link", "set", "dev", "eth0", "mtu", "1500", "up"},
	}
	if !slices.EqualFunc(got, wantCmds, slices.Equal) {
		t.Errorf("undo, settings: %q\nwant %q", got, wantCmds)
	}
	if e, m := clean.diff(clean); len(e) > 0 || len(m) > 0 {
		t.Errorf("a state differs from itself: %s / %s", e, m)
	}
	if cmds := undo(nodeState{}, nodeState{}, snap); len(cmds) != 0 {
		t.Errorf("nothing to undo: %q", cmds)
	}
}

// TestNodeStateUnreadable: a kind the script couldn't read makes the
// state an error, never a state with that kind empty.
func TestNodeStateUnreadable(t *testing.T) {
	s := parseNodeState("link lo\nerror sysctl\nerror path\n")
	if err := s.err(); err == nil || !strings.Contains(err.Error(), "path, sysctl") {
		t.Errorf("err: %v", err)
	}
	if err := parseNodeState("link lo\n").err(); err != nil {
		t.Error(err)
	}
}

// TestTopmost: paths under another of the list go with it.
func TestTopmost(t *testing.T) {
	got := topmost([]string{"/tmp/m0/keys", "/tmp/m0", "/tmp/m00", "/run/x", "/tmp/m0/keys/a"})
	if want := []string{"/run/x", "/tmp/m0", "/tmp/m00"}; !slices.Equal(got, want) {
		t.Errorf("topmost: %q, want %q", got, want)
	}
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
	if err := clearUntilEmpty(clear, countdown, list, 0, time.Minute, "router"); err != nil {
		t.Fatal(err)
	}
	if clears != 4 {
		t.Errorf("%d flushes, want 4: one per read until the count read 0", clears)
	}

	stuck := func() (string, error) { return "1\n", nil }
	err := clearUntilEmpty(clear, stuck, list, time.Millisecond, 20*time.Millisecond, "router")
	if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "router: 1 conntrack entries") {
		t.Errorf("entries that never go: %v, want an error listing them", err)
	}
}
