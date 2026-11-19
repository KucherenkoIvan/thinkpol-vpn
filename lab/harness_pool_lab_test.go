//go:build lab

package lab_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// harnessPool is TestHarnessPoolResetsOrRetires' own: one lab at a time,
// of a topology no other pool has.
var harnessPool = lab.NewPool(lab.Standard().Only(lab.Router, lab.DeviceA), 1)

// TestHarnessPoolResetsOrRetires: a pooled lab's next user gets it back
// as it came up, whatever the user before left that the reset can undo
// (processes, a TCP connection, a link with an address, a route in
// another table and a policy rule, nftables tables, a network namespace,
// files under /tmp and /var/lib, /etc changed in content and mode and
// added to, a sysctl, a link's MTU, a permanent neighbour entry,
// conntrack entries, and the neighbour cache its traffic filled); a user
// that leaves what it can't (an /etc symlink pointed elsewhere) gets the
// lab retired, and the next user a fresh one. What the reset only reads
// fails its check, each on its own: a qdisc, an xfrm policy, a rule of
// the seal's table moved to its other chain, a file outside /etc
// changed, a link's address changed, a link made again under its name.
func TestHarnessPoolResetsOrRetires(t *testing.T) {
	t.Parallel()
	var first, mode, link, target, routerAddr string
	t.Run("leaves what the reset undoes", func(t *testing.T) {
		l := harnessPool.Acquire(t)
		first = l.Project
		dev, router := l.Node(lab.DeviceA), l.Node(lab.Router)
		mode = strings.TrimSpace(dev.MustExec(t, "stat", "-c", "%a", "/etc/debian_version"))
		dev.MustExec(t, "sh", "-ec", `
ip link add leftover0 type dummy
ip link set leftover0 up
ip addr add 192.0.2.1/32 dev leftover0
ip route add 198.51.100.0/24 dev leftover0 table 100
ip rule add pref 1000 from 192.0.2.1 lookup 100
nft add table inet leftover
nft add chain inet leftover out '{ type filter hook output priority 0; }'
ip netns add leftover
mkdir -p /var/lib/leftover && echo x > /var/lib/leftover/x && echo x > /tmp/leftover
echo '# leftover' >> /etc/resolv.conf
echo x > /etc/leftover.conf
chmod 600 /etc/debian_version
sysctl -q -w net.ipv4.conf.eth0.arp_ignore=1
ip link set eth0 mtu 1400
ip neigh add 192.0.2.9 lladdr 02:00:00:00:00:09 dev eth0 nud permanent
setsid sleep 1000 </dev/null >/dev/null 2>&1 &
`)
		router.MustExec(t, "sh", "-ec", `nft add table ip leftover; echo x > /tmp/leftover`)
		// A connection left open, its ends killed by the reset (their
		// orphans aborted), and conntrack entries in both nodes.
		addr := router.IPv4(lab.NetDevices).String()
		routerAddr = addr
		router.Start(t, "nc", "-l", "-s", addr, "-p", "4000")
		router.MustExec(t, "sh", "-ec", `for i in $(seq 100); do ss -H -t -l -n 'sport = :4000' | grep -q . && exit 0; sleep 0.1; done; exit 1`)
		dev.MustExec(t, "sh", "-ec", `setsid sh -c 'sleep 1000 | nc `+addr+` 4000' </dev/null >/dev/null 2>&1 &
for i in $(seq 50); do ss -H -t state established | grep -q . && exit 0; sleep 0.1; done; exit 1`)
		dev.MustExec(t, "ping", "-c", "1", "-W", "5", addr)
	})
	t.Run("gets the lab back as it came up", func(t *testing.T) {
		l := harnessPool.Acquire(t)
		if l.Project != first {
			t.Fatalf("got lab %s, want %s back (pool: %+v)", l.Project, first, harnessPool.Stats())
		}
		dev, router := l.Node(lab.DeviceA), l.Node(lab.Router)
		for _, check := range []struct{ what, cmd, want string }{
			{"the dummy link", "ip -o link show | grep -c leftover0 || true", "0"},
			{"the rule", "ip rule show | grep -c 'lookup 100' || true", "0"},
			{"table 100", "ip route show table 100 | wc -l", "0"},
			{"the nft table", "nft list tables | grep -c leftover || true", "0"},
			{"the namespace", "ip netns list | wc -l", "0"},
			{"the files", "ls /tmp /var/lib | grep -c leftover || true", "0"},
			{"resolv.conf", "grep -c leftover /etc/resolv.conf || true", "0"},
			{"the new /etc file", "test -e /etc/leftover.conf && echo there || echo gone", "gone"},
			{"the mode", "stat -c %a /etc/debian_version", mode},
			{"the sysctl", "sysctl -n net.ipv4.conf.eth0.arp_ignore", "0"},
			{"the MTU", "cat /sys/class/net/eth0/mtu", "1500"},
			{"the permanent neighbour", "ip neigh show 192.0.2.9 | wc -l", "0"},
			{"the router's neighbour entry", "ip neigh show " + routerAddr + " | wc -l", "0"},
			{"TCP metrics", "ip tcp_metrics show | wc -l", "0"},
			{"the processes", "ps -eo args= | grep -c '^sleep 1000' || true", "0"},
			{"the connection", "ss -H -t state connected exclude time-wait | wc -l", "0"},
			{"conntrack", "cat /proc/sys/net/netfilter/nf_conntrack_count", "0"},
		} {
			if got := strings.TrimSpace(dev.MustExec(t, "sh", "-c", check.cmd)); got != check.want {
				t.Errorf("device-a: %s: %q, want %q", check.what, got, check.want)
			}
		}
		if got := strings.TrimSpace(router.MustExec(t, "sh", "-c", "nft list tables | grep -c leftover; test ! -e /tmp/leftover")); got != "0" {
			t.Errorf("router: the nft table: %q", got)
		}
		link = strings.TrimSpace(dev.MustExec(t, "sh", "-c", "find /etc -maxdepth 1 -type l | sort | head -1"))
		if link == "" {
			t.Fatal("no symlink in /etc to point elsewhere")
		}
		target = strings.TrimSpace(dev.MustExec(t, "readlink", link))
		dev.MustExec(t, "ln", "-sfn", "/leftover", link)
	})
	t.Run("gets a fresh lab after a reset that didn't hold", func(t *testing.T) {
		l := harnessPool.Acquire(t)
		if l.Project == first {
			t.Fatalf("got lab %s again after it was left with %s pointed elsewhere", l.Project, link)
		}
		if got := strings.TrimSpace(l.Node(lab.DeviceA).MustExec(t, "readlink", link)); got != target {
			t.Errorf("%s points to %q, want %q", link, got, target)
		}
		s := harnessPool.Stats()
		if s.Started != 2 || len(s.Retired) != 1 || !strings.Contains(s.Retired[0], "gets_the_lab_back") || !strings.Contains(s.Retired[0], "reset didn't hold") {
			t.Errorf("pool: %+v, want 2 labs started and the second user's retired for its reset", s)
		}
	})
	t.Run("the check fails on what the reset only reads", func(t *testing.T) {
		l := harnessPool.Acquire(t)
		dev := l.Node(lab.DeviceA)
		eth := dev.Interface(lab.NetDevices)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		clean, err := l.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.DropSnapshot(context.Background(), clean) })
		mac := strings.TrimSpace(dev.MustExec(t, "cat", "/sys/class/net/"+eth+"/address"))
		seal := "netdev tplab_" + eth
		for _, c := range []struct{ what, leave, putBack, kind string }{
			{"a qdisc", "tc qdisc add dev " + eth + " root netem delay 1ms", "tc qdisc del dev " + eth + " root", "qdisc"},
			{"an xfrm policy", "ip xfrm policy add src 192.0.2.1/32 dst 192.0.2.2/32 dir out", "ip xfrm policy flush", "xfrm"},
			// The rule that drops the bridge's frames moved from the
			// chain in to the chain out: the table's lines are the same.
			{"a seal rule moved to another chain", `r=$(nft list chain ` + seal + ` in | grep -o 'ether saddr [^ ]* drop'); test -n "$r"; nft flush chain ` + seal + ` in; nft add rule ` + seal + ` out $r`,
				`h=$(nft -a list chain ` + seal + ` out | sed -n 's/.*ether saddr \([^ ]*\) drop # handle \([0-9]*\)$/\1 \2/p'); test -n "$h"; set -- $h; nft delete rule ` + seal + ` out handle $2; nft add rule ` + seal + ` in ether saddr $1 drop`, "nftrule"},
			{"a file outside /etc", "cp -p /var/lib/dpkg/status /run/lab/status; echo >> /var/lib/dpkg/status", "cp -p /run/lab/status /var/lib/dpkg/status; rm /run/lab/status", "attr"},
			{"a link's address", "ip link set dev " + eth + " address 02:00:00:00:00:99", "ip link set dev " + eth + " address " + mac, "linkattr"},
		} {
			dev.MustExec(t, "sh", "-ec", c.leave)
			if err := l.Reset(ctx, clean, t.Logf); err == nil || !strings.Contains(err.Error(), "\n  "+c.kind+" ") {
				t.Errorf("%s: the reset's check: %v, want it to fail on a %s line", c.what, err, c.kind)
			}
			dev.MustExec(t, "sh", "-ec", c.putBack)
			if err := l.Reset(ctx, clean, t.Logf); err != nil {
				t.Fatalf("%s put back by hand: %v", c.what, err)
			}
		}

		// A link made again under its name, with its address and MTU:
		// only its index tells.
		dev.MustExec(t, "sh", "-ec", "ip link add again0 type dummy")
		withLink, err := l.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		dev.MustExec(t, "sh", "-ec", `a=$(cat /sys/class/net/again0/address); ip link del again0; ip link add again0 address "$a" type dummy`)
		if err := l.Reset(ctx, withLink, t.Logf); err == nil || !strings.Contains(err.Error(), "\n  linkattr again0 ") {
			t.Errorf("a link made again: the reset's check: %v, want it to fail on its linkattr line", err)
		}
		if err := l.DropSnapshot(ctx, withLink); err != nil {
			t.Error(err)
		}
		if err := l.Reset(ctx, clean, t.Logf); err != nil {
			t.Fatalf("the link made again removed: %v", err)
		}
		if s := harnessPool.Stats(); s.Started != 2 || len(s.Retired) != 1 {
			t.Errorf("pool: %+v, want this user's lab the third user's, nothing retired since", s)
		}
	})
}
