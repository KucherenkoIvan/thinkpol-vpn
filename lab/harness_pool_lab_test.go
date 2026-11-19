//go:build lab

package lab_test

import (
	"strings"
	"testing"

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
// added to, a sysctl, a link's MTU, conntrack entries); a user that leaves
// what it can't (an /etc symlink pointed elsewhere) gets the lab retired,
// and the next user a fresh one.
func TestHarnessPoolResetsOrRetires(t *testing.T) {
	t.Parallel()
	var first, mode, link, target string
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
setsid sleep 1000 </dev/null >/dev/null 2>&1 &
`)
		router.MustExec(t, "sh", "-ec", `nft add table ip leftover; echo x > /tmp/leftover`)
		// A connection left open, its ends killed by the reset (their
		// orphans aborted), and conntrack entries in both nodes.
		router.Start(t, "nc", "-l", "-p", "4000")
		addr := router.IPv4(lab.NetDevices).String()
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
}
