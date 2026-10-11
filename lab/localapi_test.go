//go:build lab

package lab_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Local users in the lab nodes: alice is in the thinkpol group, mallory
// isn't.
const (
	apiGID     = "2000"
	aliceUID   = "2001"
	malloryUID = "2002"
)

// as runs the CLI as a local user: root ("") or uid with only the groups
// given.
func as(uid string, groups string, args ...string) []string {
	cli := append([]string{"/opt/thinkpol/bin/thinkpol"}, args...)
	if uid == "" {
		return cli
	}
	if groups == "" {
		return append([]string{"setpriv", "--reuid", uid, "--regid", uid, "--clear-groups"}, cli...)
	}
	return append([]string{"setpriv", "--reuid", uid, "--regid", uid, "--groups", groups}, cli...)
}

func cli(t *testing.T, n *lab.Node, args []string) (lab.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return n.Exec(ctx, args...)
}

func noPing(t *testing.T, from *lab.Node, to string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := from.Exec(ctx, "ping", "-c", "2", "-W", "1", to); err == nil {
		t.Fatalf("%s answers %s", to, from.Name)
	}
}

// TestLocalAPI drives running nodes with the CLI over the local API:
// connect and disconnect a device, read its status and log, and check who
// may do what: root everything, the thinkpol group all but the log, anyone
// else nothing. No status shows a public address or a key.
func TestLocalAPI(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, devB := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, _ := space.build(t)
	nodes := map[string]*lab.Node{"server-1": server, "device-a": devA, "device-b": devB}
	for name, n := range nodes {
		space.install(t, n, name, envelope)
		n.MustExec(t, "groupadd", "-g", apiGID, "thinkpol")
	}
	// Secrets and public addresses no status may show.
	var secrets []string
	for _, n := range nodes {
		keys := n.MustExec(t, "cat", stateDir+"/node.key", stateDir+"/space.pub")
		for _, m := range regexp.MustCompile(`(?m)^(?:map|wireguard|signing|recovery)-key: "([0-9a-f]+)"`).FindAllStringSubmatch(keys, -1) {
			secrets = append(secrets, m[1])
		}
		for _, net := range []string{lab.NetServers, lab.NetDevices} {
			if a, ok := addrOn(n, net); ok {
				secrets = append(secrets, a...)
			}
		}
	}
	if len(secrets) < 9 {
		t.Fatalf("found only %d keys and addresses to look for", len(secrets))
	}
	clean := func(t *testing.T, what, out string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s shows %s:\n%s", what, s, out)
			}
		}
	}

	up := map[string]*lab.Process{
		"server-1": server.Start(t, "thinkpol", "up"),
		"device-a": devA.Start(t, "thinkpol", "up", "-connect=false"),
		"device-b": devB.Start(t, "thinkpol", "up"),
	}
	waitLog(t, up["server-1"], `worker space=\S+ .*msg="map applied"`)
	waitLog(t, up["device-a"], "mode=device")
	s4, s6 := space.overlay(1)
	b4, _ := space.overlay(3)

	t.Run("the socket's directory admits root and the group", func(t *testing.T) {
		for _, n := range nodes {
			lab.Eventually(t, 30*time.Second, func() error {
				_, err := cli(t, n, []string{"test", "-S", "/run/thinkpol-api/api.sock"})
				return err
			})
			if got := n.MustExec(t, "stat", "-c", "%a %U %G", "/run/thinkpol-api", "/run/thinkpol-api/api.sock"); got != "750 root thinkpol\n660 root thinkpol\n" {
				t.Errorf("%s: %q", n.Name, got)
			}
		}
	})

	t.Run("a device starts disconnected and connects", func(t *testing.T) {
		res, err := cli(t, devA, as(aliceUID, apiGID, "status"))
		if err != nil || !regexp.MustCompile(`state: +disconnected`).MatchString(res.Stdout) {
			t.Fatalf("%v\n%s", err, res.Stdout)
		}
		noPing(t, devA, s4.String())
		res, err = cli(t, devA, as(aliceUID, apiGID, "connect"))
		if err != nil || !regexp.MustCompile(`state: +connected`).MatchString(res.Stdout) {
			t.Fatalf("connect: %v\n%s", err, res.Stdout)
		}
		ping(t, devA, s4)
		ping(t, devA, s6)
		ping(t, devA, b4)
		res, err = cli(t, devA, as(aliceUID, apiGID, "status"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`health: +ok`, `peers:`, `handshake [0-9hms]+ ago`, `neighbors:`, `udp \(dialed active up\)`} {
			if !regexp.MustCompile(want).MatchString(res.Stdout) {
				t.Errorf("no %q in\n%s", want, res.Stdout)
			}
		}
		clean(t, "device-a's status", res.Stdout)
		res, err = cli(t, devA, as("", "", "status", "-json"))
		if err != nil || !regexp.MustCompile(`"connection":\s+"CONNECTION_CONNECTED"`).MatchString(res.Stdout) {
			t.Fatalf("json: %v\n%s", err, res.Stdout)
		}
		clean(t, "device-a's JSON status", res.Stdout)
	})

	t.Run("anyone else is denied", func(t *testing.T) {
		for _, cmd := range [][]string{{"status"}, {"connect"}, {"disconnect"}, {"logs"}} {
			for name, groups := range map[string]string{"no groups": "", "another group": "2003"} {
				res, err := cli(t, devA, as(malloryUID, groups, cmd...))
				if err == nil || !strings.Contains(res.Stderr, "permission denied") {
					t.Errorf("mallory (%s) %v: %v\n%s%s", name, cmd, err, res.Stdout, res.Stderr)
				}
			}
		}
		ping(t, devA, s4) // still connected
	})

	t.Run("the log is root's", func(t *testing.T) {
		res, err := cli(t, devA, as(aliceUID, apiGID, "logs"))
		if err == nil || !strings.Contains(res.Stderr, "only root") {
			t.Fatalf("alice read the log: %v\n%s", err, res.Stdout)
		}
		res, err = cli(t, devA, as("", "", "logs", "-n", "1000"))
		if err != nil || !strings.Contains(res.Stdout, `msg=connected`) {
			t.Fatalf("root: %v\n%s", err, res.Stdout)
		}
	})

	t.Run("a device disconnects and leaves nothing up", func(t *testing.T) {
		res, err := cli(t, devA, as(aliceUID, apiGID, "disconnect"))
		if err != nil || !regexp.MustCompile(`state: +disconnected`).MatchString(res.Stdout) {
			t.Fatalf("disconnect: %v\n%s", err, res.Stdout)
		}
		if _, err := cli(t, devA, []string{"ip", "link", "show", "thinkpol0"}); err == nil {
			t.Fatal("the TUN outlived the disconnect")
		}
		noPing(t, devA, s4.String())
		ping(t, devB, s4) // the others carry on
		if _, err := cli(t, devA, as("", "", "connect")); err != nil {
			t.Fatal(err)
		}
		ping(t, devA, b4)
	})

	t.Run("a server reports its workers and listeners", func(t *testing.T) {
		res, err := cli(t, server, as("", "", "status"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`state: +serving`, `mode: +server`, `workers:`, `\d+ starts`, `public listeners:`, `udp +routed [1-9]`} {
			if !regexp.MustCompile(want).MatchString(res.Stdout) {
				t.Errorf("no %q in\n%s", want, res.Stdout)
			}
		}
		clean(t, "server-1's status", res.Stdout)
		res, err = cli(t, server, as("", "", "connect"))
		if err == nil || !strings.Contains(res.Stderr, "this node is a server") {
			t.Fatalf("connect on a server: %v\n%s%s", err, res.Stdout, res.Stderr)
		}
	})

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
	for _, n := range nodes {
		if out := n.MustExec(t, "ls", "-A", "/run/thinkpol-api"); out != "" {
			t.Errorf("%s: left in /run/thinkpol-api: %s", n.Name, out)
		}
	}
}

// addrOn is a node's addresses on a network, if it is on it.
func addrOn(n *lab.Node, network string) (addrs []string, ok bool) {
	defer func() {
		if recover() != nil {
			addrs, ok = nil, false
		}
	}()
	a := n.Addr(network)
	if a.IPv4.IsValid() {
		addrs = append(addrs, a.IPv4.String())
	}
	if a.IPv6.IsValid() {
		addrs = append(addrs, a.IPv6.String())
	}
	return addrs, true
}
