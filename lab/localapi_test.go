//go:build lab

package lab_test

import (
	"context"
	"fmt"
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

	// device-a has a socket directory left from an earlier run, with the
	// wrong mode and group: it is fixed. device-b's API can't serve (its
	// directory is someone else's): its VPN runs all the same.
	devA.MustExec(t, "install", "-d", "-m", "2777", "/run/thinkpol-api")
	devB.MustExec(t, "install", "-d", "-m", "755", "-o", malloryUID, "/run/foreign-api")
	up := map[string]*lab.Process{
		"server-1": server.Start(t, "thinkpol", "up"),
		"device-a": devA.Start(t, "thinkpol", "up", "-connect=false"),
		"device-b": devB.Start(t, "env", "THINKPOL_API_SOCKET=/run/foreign-api/api.sock", "thinkpol", "up"),
	}
	waitLog(t, up["server-1"], `worker space=\S+ .*msg="map applied"`)
	waitLog(t, up["device-a"], "mode=device")
	s4, s6 := space.overlay(1)
	b4, _ := space.overlay(3)

	t.Run("an API that can't serve leaves the VPN up", func(t *testing.T) {
		waitLog(t, up["device-b"], `level=ERROR msg="the local API is down`)
		ping(t, devB, s4)
		if _, err := cli(t, devB, as("", "", "status", "-socket", "/run/foreign-api/api.sock")); err == nil {
			t.Fatal("status from an API that can't serve")
		}
	})

	t.Run("the socket's directory admits root and the group", func(t *testing.T) {
		for _, n := range []*lab.Node{server, devA} {
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

	t.Run("the group sets the rule preset, the service stores it", func(t *testing.T) {
		// The M0 map has no chain to build "everything" from: the choice
		// is kept and enforced failing closed, and the CLI says so.
		res, err := cli(t, devA, as(aliceUID, apiGID, "rules", "preset", "everything"))
		if err == nil || !strings.Contains(res.Stderr, "enforced failing closed") {
			t.Fatalf("preset: %v\n%s%s", err, res.Stdout, res.Stderr)
		}
		if got := devA.MustExec(t, "stat", "-c", "%a %U", stateDir+"/rules.local"); got != "644 root\n" {
			t.Errorf("rules.local: %q", got)
		}
		if got := devA.MustExec(t, "cat", stateDir+"/rules.local"); got != "preset everything\n" {
			t.Errorf("rules.local holds %q", got)
		}
		res, err = cli(t, devA, as(aliceUID, apiGID, "status"))
		if err != nil || !regexp.MustCompile(`rule preset: +everything \(unavailable in this space: failing closed\)`).MatchString(res.Stdout) {
			t.Fatalf("status: %v\n%s", err, res.Stdout)
		}
		ping(t, devA, s4) // the overlay is never routed by the rules
		res, err = cli(t, devA, as(aliceUID, apiGID, "rules", "preset", "space"))
		if err != nil || !regexp.MustCompile(`rule preset: +space\n`).MatchString(res.Stdout) {
			t.Fatalf("back to the space's rules: %v\n%s%s", err, res.Stdout, res.Stderr)
		}
		res, err = cli(t, devA, as(aliceUID, apiGID, "rules", "preset", "sometimes"))
		if err == nil || !strings.Contains(res.Stderr, "no such rule preset") {
			t.Fatalf("unknown preset: %v\n%s", err, res.Stderr)
		}
		res, err = cli(t, devA, as(malloryUID, "", "rules", "preset", "space"))
		if err == nil || !strings.Contains(res.Stderr, "permission denied") {
			t.Fatalf("mallory: %v\n%s", err, res.Stderr)
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
	for _, n := range []*lab.Node{server, devA} {
		// The lock file stays, unlocked, for the next run.
		if out := n.MustExec(t, "ls", "-A", "/run/thinkpol-api"); out != "api.lock\n" {
			t.Errorf("%s: left in /run/thinkpol-api: %s", n.Name, out)
		}
	}
}

// TestDisconnectLeavesNothingBehind is the teardown check behind the CLI
// (TestLocalAPI checks only the TUN): with the DNS map (rules and DNS),
// after `thinkpol disconnect` the route table's rules and routes,
// resolv.conf and the IPv6 guard table are all gone, and come back on
// `connect` — both families' rules, the guard's chain with its table, and
// AAAA resolution included. device-b carries on throughout.
func TestDisconnectLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, devB, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	startResolvers(t, inet)

	space, v1 := buildDNSMap(t, inet, server, devA, devB)
	s4, _ := space.overlay(1)
	a4, _ := space.overlay(2)
	b4, _ := space.overlay(3)

	original := osResolvConf(inetIP)
	devA.WriteFile(t, "/etc/resolv.conf", original)
	rulesBefore := devA.MustExec(t, "ip", "rule") + "\n" + devA.MustExec(t, "ip", "-6", "rule")

	exit := startServerExit(t, server, inetIP, v1)
	devBUp := devB.Start(t, "thinkpol", "up")
	up := devA.Start(t, "thinkpol", "up", "-connect=false")
	waitLog(t, up, "mode=device")

	// What a disconnect must take away is all there while connected, and
	// all gone after: the route table's rules and routes (both families),
	// resolv.conf and the guard table with its chain.
	state := func(connected bool) error {
		rules4, rules6 := devA.MustExec(t, "ip", "rule"), devA.MustExec(t, "ip", "-6", "rule")
		if connected {
			if !strings.Contains(rules4, "5301:") || !strings.Contains(rules6, "5301:") {
				return fmt.Errorf("no route-table rules while connected:\n%s%s", rules4, rules6)
			}
		} else {
			if got := rules4 + "\n" + rules6; got != rulesBefore {
				return fmt.Errorf("rules after disconnecting:\n%s\nwant\n%s", got, rulesBefore)
			}
			if _, err := cli(t, devA, []string{"ip", "link", "show", "thinkpol0"}); err == nil {
				return fmt.Errorf("the TUN outlived the disconnect")
			}
		}
		if got := routeTableRoutes(t, devA) != ""; got != connected {
			return fmt.Errorf("the route table's routes: present %v, want %v", got, connected)
		}
		conf := devA.MustExec(t, "cat", "/etc/resolv.conf")
		if connected {
			if !strings.Contains(conf, "nameserver "+a4.String()+"\n") {
				return fmt.Errorf("resolv.conf while connected:\n%s", conf)
			}
		} else if conf != string(original) {
			return fmt.Errorf("resolv.conf after disconnecting:\n%s\nwant\n%s", conf, original)
		}
		if got := hasGuard(t, devA); got != connected {
			return fmt.Errorf("the IPv6 guard: present %v, want %v", got, connected)
		}
		return nil
	}

	res, err := cli(t, devA, as("", "", "connect"))
	if err != nil || !regexp.MustCompile(`state: +connected`).MatchString(res.Stdout) {
		t.Fatalf("connect: %v\n%s", err, res.Stdout)
	}
	ping(t, devA, s4)
	lab.Eventually(t, 30*time.Second, func() error { return state(true) })
	capture := devA.Capture(t, "")
	mustResolve(t, devA, "www.tunnel.test", false, foreignA)
	mustResolve(t, devA, "www.tunnel.test", true, foreignAAAA)
	mustResolve(t, devA, "device-b.lab.internal", false, b4.String())
	mustResolve(t, devA, "www.direct.test", false, domesticA)
	if err := capture.Complete(); err != nil {
		t.Fatal(err)
	}
	noLeaks(t, capture.Stop(), inetIP)

	res, err = cli(t, devA, as("", "", "disconnect"))
	if err != nil || !regexp.MustCompile(`state: +disconnected`).MatchString(res.Stdout) {
		t.Fatalf("disconnect: %v\n%s", err, res.Stdout)
	}
	lab.Eventually(t, 30*time.Second, func() error { return state(false) })
	noPing(t, devA, s4.String())
	ping(t, devB, s4) // the others carry on

	// And everything is back on connect.
	res, err = cli(t, devA, as("", "", "connect"))
	if err != nil || !regexp.MustCompile(`state: +connected`).MatchString(res.Stdout) {
		t.Fatalf("reconnect: %v\n%s", err, res.Stdout)
	}
	ping(t, devA, s4)
	lab.Eventually(t, 30*time.Second, func() error { return state(true) })
	mustResolve(t, devA, "www.tunnel.test", true, foreignAAAA)

	if err := up.Stop(); err != nil {
		t.Errorf("device-a: thinkpol up exited with %v:\n%s", err, up.Output())
	}
	if err := devBUp.Stop(); err != nil {
		t.Errorf("device-b: thinkpol up exited with %v:\n%s", err, devBUp.Output())
	}
	if err := exit.Stop(); err != nil {
		t.Errorf("the exit: %v\n%s", err, exit.Output())
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
