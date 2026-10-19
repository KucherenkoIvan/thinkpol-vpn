//go:build lab

package lab_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// listSource is a DB-IP Lite CSV in miniature: what `thinkpol dev lists
// build` makes the lab's list from.
const listSource = "5.3.0.0,5.3.255.255,RU\n" +
	"37.17.0.0,37.17.127.255,BY\n" +
	"77.88.8.0,77.88.8.255,RU\n" +
	"2a02:6b8::,2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff,RU\n"

// TestBlobDistribution is TP-017's acceptance: device-a's map names a GeoIP
// list it doesn't have. It asks server-2 first, which sends a tampered copy
// (a stand-in that answers every request with junk of the right size): the
// device rejects it and fetches the list from server-1, whose worker holds
// it from the seed in server-1's state directory, then keeps it in its own
// state directory. A tampered copy there is rejected at the next start and
// fetched again.
func TestBlobDistribution(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	builder := l.Node(lab.Internet)
	server1, server2, devA := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA)

	// The space, its list and its map, made on a node outside it.
	builder.WriteFile(t, "/tmp/bl/dbip-country-lite.csv", []byte(listSource))
	builder.MustExec(t, "sh", "-ec", `cd /tmp/bl
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 server-2 device-a >/dev/null
		thinkpol dev lists build -only ru -out lists dbip-country-lite.csv >/dev/null`)
	out := builder.MustExec(t, "env", "SERVER_1_IPV4="+server1.IPv4(lab.NetServers).String(),
		"SERVER_2_IPV4="+server2.IPv4(lab.NetServers).String(), "RU_LIST=/tmp/bl/lists/ru.geoip",
		"sh", "-ec", "cd /tmp/bl && thinkpol dev map build -keys keys -out map.bin /src/lab/maps/blobs.yaml")
	version := regexp.MustCompile(`map version (\d+)`).FindStringSubmatch(out)
	if version == nil {
		t.Fatalf("build said %q", out)
	}
	file := func(name string) []byte {
		t.Helper()
		b, err := base64.StdEncoding.DecodeString(builder.MustExec(t, "base64", "-w0", "/tmp/bl/"+name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	list := file("lists/ru.geoip")
	sum := sha256.Sum256(list)
	blobFile := stateDir + "/blobs/" + hex.EncodeToString(sum[:])
	nodeID := func(name string) string {
		m := regexp.MustCompile(`node-id: "([0-9a-f]+)"`).FindSubmatch(file("keys/" + name + ".pub"))
		if m == nil {
			t.Fatalf("no node id for %s", name)
		}
		return string(m[1])
	}
	server1ID, server2ID := nodeID("server-1"), nodeID("server-2")
	envelope := file("map.bin")
	for name, n := range map[string]*lab.Node{"server-1": server1, "server-2": server2, "device-a": devA} {
		n.MustExec(t, "install", "-d", "-m", "700", stateDir)
		n.WriteFile(t, stateDir+"/node.key", file("keys/"+name+".key"))
		n.WriteFile(t, stateDir+"/space.pub", file("keys/space.pub"))
		n.MustExec(t, "chmod", "600", stateDir+"/node.key")
		putMap(t, n, envelope)
	}
	// server-1's seed: the list, under its hash, where provisioning puts it.
	server1.MustExec(t, "install", "-d", "-m", "700", stateDir+"/blobs")
	server1.WriteFile(t, blobFile, list)
	server1.MustExec(t, "chmod", "600", blobFile)

	// server-2's overlay address answers on the blob port with a tampered
	// list, once: a server that has been tampered with. server-2 runs in
	// device mode, so its overlay address is in the node's own namespace,
	// where the stand-in listens, and thinkpol serves no blobs there.
	resp := binary.BigEndian.AppendUint64([]byte{0}, uint64(len(list)))
	resp = append(resp, []byte(strings.Repeat("\x5a", len(list)))...)
	server2.WriteFile(t, "/tmp/tampered.resp", resp)
	tampering := server2.Start(t, "sh", "-c", "exec nc -l 4717 < /tmp/tampered.resp")
	lab.Eventually(t, 30*time.Second, func() error {
		_, err := execRead(server2, pollTimeout, "sh", "-c", "ss -Htln 'sport = :4717' | grep -q .")
		return err
	})

	up1 := server1.Start(t, "thinkpol", "up")
	up2 := server2.Start(t, "thinkpol", "up", "-mode", "device")
	waitLog(t, up1, `worker space=\S+ .*`+applied(version[1]))
	waitLog(t, up2, applied(version[1]))

	upA := devA.Start(t, "thinkpol", "up")
	waitLog(t, upA, `msg="blob rejected: the peer sent something else; trying another peer" .*blob=\S+ kind=geoip name=ru peer=`+server2ID)
	waitLog(t, upA, `msg="blob fetched" .*blob=\S+ kind=geoip name=ru size=\d+ peer=`+server1ID)
	<-tampering.Done()
	if got := devA.MustExec(t, "sha256sum", blobFile); !strings.HasPrefix(got, hex.EncodeToString(sum[:])) {
		t.Fatalf("device-a keeps %q", got)
	}
	if got := devA.MustExec(t, "stat", "-c", "%a", blobFile, stateDir+"/blobs"); got != "600\n700\n" {
		t.Errorf("modes of the stored list and its directory: %q", got)
	}
	// A server keeps what it fetches in memory only: server-1's state
	// directory is as it was.
	if got := server1.MustExec(t, "sh", "-c", "cd "+stateDir+" && find . | sort"); got != ".\n./blobs\n./blobs/"+hex.EncodeToString(sum[:])+"\n./map.bin\n./node.key\n./space.pub\n" {
		t.Errorf("server-1's state directory:\n%s", got)
	}

	// A tampered copy in device-a's state directory is rejected at the
	// next start and fetched again.
	if err := upA.Stop(); err != nil {
		t.Fatalf("device-a: %v\n%s", err, upA.Output())
	}
	devA.MustExec(t, "sh", "-ec", `printf 'Z' | dd of=`+blobFile+` bs=1 seek=8 conv=notrunc status=none`)
	upA = devA.Start(t, "thinkpol", "up")
	waitLog(t, upA, `msg="stored blob rejected: it doesn't match the map; fetching it again" .*blob=\S+ kind=geoip name=ru`)
	waitLog(t, upA, `msg="blob fetched" .*blob=\S+ kind=geoip name=ru`)
	lab.Eventually(t, 30*time.Second, func() error {
		_, err := execRead(devA, pollTimeout, "sh", "-c", "sha256sum "+blobFile+" | grep -q ^"+hex.EncodeToString(sum[:]))
		return err
	})
	t.Run("the blob port answers only peers through the tunnel", func(t *testing.T) {
		m := regexp.MustCompile(`ipv6-network: "([^"]+)"`).FindSubmatch(file("keys/space.key"))
		if m == nil {
			t.Fatal("no IPv6 network in space.key")
		}
		ula := netip.MustParsePrefix(string(m[1])).Addr().As16()
		overlay := func(n byte) (string, string) {
			v6 := ula
			v6[15] = n
			return fmt.Sprintf("100.64.0.%d", n), netip.AddrFrom16(v6).String()
		}
		s1v4, s1v6 := overlay(1)
		dv4, dv6 := overlay(3)
		// reaches says whether a TCP connect from n to addr:port succeeds.
		// Only nc's own failure (exit 1 with its "connect to ... failed"
		// line; docker exec also exits 1 when docker fails) means it
		// doesn't; any other failure (an exec error, a timeout, no nc) is
		// an unknown state and an error.
		reaches := func(n *lab.Node, timeout time.Duration, addr, port string) (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res, err := n.Exec(ctx, "nc", "-v", "-z", "-w", "3", addr, port)
			switch {
			case err == nil:
				return true, nil
			case res.ExitCode == 1 && strings.Contains(res.Stderr, "connect to ") && strings.Contains(res.Stderr, " failed"):
				return false, nil
			}
			return false, fmt.Errorf("nc %s %s from %s: %w", addr, port, n.Name, err)
		}
		// A request for the list, as a peer sends it.
		req := append([]byte("TPB\x01"), sum[:]...)
		req = binary.BigEndian.AppendUint64(req, 0)
		answer := func(n *lab.Node, prefix, addr string) int {
			n.WriteFile(t, "/tmp/blob.req", req)
			out := n.MustExec(t, "sh", "-c", prefix+"nc -w 3 "+addr+" 4717 < /tmp/blob.req | wc -c")
			var got int
			_, _ = fmt.Sscan(out, &got)
			return got
		}

		// Through the tunnel, server-1's worker answers a peer.
		for _, addr := range []string{s1v4, s1v6} {
			if got, want := answer(devA, "", addr), 1+8+len(list); got != want {
				t.Errorf("device-a got %d bytes from %s:4717 through the tunnel, want %d", got, addr, want)
			}
		}
		// A process in the worker's own namespace (the kernel delivers it as
		// if through the TUN) is no peer: it gets nothing.
		pid := strings.TrimSpace(server1.MustExec(t, "pgrep", "-f", "thinkpol worker"))
		inWorker := "nsenter --net=/proc/" + pid + "/ns/net "
		for _, addr := range []string{s1v4, s1v6} {
			if got := answer(server1, inWorker, addr); got != 0 {
				t.Errorf("a local process in server-1's worker got %d bytes from %s:4717", got, addr)
			}
		}

		// Devices, and servers run in device mode, only fetch: nothing
		// listens on the blob port there.
		for name, n := range map[string]*lab.Node{"device-a": devA, "server-2": server2} {
			if out := n.MustExec(t, "sh", "-c", "ss -Htln 'sport = :4717'"); out != "" {
				t.Errorf("%s listens on the blob port:\n%s", name, out)
			}
		}
		// From the router, a neighbour of device-a's on its LAN, routed to
		// its overlay addresses by its LAN addresses: a listener there not
		// bound to the TUN answers (the route works), the blob port doesn't.
		router := l.Node(lab.Router)
		router.MustExec(t, "ip", "route", "add", dv4+"/32", "via", devA.IPv4(lab.NetDevices).String())
		router.MustExec(t, "ip", "-6", "route", "add", dv6+"/128", "via", devA.IPv6(lab.NetDevices).String())
		control4 := devA.Start(t, "nc", "-4", "-l", "4718")
		control6 := devA.Start(t, "nc", "-6", "-l", "4719")
		for _, c := range []struct{ addr, port string }{{dv4, "4718"}, {dv6, "4719"}} {
			lab.Eventually(t, 30*time.Second, func() error {
				ok, err := reaches(router, pollTimeout, c.addr, c.port)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("the control listener at %s:%s is unreachable from the router", c.addr, c.port)
				}
				return nil
			})
		}
		_, _ = control4.Stop(), control6.Stop()
		for _, addr := range []string{dv4, dv6} {
			if ok, err := reaches(router, execTimeout, addr, "4717"); err != nil {
				t.Fatal(err)
			} else if ok {
				t.Errorf("the router reaches device-a's %s:4717 outside the tunnel", addr)
			}
		}
		// A server's overlay addresses live in its worker's namespace, which
		// a neighbour's packets for them never reach.
		builder.MustExec(t, "ip", "route", "add", s1v4+"/32", "via", server1.IPv4(lab.NetServers).String())
		builder.MustExec(t, "ip", "-6", "route", "add", s1v6+"/128", "via", server1.IPv6(lab.NetServers).String())
		for _, addr := range []string{s1v4, s1v6} {
			if ok, err := reaches(builder, execTimeout, addr, "4717"); err != nil {
				t.Fatal(err)
			} else if ok {
				t.Errorf("a neighbour reaches server-1's %s:4717 outside the tunnel", addr)
			}
		}
	})

	for name, p := range map[string]*lab.Process{"server-1": up1, "server-2": up2, "device-a": upA} {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v", name, err)
		}
	}
}
