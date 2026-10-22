//go:build lab

package lab_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// diagSnapshot is the part of `thinkpol diag`'s JSON the lab checks.
type diagSnapshot struct {
	SchemaVersion int    `json:"schemaVersion"`
	Os            string `json:"os"`
	Status        struct {
		Connection string `json:"connection"`
	} `json:"status"`
	Tun struct {
		Unreadable string   `json:"unreadable"`
		Name       string   `json:"name"`
		Index      int      `json:"index"`
		Mtu        int      `json:"mtu"`
		Up         bool     `json:"up"`
		Addresses  []string `json:"addresses"`
	} `json:"tun"`
}

// ipLink is the part of `ip -j addr show` the lab compares with.
type ipLink struct {
	Ifindex  int      `json:"ifindex"`
	Ifname   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	Mtu      int      `json:"mtu"`
	AddrInfo []struct {
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

// TestDiagShowsWhatTheHostHolds runs device-a in route-table mode with the
// "all but domestic" preset, as TestRouteTableSendsOnlyDirectAroundTheTunnel
// does, and checks `thinkpol diag` against what the host's own tools
// report. No snapshot shows a key.
func TestDiagShowsWhatTheHostHolds(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, dev, internet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Internet)
	space := newM0Space(t, internet, server)
	space.spec = "/src/lab/maps/routetable.yaml"
	space.env = append(space.env, "DM_LIST=/tmp/m0/lists/dm.geoip")
	internet.WriteFile(t, "/tmp/m0/domestic.csv", []byte(domesticList))
	internet.MustExec(t, "sh", "-ec", "cd /tmp/m0 && thinkpol dev lists build -only dm -out lists domestic.csv >/dev/null")
	envelope, v1 := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	list := space.file(t, "lists/dm.geoip")
	sum := sha256.Sum256(list)
	seed := stateDir + "/blobs/" + hex.EncodeToString(sum[:])
	server.MustExec(t, "install", "-d", "-m", "700", stateDir+"/blobs")
	server.WriteFile(t, seed, list)
	server.MustExec(t, "chmod", "600", seed)
	dev.MustExec(t, "groupadd", "-g", apiGID, "thinkpol")

	srv := server.Start(t, "thinkpol", "up", "-map-poll", "1s")
	up := dev.Start(t, "thinkpol", "up", "-map-poll", "1s")
	waitLog(t, srv, `worker space=\S+ .*`+applied(v1))
	waitLog(t, up, applied(v1)+`.*route_table_routes=`)
	waitLog(t, up, `msg="blob fetched" .*name=dm`)
	dev.MustExec(t, "thinkpol", "rules", "preset", "all-but-domestic")
	s4, _ := space.overlay(1)
	ping(t, dev, s4)

	var secrets []string
	keys := dev.MustExec(t, "cat", stateDir+"/node.key")
	for _, m := range regexp.MustCompile(`(?m)^(?:map|wireguard)-key: "([0-9a-f]+)"`).FindAllStringSubmatch(keys, -1) {
		secrets = append(secrets, m[1])
	}
	if len(secrets) != 2 {
		t.Fatalf("found %d keys in node.key", len(secrets))
	}
	diag := func(t *testing.T, args ...string) (diagSnapshot, string) {
		t.Helper()
		res, err := cli(t, dev, args)
		if err != nil {
			t.Fatalf("diag: %v\n%s%s", err, res.Stdout, res.Stderr)
		}
		out := res.Stdout
		if slices.Contains(args, "-o") {
			out = dev.MustExec(t, "cat", args[len(args)-1])
		}
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("the snapshot shows a key:\n%s", out)
			}
		}
		var d diagSnapshot
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("diag's JSON: %v\n%s", err, out)
		}
		if d.SchemaVersion != 1 || d.Os != "linux" || d.Status.Connection != "CONNECTION_CONNECTED" {
			t.Fatalf("diag: %+v", d)
		}
		return d, out
	}

	t.Run("the TUN is as ip shows it", func(t *testing.T) {
		d, out := diag(t, as("", "", "diag")...)
		var links []ipLink
		if err := json.Unmarshal([]byte(dev.MustExec(t, "ip", "-j", "addr", "show", "dev", "thinkpol0")), &links); err != nil || len(links) != 1 {
			t.Fatalf("ip -j addr: %v", err)
		}
		ln := links[0]
		var addrs []string
		for _, a := range ln.AddrInfo {
			addrs = append(addrs, netip.PrefixFrom(netip.MustParseAddr(a.Local), a.Prefixlen).String())
		}
		slices.SortFunc(addrs, func(a, b string) int {
			return netip.MustParsePrefix(a).Addr().Compare(netip.MustParsePrefix(b).Addr())
		})
		tun := d.Tun
		if tun.Unreadable != "" || tun.Name != ln.Ifname || tun.Index != ln.Ifindex || tun.Mtu != ln.Mtu ||
			tun.Up != slices.Contains(ln.Flags, "UP") || !slices.Equal(tun.Addresses, addrs) {
			t.Errorf("diag's TUN %+v, ip's %+v (%q)\n%s", tun, ln, addrs, out)
		}
	})

	t.Run("-o writes a file only its owner reads", func(t *testing.T) {
		diag(t, as("", "", "diag", "-o", "/tmp/diag.json")...)
		if got := dev.MustExec(t, "stat", "-c", "%a %U", "/tmp/diag.json"); got != "600 root\n" {
			t.Errorf("diag.json: %q", got)
		}
	})
}
