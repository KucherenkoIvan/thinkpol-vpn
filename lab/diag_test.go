//go:build lab

package lab_test

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
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
	Routes struct {
		Unreadable string `json:"unreadable"`
		Routes     []struct {
			Owner       string `json:"owner"`
			Family      string `json:"family"`
			Destination string `json:"destination"`
			Type        string `json:"type"`
			Gateway     string `json:"gateway"`
			Interface   string `json:"interface"`
			Metric      int    `json:"metric"`
			Table       int    `json:"table"`
		} `json:"routes"`
	} `json:"routes"`
	Rules struct {
		Unreadable string `json:"unreadable"`
		Rules      []struct {
			Owner             string `json:"owner"`
			Family            string `json:"family"`
			Priority          int    `json:"priority"`
			Table             int    `json:"table"`
			Destination       string `json:"destination"`
			Oif               string `json:"oif"`
			Mark              uint32 `json:"mark"`
			Mask              uint32 `json:"mask"`
			Invert            bool   `json:"invert"`
			SuppressPrefixlen *int   `json:"suppressPrefixlen"`
		} `json:"rules"`
	} `json:"rules"`
	Guard struct {
		Unreadable string `json:"unreadable"`
		Where      string `json:"where"`
		Present    bool   `json:"present"`
		Rules      struct {
			Unreadable string `json:"unreadable"`
			Rules      []struct {
				Chain   string `json:"chain"`
				Text    string `json:"text"`
				Counted bool   `json:"counted"`
				Packets uint64 `json:"packets,string"`
			} `json:"rules"`
		} `json:"rules"`
		Exempt struct {
			Unreadable string   `json:"unreadable"`
			Prefixes   []string `json:"prefixes"`
		} `json:"exempt"`
		Nftables struct {
			Dormant bool `json:"dormant"`
			Chains  []struct {
				Name     string `json:"name"`
				Hook     string `json:"hook"`
				Priority int    `json:"priority"`
				Policy   string `json:"policy"`
			} `json:"chains"`
		} `json:"nftables"`
	} `json:"guard"`
	LastApply struct {
		Unreadable string `json:"unreadable"`
		Started    string `json:"started"`
		Took       string `json:"took"`
		Failed     string `json:"failed"`
		Steps      []struct {
			Step   string `json:"step"`
			Took   string `json:"took"`
			Failed bool   `json:"failed"`
		} `json:"steps"`
	} `json:"lastApply"`
	DNS struct {
		Unreadable string `json:"unreadable"`
		Sources    []struct {
			Name       string `json:"name"`
			Unreadable string `json:"unreadable"`
			Present    bool   `json:"present"`
			Resolvers  []struct {
				Interface   string   `json:"interface"`
				Servers     []string `json:"servers"`
				Domains     []string `json:"domains"`
				Search      []string `json:"search"`
				Options     []string `json:"options"`
				NodeWritten bool     `json:"nodeWritten"`
			} `json:"resolvers"`
		} `json:"sources"`
	} `json:"dns"`
}

// resolvectlLinks reads `resolvectl dns` or `resolvectl domain`: per link
// ("" for global), its entries, sorted; links without any left out.
func resolvectlLinks(t *testing.T, n *lab.Node, what string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	line := regexp.MustCompile(`^(?:Global|Link [0-9]+ \((.+)\)):\s*(.*)$`)
	for _, l := range strings.Split(n.MustExec(t, "resolvectl", what), "\n") {
		m := line.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		if f := strings.Fields(m[2]); len(f) > 0 {
			slices.Sort(f)
			out[m[1]] = f
		}
	}
	return out
}

// ipTable is a table as ip names it, by number.
func ipTable(s string) int {
	switch s {
	case "", "main":
		return 254
	case "local":
		return 255
	case "default":
		return 253
	}
	n, _ := strconv.Atoi(s)
	return n
}

// ipPrefix is a destination as ip prints it ("default", a host without its
// length) as a prefix.
func ipPrefix(s string, family string, length int) string {
	switch {
	case s == "default" && family == "IPv4":
		return "0.0.0.0/0"
	case s == "default":
		return "::/0"
	case s == "" || strings.Contains(s, "/"):
		return s
	case length > 0:
		return netip.PrefixFrom(netip.MustParseAddr(s), length).String()
	}
	a := netip.MustParseAddr(s)
	return netip.PrefixFrom(a, a.BitLen()).String()
}

// ownersByProtocol are the agent's owners by the route protocol ip shows.
var ownersByProtocol = map[string]string{"84": "overlay", "85": "supervisor", "86": "route-table"}

// hostRoutes are the owners' routes as `ip -j route show table all`
// reports them, one line each.
func hostRoutes(t *testing.T, n *lab.Node) []string {
	t.Helper()
	var out []string
	for fam, flag := range map[string]string{"IPv4": "-4", "IPv6": "-6"} {
		var routes []struct {
			Type, Dst, Gateway, Dev, Table, Protocol string
			Metric                                   int
		}
		if err := json.Unmarshal([]byte(n.MustExec(t, "ip", "-j", flag, "route", "show", "table", "all")), &routes); err != nil {
			t.Fatal(err)
		}
		for _, r := range routes {
			owner, ok := ownersByProtocol[r.Protocol]
			if !ok {
				continue
			}
			typ := cmp.Or(r.Type, "unicast")
			out = append(out, fmt.Sprintf("%s %s %s %s via %q dev %q metric %d table %d", owner, fam, typ, ipPrefix(r.Dst, fam, 0), r.Gateway, r.Dev, r.Metric, ipTable(r.Table)))
		}
	}
	slices.Sort(out)
	return out
}

// hostRules are the owners' policy rules as `ip -j rule` reports them.
func hostRules(t *testing.T, n *lab.Node) []string {
	t.Helper()
	var out []string
	for fam, flag := range map[string]string{"IPv4": "-4", "IPv6": "-6"} {
		var rules []map[string]any
		if err := json.Unmarshal([]byte(n.MustExec(t, "ip", "-j", flag, "rule", "show")), &rules); err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			owner, ok := ownersByProtocol[fmt.Sprint(r["protocol"])]
			if !ok {
				continue
			}
			str := func(k string) string {
				if v, ok := r[k]; ok {
					return fmt.Sprint(v)
				}
				return ""
			}
			length, _ := r["dstlen"].(float64)
			_, not := r["not"]
			out = append(out, fmt.Sprintf("%s %s %v table %d to %q oif %q fwmark %q not %v suppress %q", owner, fam, r["priority"],
				ipTable(str("table")), ipPrefix(str("dst"), fam, int(length)), str("oif"), str("fwmark"), not, str("suppress_prefixlen")))
		}
	}
	slices.Sort(out)
	return out
}

// hostGuard is the guard's table as `nft -j` lists it: each rule's
// counter (-1 for none), the exempt set as prefixes, the chain.
func hostGuard(t *testing.T, n *lab.Node) (counters []int64, exempt []string, chain string) {
	t.Helper()
	var listing struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(n.MustExec(t, "nft", "-j", "list", "table", "inet", "thinkpol-guard")), &listing); err != nil {
		t.Fatal(err)
	}
	var b lists.Builder
	for _, obj := range listing.Nftables {
		switch {
		case obj["rule"] != nil:
			var rule struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			}
			if err := json.Unmarshal(obj["rule"], &rule); err != nil {
				t.Fatal(err)
			}
			c := int64(-1)
			for _, x := range rule.Expr {
				if raw, ok := x["counter"]; ok {
					var counter struct{ Packets int64 }
					if err := json.Unmarshal(raw, &counter); err != nil {
						t.Fatal(err)
					}
					c = counter.Packets
				}
			}
			counters = append(counters, c)
		case obj["chain"] != nil:
			var ch struct {
				Name, Hook, Policy string
				Prio               int
			}
			if err := json.Unmarshal(obj["chain"], &ch); err != nil {
				t.Fatal(err)
			}
			chain = fmt.Sprintf("%s %s %d %s", ch.Name, ch.Hook, ch.Prio, ch.Policy)
		case obj["set"] != nil:
			var set struct{ Elem []json.RawMessage }
			if err := json.Unmarshal(obj["set"], &set); err != nil {
				t.Fatal(err)
			}
			for _, e := range set.Elem {
				var addr string
				var elem struct {
					Prefix *struct {
						Addr string
						Len  int
					}
					Range []string
				}
				var err error
				switch {
				case json.Unmarshal(e, &addr) == nil:
					err = b.AddPrefix(netip.MustParsePrefix(ipPrefix(addr, "IPv6", 0)))
				case json.Unmarshal(e, &elem) == nil && elem.Prefix != nil:
					err = b.AddPrefix(netip.PrefixFrom(netip.MustParseAddr(elem.Prefix.Addr), elem.Prefix.Len))
				case len(elem.Range) == 2:
					err = b.AddRange(netip.MustParseAddr(elem.Range[0]), netip.MustParseAddr(elem.Range[1]))
				default:
					t.Fatalf("nft lists an element %s", e)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	s, _ := b.Build()
	for _, p := range s.Prefixes() {
		exempt = append(exempt, p.String())
	}
	return counters, exempt, chain
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
	// The device resolves through systemd-resolved: the snapshot shows its
	// links and resolv.conf (its stub).
	startResolved(t, dev, internet.IPv4(lab.NetServers))

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

	t.Run("the routes and rules are as ip shows them", func(t *testing.T) {
		d, out := diag(t, as("", "", "diag")...)
		if d.Routes.Unreadable != "" || d.Rules.Unreadable != "" {
			t.Fatalf("unreadable: %s", out)
		}
		var routes []string
		for _, r := range d.Routes.Routes {
			routes = append(routes, fmt.Sprintf("%s %s %s %s via %q dev %q metric %d table %d", r.Owner, r.Family, r.Type, r.Destination, r.Gateway, r.Interface, r.Metric, r.Table))
		}
		slices.Sort(routes)
		var rules []string
		for _, r := range d.Rules.Rules {
			mark := ""
			if r.Mark != 0 {
				mark = fmt.Sprintf("0x%x", r.Mark)
				if r.Mask != 0xffffffff {
					mark += fmt.Sprintf("/0x%x", r.Mask)
				}
			}
			suppress := ""
			if r.SuppressPrefixlen != nil && *r.SuppressPrefixlen >= 0 {
				suppress = strconv.Itoa(*r.SuppressPrefixlen)
			}
			if r.SuppressPrefixlen == nil {
				suppress = "0" // protojson leaves a zero out
			}
			rules = append(rules, fmt.Sprintf("%s %s %d table %d to %q oif %q fwmark %q not %v suppress %q", r.Owner, r.Family, r.Priority, r.Table, r.Destination, r.Oif, mark, r.Invert, suppress))
		}
		slices.Sort(rules)
		// A route-table device holds a table of its own with a default into
		// the TUN, throws, unreachable defaults, and four rules a family.
		if len(routes) < 6 || len(rules) < 8 {
			t.Fatalf("only %d routes and %d rules:\n%s", len(routes), len(rules), out)
		}
		if host := hostRoutes(t, dev); !slices.Equal(routes, host) {
			t.Errorf("routes:\n%s\nip:\n%s", strings.Join(routes, "\n"), strings.Join(host, "\n"))
		}
		if host := hostRules(t, dev); !slices.Equal(rules, host) {
			t.Errorf("rules:\n%s\nip:\n%s", strings.Join(rules, "\n"), strings.Join(host, "\n"))
		}
	})

	t.Run("the guard is as nft lists it", func(t *testing.T) {
		// A bound ping the guard refuses, so its counter has counted.
		ifc := dev.Interface(lab.NetDevices)
		if _, err := execRead(dev, execTimeout, "ping", "-6", "-c", "1", "-W", "1", "-I", ifc, "2001:db8:ab::7"); err == nil {
			t.Fatal("a ping bound to the physical interface was answered")
		}
		d, out := diag(t, as("", "", "diag")...)
		counters, exempt, chain := hostGuard(t, dev)
		g := d.Guard
		if g.Unreadable != "" || !g.Present || g.Rules.Unreadable != "" || g.Exempt.Unreadable != "" || g.Nftables.Dormant ||
			g.Where != "nftables table inet thinkpol-guard" {
			t.Fatalf("guard: %s", out)
		}
		if len(g.Nftables.Chains) != 1 {
			t.Fatalf("chains: %s", out)
		}
		if c := g.Nftables.Chains[0]; fmt.Sprintf("%s %s %d %s", c.Name, c.Hook, c.Priority, c.Policy) != chain {
			t.Errorf("chain %+v, nft %q", c, chain)
		}
		if len(g.Rules.Rules) != len(counters) || len(counters) < 8 {
			t.Fatalf("%d rules, nft lists %d:\n%s", len(g.Rules.Rules), len(counters), out)
		}
		refused := uint64(0)
		for i, r := range g.Rules.Rules {
			// Counters only grow: nft read them after diag did.
			if r.Counted != (counters[i] >= 0) || r.Counted && int64(r.Packets) > counters[i] {
				t.Errorf("rule %d %q: counted %v, %d packets; nft: %d", i, r.Text, r.Counted, r.Packets, counters[i])
			}
			if strings.Contains(r.Text, "icmpx") {
				refused = r.Packets
			}
		}
		if refused == 0 {
			t.Errorf("the refused ping isn't counted:\n%s", out)
		}
		if !slices.Equal(g.Exempt.Prefixes, exempt) || len(exempt) < 3 {
			t.Errorf("exempt %q, nft %q", g.Exempt.Prefixes, exempt)
		}
	})

	t.Run("the resolvers are as resolvectl and resolv.conf show them", func(t *testing.T) {
		d, out := diag(t, as("", "", "diag")...)
		if d.DNS.Unreadable != "" || len(d.DNS.Sources) != 2 {
			t.Fatalf("dns: %s", out)
		}
		conf, resolved := d.DNS.Sources[0], d.DNS.Sources[1]
		if conf.Name != "resolv.conf" || conf.Unreadable != "" || !conf.Present || len(conf.Resolvers) != 1 || conf.Resolvers[0].NodeWritten ||
			resolved.Name != "systemd-resolved" || resolved.Unreadable != "" || !resolved.Present {
			t.Fatalf("dns: %s", out)
		}
		var want []string
		for _, l := range strings.Split(dev.MustExec(t, "cat", "/etc/resolv.conf"), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
				want = append(want, f[1])
			}
		}
		if !slices.Equal(conf.Resolvers[0].Servers, want) || len(want) == 0 {
			t.Errorf("resolv.conf's servers %q, the file's %q", conf.Resolvers[0].Servers, want)
		}
		servers, domains := map[string][]string{}, map[string][]string{}
		for _, r := range resolved.Resolvers {
			if len(r.Servers) > 0 {
				servers[r.Interface] = slices.Sorted(slices.Values(r.Servers))
			}
			if all := slices.Concat(r.Domains, r.Search); len(all) > 0 {
				domains[r.Interface] = slices.Sorted(slices.Values(all))
			}
		}
		// The TUN takes every name ("~.") and searches the space's zone;
		// the device's own link keeps its server.
		if !slices.Contains(domains["thinkpol0"], "~.") || len(servers["thinkpol0"]) == 0 || len(servers[dev.Interface(lab.NetDevices)]) == 0 {
			t.Errorf("resolved's links: servers %q, domains %q", servers, domains)
		}
		if host := resolvectlLinks(t, dev, "dns"); !maps.EqualFunc(servers, host, slices.Equal) {
			t.Errorf("servers %q, resolvectl %q", servers, host)
		}
		if host := resolvectlLinks(t, dev, "domain"); !maps.EqualFunc(domains, host, slices.Equal) {
			t.Errorf("domains %q, resolvectl %q", domains, host)
		}
	})

	t.Run("the group gets all but the host parts", func(t *testing.T) {
		res, err := cli(t, dev, as(aliceUID, apiGID, "diag"))
		if err != nil {
			t.Fatalf("%v\n%s", err, res.Stderr)
		}
		var d diagSnapshot
		if err := json.Unmarshal([]byte(res.Stdout), &d); err != nil {
			t.Fatal(err)
		}
		const rootOnly = "root only: it names public addresses"
		if d.Tun.Name != "thinkpol0" || d.Routes.Unreadable != rootOnly || d.Rules.Unreadable != rootOnly ||
			d.Guard.Unreadable != rootOnly || len(d.Routes.Routes) != 0 || d.Guard.Present || d.DNS.Unreadable != rootOnly || len(d.DNS.Sources) != 0 {
			t.Errorf("the group's snapshot:\n%s", res.Stdout)
		}
		for _, a := range []netip.Addr{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)} {
			if strings.Contains(res.Stdout, a.String()) {
				t.Errorf("the group's snapshot names the entry's %s", a)
			}
		}
	})

	t.Run("the last Apply's steps", func(t *testing.T) {
		d, out := diag(t, as("", "", "diag")...)
		a := d.LastApply
		var steps []string
		for _, s := range a.Steps {
			if _, err := time.ParseDuration(s.Took); s.Failed || (s.Took != "" && err != nil) {
				t.Errorf("step %+v", s)
			}
			steps = append(steps, s.Step)
		}
		want := []string{"section", "rules", "route_table_shrink", "removals", "interface", "devices", "router", "route_table"}
		if a.Unreadable != "" || a.Failed != "" || !slices.Equal(steps, want) {
			t.Errorf("last apply %q, want %q:\n%s", steps, want, out)
		}
		if started, err := time.Parse(time.RFC3339Nano, a.Started); err != nil || time.Since(started) > 10*time.Minute {
			t.Errorf("started %q: %v", a.Started, err)
		}
	})

	t.Run("-o writes a file only its owner reads", func(t *testing.T) {
		diag(t, as("", "", "diag", "-o", "/tmp/diag.json")...)
		if got := dev.MustExec(t, "stat", "-c", "%a %U", "/tmp/diag.json"); got != "600 root\n" {
			t.Errorf("diag.json: %q", got)
		}
	})
}
