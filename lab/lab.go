package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// KeepEnv, when set, leaves a failed test's lab running for inspection;
// make lab-down removes it.
const KeepEnv = "THINKPOL_LAB_KEEP"

// Lab is one running topology: a Compose project of its own.
type Lab struct {
	Project  string
	Topology Topology
	root     string
	runDir   string
	binDir   string // mounted at BinDir
	nodes    map[string]*Node
	gateways map[string][]netip.Addr // Docker's bridge addresses, by network
	bridges  map[string]Bridge       // by network
	release  func()                  // the host-wide lab slot
}

// Bridge is Docker's own end of a lab network: the bridge in the Docker VM.
// It is the way out of the lab, so every node is cut off from it.
type Bridge struct {
	IPv4, IPv6 netip.Addr // the network's gateway addresses (IPv6 invalid on IPv4Only)
	LinkLocal  netip.Addr // its fe80:: address, derived from MAC
	MAC        string
}

// Start brings up a lab for the test and tears it down when the test ends.
// When the test fails, the containers' logs go to the test log. All the
// labs one top-level test starts share one slot of the cap, so a test
// starting a second lab never waits for itself.
func Start(t testing.TB, topo Topology) *Lab {
	return start(t, topo, "test:"+strings.SplitN(t.Name(), "/", 2)[0])
}

// StartOwnSlot is Start with one slot per test or subtest (keyed by its
// full name) instead of one per top-level test, held until that test ends:
// a test whose subtests each start one lab gives each subtest its own
// slot, so the cap bounds its labs like every other run's. Don't mix it
// with Start, or nest it under a test that holds a slot of its own: the
// parent holds its slot while its subtests wait here.
func StartOwnSlot(t testing.TB, topo Topology) *Lab {
	return start(t, topo, "own:"+t.Name())
}

func start(t testing.TB, topo Topology, slotKey string) *Lab {
	t.Helper()
	if !mainInstalled.Load() {
		t.Fatal("lab: this package's TestMain must call lab.Main(m), or the binaries its labs run are never removed")
	}
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	checkout, err := CheckoutProject(root)
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	project := claimProject(testProject(checkout, cwd, t.Name()))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	l, err := up(ctx, root, project, topo, slotKey, processBinaries)
	if l != nil {
		t.Cleanup(func() { l.cleanup(t) })
	}
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var (
	claimedMu sync.Mutex
	claimed   = map[string]int{}
)

// claimProject numbers the second and later labs a test starts.
func claimProject(project string) string {
	claimedMu.Lock()
	defer claimedMu.Unlock()
	claimed[project]++
	if n := claimed[project]; n > 1 {
		return fmt.Sprintf("%s-%d", project, n)
	}
	return project
}

func (l *Lab) cleanup(t testing.TB) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if t.Failed() {
		if res, err := runEnv(ctx, nil, environWithoutCompose(), "docker", "compose", "-f", l.ComposeFile(), "-p", l.Project, "logs", "--no-color", "--timestamps"); err == nil {
			t.Logf("lab %s logs:\n%s", l.Project, res.Stdout)
		}
		if os.Getenv(KeepEnv) != "" {
			t.Logf("lab %s kept: docker compose -p %s exec <node> bash; make lab-down removes it", l.Project, l.Project)
			if err := keepBinaries(l.binDir); err != nil {
				t.Errorf("lab %s: keep its binaries: %v", l.Project, err)
			}
			l.releaseSlot()
			return
		}
	}
	if err := l.Down(ctx); err != nil {
		t.Errorf("lab %s: tear down: %v", l.Project, err)
	}
}

// Up brings up a topology as the Compose project named project (which must
// start with ProjectPrefix), and returns once every node is running and
// sealed into the lab. A lab of this checkout left over under the same name
// is removed first; another checkout's lab under that name is an error. On
// error the returned Lab, if any, still needs Down.
//
// The lab runs this process's binaries, so it must be down before the
// process removes them (RemoveRunBinaries).
func Up(ctx context.Context, root, project string, topo Topology) (*Lab, error) {
	return up(ctx, root, project, topo, "", processBinaries)
}

// UpDetached is Up for a lab that outlives this process (make lab-up): its
// binaries are its own, built into its directory under lab/.run, and go
// with it (Down, or labctl down).
func UpDetached(ctx context.Context, root, project string, topo Topology) (*Lab, error) {
	return up(ctx, root, project, topo, "", labBinaries)
}

// binaries builds the image and the binaries a lab runs, and returns the
// directory it mounts at BinDir; labRunDir is the lab's lab/.run/<project>.
type binaries func(ctx context.Context, root, labRunDir string) (image, string, error)

// processBinaries are this process's, shared by its labs (prepare).
func processBinaries(ctx context.Context, root, _ string) (image, string, error) {
	p, err := prepare(ctx, root)
	if err != nil {
		return image{}, "", err
	}
	return p.img, p.bin.path, nil
}

// labBinaries are the lab's own, in labRunDir/bin.
func labBinaries(ctx context.Context, root, labRunDir string) (image, string, error) {
	t, img, err := prepareImage(ctx, root)
	if err != nil {
		return image{}, "", err
	}
	dir := filepath.Join(labRunDir, "bin")
	return img, dir, buildTools(ctx, root, t, dir)
}

func up(ctx context.Context, root, project string, topo Topology, slotKey string, bins binaries) (*Lab, error) {
	if !strings.HasPrefix(project, ProjectPrefix) {
		return nil, fmt.Errorf("lab: project %q doesn't start with %q", project, ProjectPrefix)
	}
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	if err := downProject(ctx, project, root); err != nil {
		return nil, err
	}
	runDir := filepath.Join(root, "lab", ".run", project)
	img, binDir, err := bins(ctx, root, runDir)
	var release func()
	if err == nil {
		release, err = acquireSlot(ctx, slotKey)
	}
	if err == nil {
		if err = os.MkdirAll(runDir, 0o755); err != nil {
			release()
		}
	}
	if err != nil {
		// Nothing of this lab's is up; a detached lab's binaries go too.
		return nil, errors.Join(err, os.RemoveAll(runDir))
	}
	l := &Lab{
		Project:  project,
		Topology: topo,
		root:     root,
		runDir:   runDir,
		binDir:   binDir,
		nodes:    map[string]*Node{},
		release:  release,
	}
	if err := l.create(ctx, img); err != nil {
		return l, err
	}
	if err := l.inspect(ctx); err != nil {
		return l, err
	}
	if err := l.learnBridges(ctx); err != nil {
		return l, err
	}
	if err := l.configure(ctx); err != nil {
		return l, err
	}
	return l, nil
}

// create allocates the lab's subnets and starts it. Allocation and network
// creation are serialized host-wide; a subnet another daemon user took in
// the meantime means another try.
func (l *Lab) create(ctx context.Context, img image) error {
	pool, err := subnetPool()
	if err != nil {
		return err
	}
	unlock, err := lockAllocation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	for attempt := 1; ; attempt++ {
		used, err := usedSubnets(ctx)
		if err != nil {
			return err
		}
		subnets, err := allocateSubnets(l.Topology.Networks, pool, used)
		if err != nil {
			return err
		}
		file, err := renderCompose(l.Project, l.Topology, img, l.root, l.binDir, subnets)
		if err != nil {
			return err
		}
		if err := os.WriteFile(l.ComposeFile(), file, 0o644); err != nil {
			return err
		}
		_, err = runEnv(ctx, nil, environWithoutCompose(), "docker", "compose", "-f", l.ComposeFile(), "-p", l.Project, "up", "-d", "--wait")
		if err == nil {
			return nil
		}
		if !isOverlap(err) || attempt == 5 {
			return fmt.Errorf("lab %s: up: %w", l.Project, err)
		}
		if err := downProject(ctx, l.Project, l.root); err != nil {
			return err
		}
	}
}

// ComposeFile is the generated Compose file, under lab/.run.
func (l *Lab) ComposeFile() string { return filepath.Join(l.runDir, "compose.json") }

// Down removes the lab's containers and networks.
func (l *Lab) Down(ctx context.Context) error {
	defer l.releaseSlot()
	if err := downProject(ctx, l.Project, l.root); err != nil {
		return err
	}
	return os.RemoveAll(l.runDir)
}

func (l *Lab) releaseSlot() {
	if l.release != nil {
		l.release()
		l.release = nil
	}
}

// Node returns a node of the lab's topology; an unknown name is a bug in the
// test and panics.
func (l *Lab) Node(name string) *Node {
	n, ok := l.nodes[name]
	if !ok {
		panic(fmt.Sprintf("lab %s: no node %q", l.Project, name))
	}
	return n
}

// DockerGateways are the addresses Docker gave its own bridge on a lab
// network. Every node has them blackholed: they are the way out of the lab.
func (l *Lab) DockerGateways(network string) []netip.Addr { return l.gateways[network] }

// DockerBridge is Docker's own end of a lab network, which every node is
// cut off from.
func (l *Lab) DockerBridge(network string) Bridge { return l.bridges[network] }

// Nodes lists the lab's nodes by name.
func (l *Lab) Nodes() []*Node {
	out := make([]*Node, 0, len(l.nodes))
	for _, n := range l.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type inspectedContainer struct {
	ID     string
	Config struct {
		Labels map[string]string
	}
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string
			GlobalIPv6Address string
			MacAddress        string
		}
	}
}

// inspect learns each node's container and addresses, and each network's
// Docker gateway.
func (l *Lab) inspect(ctx context.Context) error {
	res, err := docker(ctx, "ps", "-a", "-q", "--filter", "label=com.docker.compose.project="+l.Project)
	if err != nil {
		return err
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		return fmt.Errorf("lab %s: no containers", l.Project)
	}
	res, err = docker(ctx, append([]string{"inspect"}, ids...)...)
	if err != nil {
		return err
	}
	var containers []inspectedContainer
	if err := json.Unmarshal([]byte(res.Stdout), &containers); err != nil {
		return fmt.Errorf("lab %s: docker inspect: %w", l.Project, err)
	}
	for _, c := range containers {
		name := c.Config.Labels["com.docker.compose.service"]
		n := &Node{Name: name, Container: c.ID, lab: l, addrs: map[string]NodeAddr{}}
		for key, net := range c.NetworkSettings.Networks {
			network := strings.TrimPrefix(key, l.Project+"_")
			var a NodeAddr
			a.IPv4, _ = netip.ParseAddr(net.IPAddress)
			a.IPv6, _ = netip.ParseAddr(net.GlobalIPv6Address)
			a.mac = strings.ToLower(net.MacAddress)
			n.addrs[network] = a
		}
		l.nodes[name] = n
	}
	for _, n := range l.Topology.Nodes {
		if _, ok := l.nodes[n.Name]; !ok {
			return fmt.Errorf("lab %s: node %q has no container", l.Project, n.Name)
		}
	}

	l.gateways = map[string][]netip.Addr{}
	for _, net := range l.Topology.Networks {
		res, err := docker(ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}", l.Project+"_"+net.Name)
		if err != nil {
			return err
		}
		for _, s := range strings.Fields(res.Stdout) {
			s, _, _ = strings.Cut(s, "/")
			if a, err := netip.ParseAddr(s); err == nil {
				l.gateways[net.Name] = append(l.gateways[net.Name], a)
			}
		}
	}
	return nil
}

// learnBridges finds each network's bridge MAC from a node on it, before
// any node is sealed: the bridge answers ARP for the network's gateway
// address. The MAC also gives the bridge's link-local address.
func (l *Lab) learnBridges(ctx context.Context) error {
	l.bridges = map[string]Bridge{}
	for _, net := range l.Topology.Networks {
		var b Bridge
		for _, gw := range l.gateways[net.Name] {
			if gw.Is4() {
				b.IPv4 = gw
			} else {
				b.IPv6 = gw
			}
		}
		if !b.IPv4.IsValid() {
			return fmt.Errorf("lab %s: network %s has no IPv4 gateway", l.Project, net.Name)
		}
		i := slices.IndexFunc(l.Topology.Nodes, func(n NodeSpec) bool { return slices.Contains(n.Networks, net.Name) })
		if i < 0 {
			l.bridges[net.Name] = b
			continue
		}
		n := l.nodes[l.Topology.Nodes[i].Name]
		res, err := n.Exec(ctx, "sh", "-c", `ping -c 1 -W 1 "$0" >/dev/null 2>&1; ip -j neigh show "$0"`, b.IPv4.String())
		if err != nil {
			return fmt.Errorf("lab %s: network %s: %w", l.Project, net.Name, err)
		}
		var neigh []struct {
			LLAddr string `json:"lladdr"`
		}
		if err := json.Unmarshal([]byte(res.Stdout), &neigh); err != nil || len(neigh) == 0 || neigh[0].LLAddr == "" {
			return fmt.Errorf("lab %s: network %s: no MAC for the bridge at %s: %q", l.Project, net.Name, b.IPv4, res.Stdout)
		}
		b.MAC = strings.ToLower(neigh[0].LLAddr)
		if b.LinkLocal, err = linkLocalFromMAC(b.MAC); err != nil {
			return err
		}
		l.bridges[net.Name] = b
	}
	return nil
}

// linkLocalFromMAC is the EUI-64 link-local address Linux gives an
// interface with this MAC.
func linkLocalFromMAC(mac string) (netip.Addr, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return netip.Addr{}, fmt.Errorf("lab: bad MAC %q", mac)
	}
	a := [16]byte{0: 0xfe, 1: 0x80}
	copy(a[8:], []byte{hw[0] ^ 2, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]})
	return netip.AddrFrom16(a), nil
}

// sealedMarker is written once a node is sealed; a node's Command waits for
// it (see renderCompose).
const sealedMarker = "/run/lab/sealed"

// configure seals every node into the lab (see configureNode), all at once.
func (l *Lab) configure(ctx context.Context) error {
	var wg sync.WaitGroup
	errs := make([]error, len(l.Topology.Nodes))
	for i, spec := range l.Topology.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.configureNode(ctx, spec); err != nil {
				errs[i] = fmt.Errorf("lab %s: node %s: %w", l.Project, spec.Name, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// configureNode seals a node into the lab, replacing what Docker set up to
// connect a container to the outside. The default routes go (a gateway
// node's take their place). Docker's bridge, the Docker VM's end of every
// lab network, becomes unreachable: its addresses are blackholed, and
// nftables drops every frame to or from its MAC, which also covers its
// link-local address. DNS points at nothing, so Docker's resolver never
// forwards a lookup out; lab nodes find each other through /etc/hosts.
// /proc/sys/net becomes writable, so tests and thinkpol can set network
// sysctls in the node and its namespaces without the rest of /proc/sys.
// Last, the marker that lets the node's Command start.
func (l *Lab) configureNode(ctx context.Context, spec NodeSpec) error {
	n := l.nodes[spec.Name]
	res, err := n.Exec(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return err
	}
	var links []struct {
		Index   int    `json:"ifindex"`
		Name    string `json:"ifname"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &links); err != nil {
		return fmt.Errorf("ip -j link: %w", err)
	}
	n.ifaces = map[int]string{}
	n.ifnames = map[string]string{}
	for network, a := range n.addrs {
		for _, link := range links {
			if a.mac != "" && strings.EqualFold(link.Address, a.mac) {
				n.ifaces[link.Index] = network
				n.ifnames[network] = link.Name
			}
		}
	}

	var script strings.Builder
	script.WriteString("while ip -4 route del default 2>/dev/null; do :; done\n")
	script.WriteString("while ip -6 route del default 2>/dev/null; do :; done\n")
	for _, net := range spec.Networks {
		b, ifname := l.bridges[net], n.ifnames[net]
		if ifname == "" {
			return fmt.Errorf("no interface for network %s", net)
		}
		fmt.Fprintf(&script, "ip -4 route add blackhole %s/32\n", b.IPv4)
		if b.IPv6.IsValid() {
			fmt.Fprintf(&script, "ip -6 route add blackhole %s/128\n", b.IPv6)
		}
		fmt.Fprintf(&script, "nft -f - <<'EOF'\ntable netdev tplab_%[1]s {\n"+
			"  chain in { type filter hook ingress device %[1]q priority -500; ether saddr %[2]s drop; }\n"+
			"  chain out { type filter hook egress device %[1]q priority -500; ether daddr %[2]s drop; }\n"+
			"}\nEOF\n", ifname, b.MAC)
	}
	if spec.Gateway != "" {
		gw := l.Topology.Nodes[l.Topology.nodeIndex(spec.Gateway)]
		addr := l.nodes[gw.Name].addrs[sharedNetwork(spec, gw)]
		fmt.Fprintf(&script, "ip -4 route add default via %s\n", addr.IPv4)
		if addr.IPv6.IsValid() {
			fmt.Fprintf(&script, "ip -6 route add default via %s\n", addr.IPv6)
		}
	}
	script.WriteString("printf 'nameserver 127.0.0.1\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf\n")
	fmt.Fprintf(&script, "cat > /etc/hosts <<'EOF'\n%sEOF\n", l.hostsFor(spec))
	script.WriteString("mount --bind /proc/sys/net /proc/sys/net && mount -o remount,bind,rw /proc/sys/net\n")
	fmt.Fprintf(&script, "mkdir -p %s && touch %s\n", path.Dir(sealedMarker), sealedMarker)
	if spec.Systemd {
		// Kept for the node's next start, which runs it before systemd.
		fmt.Fprintf(&script, "mkdir -p %s && cat > %s <<'SEAL' && chmod 700 %[2]s\n#!/bin/sh\nset -e\n%sSEAL\n",
			path.Dir(sealScript), sealScript, script.String())
	}
	_, err = n.Exec(ctx, "sh", "-ec", script.String())
	return err
}

// checkSealed checks from inside a node that it is sealed as
// configureNode left it, for a node that sealed itself again on a restart
// rather than trusting Docker to give back what it had: its addresses the
// ones the lab knows (other nodes' /etc/hosts name them), each network's
// frame filter and blackholed bridge, and no default route but the
// gateway's.
func (l *Lab) checkSealed(ctx context.Context, n *Node) error {
	spec := l.Topology.Nodes[l.Topology.nodeIndex(n.Name)]
	var problems []string
	routes, err := n.Exec(ctx, "sh", "-c", "ip -4 route show; ip -6 route show")
	if err != nil {
		return err
	}
	for _, net := range spec.Networks {
		a, ifname, b := n.addrs[net], n.ifnames[net], l.bridges[net]
		// Each address on its own interface: the filters below are per
		// interface, so interfaces that swapped would leave them on the
		// wrong network.
		addrs, err := n.Exec(ctx, "ip", "-o", "addr", "show", "dev", ifname)
		if err != nil {
			return err
		}
		if !strings.Contains(addrs.Stdout, " "+a.IPv4.String()+"/") || a.IPv6.IsValid() && !strings.Contains(addrs.Stdout, " "+a.IPv6.String()+"/") {
			problems = append(problems, fmt.Sprintf("%s: %s is not at %s, %s any more", net, ifname, a.IPv4, a.IPv6))
		}
		if _, err := n.Exec(ctx, "nft", "list", "table", "netdev", "tplab_"+ifname); err != nil {
			problems = append(problems, fmt.Sprintf("%s: no frame filter tplab_%s", net, ifname))
		}
		for _, br := range []netip.Addr{b.IPv4, b.IPv6} {
			if br.IsValid() && !strings.Contains(routes.Stdout, "blackhole "+br.String()+" ") && !strings.Contains(routes.Stdout, "blackhole "+br.String()+"\n") {
				problems = append(problems, fmt.Sprintf("%s: the bridge %s isn't blackholed", net, br))
			}
		}
	}
	var want []string
	if spec.Gateway != "" {
		gw := l.Topology.Nodes[l.Topology.nodeIndex(spec.Gateway)]
		addr := l.nodes[gw.Name].addrs[sharedNetwork(spec, gw)]
		want = append(want, "default via "+addr.IPv4.String()+" ")
		if addr.IPv6.IsValid() {
			want = append(want, "default via "+addr.IPv6.String()+" ")
		}
	}
	for _, line := range strings.Split(routes.Stdout, "\n") {
		if !strings.HasPrefix(line, "default ") {
			continue
		}
		if !slices.ContainsFunc(want, func(w string) bool { return strings.HasPrefix(line, w) }) {
			problems = append(problems, "a default route that isn't the gateway's: "+line)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s: not sealed after its restart: %s", n.Name, strings.Join(problems, "; "))
	}
	return nil
}

// hostsFor is reader's /etc/hosts: every node by name, at its address on the
// first network it shares with reader, or else on its first network.
func (l *Lab) hostsFor(reader NodeSpec) string {
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	for _, other := range l.Topology.Nodes {
		net := sharedNetwork(other, reader)
		if net == "" {
			net = other.Networks[0]
		}
		a := l.nodes[other.Name].addrs[net]
		for _, ip := range []netip.Addr{a.IPv4, a.IPv6} {
			if ip.IsValid() {
				fmt.Fprintf(&b, "%s\t%s\n", ip, other.Name)
			}
		}
	}
	return b.String()
}
