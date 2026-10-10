package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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
	nodes    map[string]*Node
	gateways map[string][]netip.Addr // Docker's bridge addresses, by network
	release  func()                  // the host-wide lab slot
}

// Start brings up a lab for the test and tears it down when the test ends.
// When the test fails, the containers' logs go to the test log.
func Start(t testing.TB, topo Topology) *Lab {
	t.Helper()
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
	l, err := Up(ctx, root, project, topo)
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
		if res, err := docker(ctx, "compose", "-p", l.Project, "logs", "--no-color", "--timestamps"); err == nil {
			t.Logf("lab %s logs:\n%s", l.Project, res.Stdout)
		}
		if os.Getenv(KeepEnv) != "" {
			t.Logf("lab %s kept: docker compose -p %s exec <node> bash; make lab-down removes it", l.Project, l.Project)
			l.releaseSlot()
			return
		}
	}
	if err := l.Down(ctx); err != nil {
		t.Errorf("lab %s: tear down: %v", l.Project, err)
	}
}

// Up brings up a topology as the Compose project named project (which must
// start with ProjectPrefix), and returns once every node is running with its
// routes set. A lab left over under the same name is removed first. On error
// the returned Lab, if any, still needs Down.
func Up(ctx context.Context, root, project string, topo Topology) (*Lab, error) {
	if !strings.HasPrefix(project, ProjectPrefix) {
		return nil, fmt.Errorf("lab: project %q doesn't start with %q", project, ProjectPrefix)
	}
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	img, err := prepare(ctx, root)
	if err != nil {
		return nil, err
	}
	release, err := acquireSlot(ctx)
	if err != nil {
		return nil, err
	}
	l := &Lab{
		Project:  project,
		Topology: topo,
		root:     root,
		runDir:   filepath.Join(root, "lab", ".run", project),
		nodes:    map[string]*Node{},
		release:  release,
	}
	if err := downProject(ctx, project); err != nil {
		l.releaseSlot()
		return nil, err
	}
	if err := os.MkdirAll(l.runDir, 0o755); err != nil {
		l.releaseSlot()
		return nil, err
	}
	if err := l.create(ctx, img); err != nil {
		return l, err
	}
	if err := l.inspect(ctx); err != nil {
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
		file, err := renderCompose(l.Project, l.Topology, img, l.root, subnets)
		if err != nil {
			return err
		}
		if err := os.WriteFile(l.ComposeFile(), file, 0o644); err != nil {
			return err
		}
		_, err = docker(ctx, "compose", "-f", l.ComposeFile(), "-p", l.Project, "up", "-d", "--wait")
		if err == nil {
			return nil
		}
		if !isOverlap(err) || attempt == 5 {
			return fmt.Errorf("lab %s: up: %w", l.Project, err)
		}
		if err := downProject(ctx, l.Project); err != nil {
			return err
		}
	}
}

// ComposeFile is the generated Compose file, under lab/.run.
func (l *Lab) ComposeFile() string { return filepath.Join(l.runDir, "compose.json") }

// Down removes the lab's containers and networks.
func (l *Lab) Down(ctx context.Context) error {
	defer l.releaseSlot()
	if err := downProject(ctx, l.Project); err != nil {
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
	res, err := docker(ctx, "compose", "-p", l.Project, "ps", "-q")
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

// configureNode replaces what Docker set up to connect a container to the
// outside: the default routes go (a gateway node's take their place), the
// Docker bridges' own addresses become unroutable, and DNS points at
// nothing, so Docker's resolver never forwards a lookup out. Lab nodes find
// each other through /etc/hosts. /proc/sys/net becomes writable, so tests
// and thinkpol can set network sysctls in the node and its namespaces
// without the rest of /proc/sys.
func (l *Lab) configureNode(ctx context.Context, spec NodeSpec) error {
	n := l.nodes[spec.Name]
	var script strings.Builder
	script.WriteString("while ip -4 route del default 2>/dev/null; do :; done\n")
	script.WriteString("while ip -6 route del default 2>/dev/null; do :; done\n")
	for _, net := range spec.Networks {
		for _, gw := range l.gateways[net] {
			if gw.Is4() {
				fmt.Fprintf(&script, "ip -4 route add blackhole %s/32\n", gw)
			} else {
				fmt.Fprintf(&script, "ip -6 route add blackhole %s/128\n", gw)
			}
		}
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
	script.WriteString("ip -j link show\n")

	res, err := n.Exec(ctx, "sh", "-ec", script.String())
	if err != nil {
		return err
	}
	var links []struct {
		Index   int    `json:"ifindex"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &links); err != nil {
		return fmt.Errorf("ip -j link: %w", err)
	}
	n.ifaces = map[int]string{}
	for network, a := range n.addrs {
		for _, link := range links {
			if a.mac != "" && strings.EqualFold(link.Address, a.mac) {
				n.ifaces[link.Index] = network
			}
		}
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
