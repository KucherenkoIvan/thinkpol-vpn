package lab

import (
	"context"
	"encoding/json"
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
}

// Start brings up a lab for the test and tears it down when the test ends.
// When the test fails, the containers' logs go to the test log.
func Start(t testing.TB, topo Topology) *Lab {
	t.Helper()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	project := claimProject(testProject(CheckoutProject(root), cwd, t.Name()))
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
			t.Logf("lab %s kept: docker compose -p %s exec <node> sh; make lab-down removes it", l.Project, l.Project)
			return
		}
	}
	if err := l.Down(ctx); err != nil {
		t.Errorf("lab %s: tear down: %v", l.Project, err)
	}
}

// Up brings up a topology as the Compose project named project, and returns
// once every node is running with its routes set. On error the returned Lab,
// if any, still needs Down.
func Up(ctx context.Context, root, project string, topo Topology) (*Lab, error) {
	image, err := Prepare(ctx, root)
	if err != nil {
		return nil, err
	}
	file, err := renderCompose(project, topo, image, root)
	if err != nil {
		return nil, err
	}
	l := &Lab{
		Project:  project,
		Topology: topo,
		root:     root,
		runDir:   filepath.Join(root, "lab", ".run", project),
		nodes:    map[string]*Node{},
	}
	if err := os.MkdirAll(l.runDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(l.ComposeFile(), file, 0o644); err != nil {
		return nil, err
	}
	if _, err := docker(ctx, "compose", "-f", l.ComposeFile(), "-p", project, "up", "-d", "--wait"); err != nil {
		return l, fmt.Errorf("lab %s: up: %w", project, err)
	}
	if err := l.inspect(ctx); err != nil {
		return l, err
	}
	if err := l.configure(ctx); err != nil {
		return l, err
	}
	return l, nil
}

// ComposeFile is the generated Compose file, under lab/.run.
func (l *Lab) ComposeFile() string { return filepath.Join(l.runDir, "compose.json") }

// Down removes the lab's containers and networks.
func (l *Lab) Down(ctx context.Context) error {
	if err := downProject(ctx, l.Project); err != nil {
		return err
	}
	return os.RemoveAll(l.runDir)
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

// Nodes lists the lab's nodes by name.
func (l *Lab) Nodes() []*Node {
	out := make([]*Node, 0, len(l.nodes))
	for _, n := range l.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type inspected struct {
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

// inspect learns each node's container and its addresses on each network.
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
	var containers []inspected
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
	return nil
}

// configure replaces Docker's default routes: a node routes through its
// gateway or nowhere, so lab traffic never leaves the lab.
func (l *Lab) configure(ctx context.Context) error {
	var wg sync.WaitGroup
	errs := make(chan error, len(l.Topology.Nodes))
	for _, spec := range l.Topology.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.configureNode(ctx, spec); err != nil {
				errs <- fmt.Errorf("lab %s: node %s: %w", l.Project, spec.Name, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs
}

func (l *Lab) configureNode(ctx context.Context, spec NodeSpec) error {
	n := l.nodes[spec.Name]
	script := "while ip -4 route del default 2>/dev/null; do :; done\n" +
		"while ip -6 route del default 2>/dev/null; do :; done\n"
	if spec.Gateway != "" {
		gw := l.Topology.Nodes[l.Topology.nodeIndex(spec.Gateway)]
		addr := l.nodes[gw.Name].addrs[sharedNetwork(spec, gw)]
		script += "ip -4 route add default via " + addr.IPv4.String() + "\n"
		if addr.IPv6.IsValid() {
			script += "ip -6 route add default via " + addr.IPv6.String() + "\n"
		}
	}
	script += "ip -j link show\n"
	res, err := n.Exec(ctx, "sh", "-ec", script)
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

// downProject removes a Compose project's containers and networks. It works
// from the project name alone, so it also cleans up after a killed run.
func downProject(ctx context.Context, project string) error {
	_, err := docker(ctx, "compose", "-p", project, "down", "--volumes", "--remove-orphans", "--timeout", "0")
	return err
}

// DownCheckout removes every lab started from the checkout whose project
// prefix is checkout (see CheckoutProject), or with onlyTests just the labs
// tests and GoTest started. It returns the projects it removed.
func DownCheckout(ctx context.Context, root, checkout string, onlyTests bool) ([]string, error) {
	projects := map[string]bool{}
	for _, kind := range [][]string{
		{"ps", "-a"},
		{"network", "ls"},
	} {
		args := append(kind, "--filter", "label=com.docker.compose.project", "--format", `{{.Label "com.docker.compose.project"}}`)
		res, err := docker(ctx, args...)
		if err != nil {
			return nil, err
		}
		for _, p := range strings.Fields(res.Stdout) {
			if !belongsTo(p, checkout) {
				continue
			}
			if onlyTests && !strings.HasPrefix(p, checkout+"-t-") && p != GoTestProject(checkout) {
				continue
			}
			projects[p] = true
		}
	}
	var removed []string
	for p := range projects {
		if err := downProject(ctx, p); err != nil {
			return removed, err
		}
		_ = os.RemoveAll(filepath.Join(root, "lab", ".run", p))
		removed = append(removed, p)
	}
	sort.Strings(removed)
	return removed, nil
}
