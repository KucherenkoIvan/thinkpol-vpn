package lab

import (
	"fmt"
	"regexp"
	"slices"
)

// Topology is what a test asks the lab for: networks, and the nodes on them.
// Each test declares its own (usually Standard, maybe extended with With), so
// adding a node for one test never changes another test's lab.
type Topology struct {
	Networks []Network
	Nodes    []NodeSpec
}

// Network is a lab network. Docker picks its subnets: an IPv4 one and, unless
// IPv4Only, a unique-local IPv6 /64.
type Network struct {
	Name     string
	IPv4Only bool
}

// NodeSpec declares one container. Every node runs the lab image as root
// with NET_ADMIN, NET_RAW and SYS_ADMIN, /dev/net/tun, and the
// cross-compiled binaries (BinDir) on its PATH.
type NodeSpec struct {
	Name     string
	Networks []string // the topology networks the node is attached to
	// Gateway names the node that becomes this node's default route, over
	// IPv4 and IPv6, on the first network they share. Without a gateway the
	// node has no default route: the lab never reaches the real internet.
	Gateway string
	// Forward turns on IPv4 and IPv6 forwarding (routers, relays, exits).
	Forward bool
	// Privileged runs the node as a privileged container. Nodes don't need it
	// for namespaces, TUN, nftables or net sysctls; set it only for something
	// the default capabilities can't do, and say why next to it. A privileged
	// node can change the Docker VM's own kernel settings and devices.
	Privileged bool
	// Command is the container's main process; the default sleeps forever,
	// and tests start their own processes with Node.Start.
	Command []string
	Env     map[string]string
	// Systemd runs systemd as the node's PID 1 instead of Command, for
	// tests of a service under systemd. /run is a tmpfs, and the node
	// seals itself again when it starts after Node.Restart, before systemd
	// runs: a restart is a reboot but for the kernel's boot id, which is
	// the Docker VM's. systemd-resolved, systemd-networkd and nginx are
	// masked.
	Systemd bool
}

// Names used by Standard.
const (
	NetDevices = "devices"
	NetServers = "servers"

	Router   = "router"
	DeviceA  = "device-a"
	DeviceB  = "device-b"
	Server1  = "server-1"
	Server2  = "server-2"
	Internet = "internet"
)

// Standard is the usual lab: devices on one network, servers and the
// internet target on another, and a router joining the two. Everything a
// device sends to a server or the internet crosses the router, which is
// where packets are captured and where the censor sits.
func Standard() Topology {
	device := func(name string) NodeSpec {
		return NodeSpec{Name: name, Networks: []string{NetDevices}, Gateway: Router}
	}
	server := func(name string) NodeSpec {
		return NodeSpec{Name: name, Networks: []string{NetServers}, Gateway: Router, Forward: true}
	}
	return Topology{
		Networks: []Network{{Name: NetDevices}, {Name: NetServers}},
		Nodes: []NodeSpec{
			{Name: Router, Networks: []string{NetDevices, NetServers}, Forward: true},
			device(DeviceA),
			device(DeviceB),
			server(Server1),
			server(Server2),
			{Name: Internet, Networks: []string{NetServers}, Gateway: Router},
		},
	}
}

// Names used by Upstream.
const (
	NetWorld   = "world"
	Camouflage = "camouflage"
)

// Upstream is Standard with a camouflage target, the real site a
// disguised entry forwards unrecognized clients to, on a network of its
// own behind the router: an entry's connection to it crosses the router,
// where the censor sees it (TP-026's upstream tell), as a client's
// connection to the entry does.
func Upstream() Topology {
	t := Standard().WithNetworks(Network{Name: NetWorld})
	return t.With(
		NodeSpec{Name: Router, Networks: []string{NetDevices, NetServers, NetWorld}, Forward: true},
		NodeSpec{Name: Camouflage, Networks: []string{NetWorld}, Gateway: Router},
	)
}

// With returns a copy of the topology with nodes added, or replaced when a
// node of the same name exists.
func (t Topology) With(nodes ...NodeSpec) Topology {
	out := Topology{Networks: slices.Clone(t.Networks), Nodes: slices.Clone(t.Nodes)}
	for _, n := range nodes {
		if i := out.nodeIndex(n.Name); i >= 0 {
			out.Nodes[i] = n
		} else {
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out
}

// WithNetworks returns a copy of the topology with networks added.
func (t Topology) WithNetworks(networks ...Network) Topology {
	out := Topology{Networks: slices.Clone(t.Networks), Nodes: slices.Clone(t.Nodes)}
	out.Networks = append(out.Networks, networks...)
	return out
}

func (t Topology) nodeIndex(name string) int {
	return slices.IndexFunc(t.Nodes, func(n NodeSpec) bool { return n.Name == name })
}

// Compose service and network names, which also become DNS names.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Validate reports a topology the lab can't build.
func (t Topology) Validate() error {
	if len(t.Nodes) == 0 {
		return fmt.Errorf("lab topology: no nodes")
	}
	seen := map[string]bool{}
	for _, n := range t.Networks {
		if !namePattern.MatchString(n.Name) {
			return fmt.Errorf("lab topology: bad network name %q", n.Name)
		}
		if seen[n.Name] {
			return fmt.Errorf("lab topology: network %q declared twice", n.Name)
		}
		seen[n.Name] = true
	}
	nodes := map[string]NodeSpec{}
	for _, n := range t.Nodes {
		if !namePattern.MatchString(n.Name) {
			return fmt.Errorf("lab topology: bad node name %q", n.Name)
		}
		if _, dup := nodes[n.Name]; dup {
			return fmt.Errorf("lab topology: node %q declared twice", n.Name)
		}
		if len(n.Networks) == 0 {
			return fmt.Errorf("lab topology: node %q is on no network", n.Name)
		}
		if n.Systemd && len(n.Command) > 0 {
			return fmt.Errorf("lab topology: node %q runs systemd, which takes the place of its command", n.Name)
		}
		for _, net := range n.Networks {
			if !seen[net] {
				return fmt.Errorf("lab topology: node %q is on undeclared network %q", n.Name, net)
			}
		}
		nodes[n.Name] = n
	}
	for _, n := range t.Nodes {
		if n.Gateway == "" {
			continue
		}
		gw, ok := nodes[n.Gateway]
		if !ok {
			return fmt.Errorf("lab topology: node %q has unknown gateway %q", n.Name, n.Gateway)
		}
		if sharedNetwork(n, gw) == "" {
			return fmt.Errorf("lab topology: node %q shares no network with its gateway %q", n.Name, n.Gateway)
		}
	}
	return nil
}

// sharedNetwork is the first of n's networks that other is also on.
func sharedNetwork(n, other NodeSpec) string {
	for _, net := range n.Networks {
		if slices.Contains(other.Networks, net) {
			return net
		}
	}
	return ""
}
