package lab

import (
	"encoding/json"
	"net/netip"
)

// Paths inside every node.
const (
	// BinDir holds the run's binary directory (Prepare), read-only: the
	// cross-compiled thinkpol binary, the lab's tools and the test binaries
	// built by GoTest.
	BinDir = "/opt/thinkpol/bin"
	// SrcDir holds the checkout, read-only, so tests run by GoTest find their
	// testdata.
	SrcDir = "/src"
)

// Labels on every container and network of a lab. The harness tears down
// only projects whose every container and network carries LabelLab.
const (
	LabelLab  = "org.thinkpol.lab"      // "1"
	LabelRoot = "org.thinkpol.lab.root" // the checkout that started the lab
)

// The Compose file is generated as JSON, which Compose reads as YAML.
type composeFile struct {
	Name     string                    `json:"name"`
	Networks map[string]composeNetwork `json:"networks"`
	Services map[string]composeService `json:"services"`
}

type composeNetwork struct {
	EnableIPv6 bool              `json:"enable_ipv6"`
	Labels     map[string]string `json:"labels"`
	DriverOpts map[string]string `json:"driver_opts"`
	IPAM       composeIPAM       `json:"ipam"`
}

type composeIPAM struct {
	Config []composeSubnet `json:"config"`
}

type composeSubnet struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
}

// subnetConfig fixes the Docker bridge's address at the subnet's first one;
// Docker would pick the same but not report it.
func subnetConfig(p netip.Prefix) composeSubnet {
	return composeSubnet{Subnet: p.String(), Gateway: p.Addr().Next().String()}
}

type composeService struct {
	Image       string              `json:"image"`
	Platform    string              `json:"platform"`
	Hostname    string              `json:"hostname"`
	Init        bool                `json:"init"`
	Command     []string            `json:"command"`
	StopSignal  string              `json:"stop_signal,omitempty"`
	Tmpfs       []string            `json:"tmpfs,omitempty"`
	Cgroup      string              `json:"cgroup,omitempty"`
	Privileged  bool                `json:"privileged,omitempty"`
	CapAdd      []string            `json:"cap_add"`
	SecurityOpt []string            `json:"security_opt"`
	Devices     []string            `json:"devices"`
	Sysctls     map[string]string   `json:"sysctls,omitempty"`
	Environment map[string]string   `json:"environment"`
	Labels      map[string]string   `json:"labels"`
	Volumes     []string            `json:"volumes"`
	Networks    map[string]struct{} `json:"networks"`
}

// image is what renderCompose runs every node from.
type image struct {
	ref      string
	platform string // linux/<arch>[/<variant>]
}

// renderCompose turns a topology into a Compose file. root is the checkout,
// mounted read-only together with binDir, the binaries the lab runs. No container names: Compose
// names containers after the project. Subnets are the ones allocated for
// this lab.
func renderCompose(project string, topo Topology, img image, root, binDir string, subnets map[string]netSubnets) ([]byte, error) {
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	labels := map[string]string{LabelLab: "1", LabelRoot: root}
	f := composeFile{
		Name:     project,
		Networks: map[string]composeNetwork{},
		Services: map[string]composeService{},
	}
	for _, n := range topo.Networks {
		s := subnets[n.Name]
		ipam := composeIPAM{Config: []composeSubnet{subnetConfig(s.v4)}}
		if s.v6.IsValid() {
			ipam.Config = append(ipam.Config, subnetConfig(s.v6))
		}
		f.Networks[n.Name] = composeNetwork{
			EnableIPv6: !n.IPv4Only,
			Labels:     labels,
			// Docker would NAT whatever reaches the bridge out to the real
			// network; nodes have no route there anyway (see configureNode).
			DriverOpts: map[string]string{"com.docker.network.bridge.enable_ip_masquerade": "false"},
			IPAM:       ipam,
		}
	}
	for _, n := range topo.Nodes {
		env := map[string]string{
			"PATH":         BinDir + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"THINKPOL_LAB": "1",
			"LAB_NODE":     n.Name,
		}
		for k, v := range n.Env {
			env[k] = v
		}
		cmd := n.Command
		if len(cmd) == 0 {
			cmd = []string{"sleep", "infinity"}
		}
		// Nothing of the node's own runs before Up has sealed it.
		cmd = append([]string{"sh", "-c", `while [ ! -e ` + sealedMarker + ` ]; do sleep 0.1; done; exec "$@"`, "wait-for-seal"}, cmd...)
		if n.Systemd {
			cmd = systemdCommand
		}
		svc := composeService{
			Image:      img.ref,
			Platform:   img.platform,
			Hostname:   n.Name,
			Init:       !n.Systemd,
			Command:    cmd,
			Privileged: n.Privileged,
			// NET_ADMIN for links, routes and nftables, NET_RAW for ping and
			// tcpdump, SYS_ADMIN for network namespaces (mounts under
			// /run/netns) and the writable /proc/sys/net (see configureNode).
			CapAdd: []string{"NET_ADMIN", "NET_RAW", "SYS_ADMIN"},
			// Docker's AppArmor profile, where the host has AppArmor, denies
			// the mounts that network namespaces need, even with SYS_ADMIN.
			SecurityOpt: []string{"apparmor=unconfined"},
			Devices:     []string{"/dev/net/tun"},
			Environment: env,
			Labels:      labels,
			Volumes: []string{
				binDir + ":" + BinDir + ":ro",
				root + ":" + SrcDir + ":ro",
			},
			Networks: map[string]struct{}{},
		}
		if n.Systemd {
			// systemd halts on SIGRTMIN+3; /run is a tmpfs, as a host's is;
			// its own cgroup namespace, which the command makes writable.
			svc.StopSignal, svc.Tmpfs, svc.Cgroup = "SIGRTMIN+3", []string{"/run", "/run/lock"}, "private"
		}
		if n.Forward {
			svc.Sysctls = map[string]string{
				"net.ipv4.ip_forward":          "1",
				"net.ipv6.conf.all.forwarding": "1",
			}
		}
		for _, net := range n.Networks {
			svc.Networks[net] = struct{}{}
		}
		f.Services[n.Name] = svc
	}
	return json.MarshalIndent(f, "", "  ")
}

// sealScript, in a systemd node, is its sealing script (configureNode),
// kept for the node's next start: /run, where the marker is, is a tmpfs.
const sealScript = "/etc/lab/seal.sh"

// systemdCommand is a systemd node's main process: sealed again first
// when the node restarts (Node.Restart), else waiting for Up to seal it,
// then its cgroups made writable (Docker mounts them read-only in an
// unprivileged container) and systemd exec'd as PID 1. In a container
// systemd reads its arguments as the kernel's command line.
var systemdCommand = []string{"sh", "-c",
	`if [ -x ` + sealScript + ` ]; then ` + sealScript + ` || exit 1; fi; ` +
		`while [ ! -e ` + sealedMarker + ` ]; do sleep 0.1; done; ` +
		`mount -o remount,rw /sys/fs/cgroup || exit 1; exec "$@"`,
	"wait-for-seal", "/lib/systemd/systemd",
	"systemd.mask=systemd-resolved.service", "systemd.mask=systemd-networkd.service", "systemd.mask=nginx.service",
}
