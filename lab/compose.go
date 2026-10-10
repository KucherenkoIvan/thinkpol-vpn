package lab

import (
	"encoding/json"
	"path/filepath"
)

// Paths inside every node.
const (
	// BinDir holds lab/bin, read-only: the cross-compiled thinkpol binary and
	// the test binaries built by GoTest.
	BinDir = "/opt/thinkpol/bin"
	// SrcDir holds the checkout, read-only, so tests run by GoTest find their
	// testdata.
	SrcDir = "/src"
)

// The Compose file is generated as JSON, which Compose reads as YAML.
type composeFile struct {
	Name     string                    `json:"name"`
	Networks map[string]composeNetwork `json:"networks"`
	Services map[string]composeService `json:"services"`
}

type composeNetwork struct {
	EnableIPv6 bool `json:"enable_ipv6"`
}

type composeService struct {
	Image       string              `json:"image"`
	Hostname    string              `json:"hostname"`
	Init        bool                `json:"init"`
	Command     []string            `json:"command"`
	Privileged  bool                `json:"privileged"`
	CapAdd      []string            `json:"cap_add"`
	Devices     []string            `json:"devices"`
	Sysctls     map[string]string   `json:"sysctls,omitempty"`
	Environment map[string]string   `json:"environment"`
	Volumes     []string            `json:"volumes"`
	Networks    map[string]struct{} `json:"networks"`
}

// renderCompose turns a topology into a Compose file. root is the checkout,
// mounted read-only together with its lab/bin. No container names and no
// subnets: Compose names containers after the project and Docker allocates
// the subnets, so two projects never collide.
func renderCompose(project string, topo Topology, image, root string) ([]byte, error) {
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	f := composeFile{
		Name:     project,
		Networks: map[string]composeNetwork{},
		Services: map[string]composeService{},
	}
	for _, n := range topo.Networks {
		f.Networks[n.Name] = composeNetwork{EnableIPv6: !n.IPv4Only}
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
		svc := composeService{
			Image:       image,
			Hostname:    n.Name,
			Init:        true,
			Command:     cmd,
			Privileged:  true,
			CapAdd:      []string{"NET_ADMIN"},
			Devices:     []string{"/dev/net/tun"},
			Environment: env,
			Volumes: []string{
				filepath.Join(root, "lab", "bin") + ":" + BinDir + ":ro",
				root + ":" + SrcDir + ":ro",
			},
			Networks: map[string]struct{}{},
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
