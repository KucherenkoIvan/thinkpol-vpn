package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KucherenkoIvan/go-kernel/config"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
)

// Mode is how a node runs its data plane.
type Mode string

const (
	// ModeAuto runs a server node in ModeServer and a device in ModeDevice,
	// by the node's kind in its own section of the map.
	ModeAuto Mode = "auto"
	// ModeDevice runs one space's engine in-process, on the node's own TUN
	// and sockets.
	ModeDevice Mode = "device"
	// ModeServer runs a supervisor that owns the public listeners and one
	// sandboxed worker per space (DESIGN.md "Server agent").
	ModeServer Mode = "server"
)

// DefaultStateDir is where a node keeps its keys and its map, and nothing
// else (PRD S1).
const DefaultStateDir = "/var/lib/thinkpol"

// Config is what `thinkpol up` runs with: environment variables, which the
// command's flags override.
type Config struct {
	// StateDir holds the node's keys and its map (see LoadState).
	StateDir string `env:"THINKPOL_STATE_DIR" default:"/var/lib/thinkpol"`
	// MapFile is the map's path; empty means map.bin in StateDir.
	MapFile string `env:"THINKPOL_MAP"`
	Mode    Mode   `env:"THINKPOL_MODE" default:"auto"`
	// LogLevel is debug, info, warn or error. Logs go to stderr and an
	// in-memory ring, never to a file (PRD S2).
	LogLevel string `env:"THINKPOL_LOG_LEVEL" default:"info"`
	// Interface names the overlay TUN; empty is the platform's default
	// (tun.DefaultName).
	Interface string `env:"THINKPOL_INTERFACE"`
	// LinkMTU is the MTU of the network under the node's links; 0 is
	// dataplane.DefaultLinkMTU.
	LinkMTU int `env:"THINKPOL_LINK_MTU"`
	// MapPoll is how often the map file is checked for a change; SIGHUP
	// checks it at once.
	MapPoll time.Duration `env:"THINKPOL_MAP_POLL" default:"5s"`
	// Connect brings a device's data plane up when the node starts;
	// otherwise it waits for the local API's Connect. A server always
	// serves its spaces.
	Connect bool `env:"THINKPOL_CONNECT" default:"true"`
	// APISocket is the local API's Unix socket, in a directory of its own
	// (DefaultAPISocket when THINKPOL_API_SOCKET is unset); empty serves no
	// local API.
	APISocket string `env:"THINKPOL_API_SOCKET"`
	// APIGroup is the group (a name or a gid) whose members may use the
	// local API besides root; if no such group exists, only root may.
	APIGroup string `env:"THINKPOL_API_GROUP" default:"thinkpol"`
	// DNS runs the node's resolver (DESIGN.md "DNS is routing"): a
	// device's answers its overlay names and resolves the rest by its
	// rules, and the OS resolves through it while the device is
	// connected; an exit's is the resolver devices ask through the
	// tunnel.
	DNS bool `env:"THINKPOL_DNS" default:"true"`
	// DNSUpstream is what the node's resolver asks, comma-separated IPs
	// (port 53) or IP:ports: a device's domestic resolver, an exit's
	// upstream. Empty: the resolvers the OS used before.
	DNSUpstream string `env:"THINKPOL_DNS_UPSTREAM"`
	// EgressAllowed are prefixes (comma-separated) an exit's spaces may
	// reach although they are private or provider networks, which egress
	// otherwise refuses (supervisor.Options.EgressAllowed): a network that
	// is this node's internet.
	EgressAllowed string `env:"THINKPOL_EGRESS_ALLOWED"`
}

// EgressAllowedPrefixes parses EgressAllowed.
func (c Config) EgressAllowedPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(c.EgressAllowed, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, fmt.Errorf("egress allowed %q: want IPv4 or IPv6 prefixes like 203.0.113.0/24", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// LoadConfig reads the configuration from the environment, with the
// defaults above. Unlike go-kernel's usual setup it reads no .env files: a
// node's configuration is its environment and its flags.
func LoadConfig() (Config, error) {
	c, err := config.Load[Config](os.DevNull)
	if err != nil {
		return Config{}, err
	}
	c.APISocket = APISocket()
	return *c, nil
}

// DefaultAPISocket is where the local API listens by default; empty where
// it has no socket yet (Windows: a named pipe, TP-047). On macOS not under
// /var/run, which is group-writable (root:daemon 0775) and so fails the
// API's parent check: /var/db is root's alone all the way up.
func DefaultAPISocket() string {
	switch runtime.GOOS {
	case "windows":
		return ""
	case "darwin":
		return "/var/db/thinkpol-api/api.sock"
	}
	return "/run/thinkpol-api/api.sock"
}

// APISocket is the local API's socket: THINKPOL_API_SOCKET if set (empty
// for none), else DefaultAPISocket.
func APISocket() string {
	if p, ok := os.LookupEnv("THINKPOL_API_SOCKET"); ok {
		return p
	}
	return DefaultAPISocket()
}

// MapPath is the map file's path.
func (c Config) MapPath() string {
	if c.MapFile != "" {
		return c.MapFile
	}
	return filepath.Join(c.StateDir, MapFileName)
}

// Check rejects a configuration `thinkpol up` can't run with.
func (c Config) Check() error {
	var errs []error
	if c.StateDir == "" {
		errs = append(errs, errors.New("no state directory"))
	}
	switch c.Mode {
	case ModeAuto, ModeDevice, ModeServer:
	default:
		errs = append(errs, fmt.Errorf("mode %q: want %s, %s or %s", c.Mode, ModeAuto, ModeDevice, ModeServer))
	}
	if _, err := ParseLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	if c.Interface != "" {
		if err := checkInterfaceName(c.Interface); err != nil {
			errs = append(errs, err)
		}
	}
	// Below 576 plus a link's overhead nothing fits.
	if c.LinkMTU != 0 && (c.LinkMTU < 576 || c.LinkMTU > 65535) {
		errs = append(errs, fmt.Errorf("link MTU %d: want 576 to 65535, or 0 for the default", c.LinkMTU))
	}
	if c.Mode == ModeDevice && !c.Connect && c.APISocket == "" {
		errs = append(errs, errors.New("a device that starts disconnected needs the local API to connect: set an API socket"))
	}
	if c.APISocket != "" && !filepath.IsAbs(c.APISocket) {
		errs = append(errs, fmt.Errorf("API socket %q: want an absolute path", c.APISocket))
	}
	if _, err := c.EgressAllowedPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if _, err := ParseUpstreams(c.DNSUpstream); err != nil {
		errs = append(errs, err)
	}
	if c.MapPoll < 100*time.Millisecond {
		errs = append(errs, fmt.Errorf("map poll interval %v: want at least 100ms", c.MapPoll))
	}
	return errors.Join(errs...)
}

// checkInterfaceName accepts what Linux takes as a link name: 1 to 15
// bytes, no '/', ':' or whitespace.
func checkInterfaceName(name string) error {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return fmt.Errorf("interface name %q: want 1 to 15 characters", name)
	}
	for _, r := range name {
		if r <= ' ' || r == '/' || r == ':' || r > '~' {
			return fmt.Errorf("interface name %q: only printable ASCII without '/', ':' or spaces", name)
		}
	}
	return nil
}

// ParseUpstreams reads DNS upstreams: comma-separated IPs (port 53) or
// IP:ports.
func ParseUpstreams(s string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if a, err := netip.ParseAddr(f); err == nil && a.Zone() == "" {
			out = append(out, netip.AddrPortFrom(a.Unmap(), dns.Port))
			continue
		}
		ap, err := netip.ParseAddrPort(f)
		if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
			return nil, fmt.Errorf("DNS upstream %q: want an IP or IP:port", f)
		}
		out = append(out, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	return out, nil
}
