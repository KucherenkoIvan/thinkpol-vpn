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

// Config is what `thinkpol up` runs with: environment variables, which the
// command's flags override. The flag: and help: tags are the flags
// (config.BindFlags), so a setting is named in one place.
type Config struct {
	// StateDir holds the node's keys and its map (see LoadState).
	StateDir string `env:"THINKPOL_STATE_DIR" flag:"state" help:"state directory: node.key, space.pub and map.bin"`
	// MapFile is the map's path; empty means map.bin in StateDir.
	MapFile string `env:"THINKPOL_MAP" flag:"map" help:"the map file, if not map.bin in the state directory"`
	Mode    Mode   `env:"THINKPOL_MODE" default:"auto" flag:"mode" help:"auto (by the node's kind in the map), device or server"`
	// LogLevel is debug, info, warn or error. Logs go to stderr and an
	// in-memory ring, never to a file (PRD S2).
	LogLevel string `env:"THINKPOL_LOG_LEVEL" default:"info" flag:"log-level" help:"debug, info, warn or error; logs go to stderr only"`
	// Interface names the overlay TUN; empty is the platform's default
	// (tun.DefaultName).
	Interface string `env:"THINKPOL_INTERFACE" flag:"interface" help:"the overlay TUN's name; empty: the platform's default"`
	// LinkMTU is the MTU of the network under the node's links; 0 is
	// dataplane.DefaultLinkMTU.
	LinkMTU int `env:"THINKPOL_LINK_MTU" flag:"link-mtu" help:"MTU of the network under the links; 0: 1500"`
	// MapPoll is how often the map file is checked for a change; SIGHUP
	// checks it at once.
	MapPoll time.Duration `env:"THINKPOL_MAP_POLL" default:"5s" flag:"map-poll" help:"how often to check the map file for a change; SIGHUP checks at once"`
	// Connect brings a device's data plane up when the node starts;
	// otherwise it waits for the local API's Connect. A start in the same
	// boot as the last Connect or Disconnect follows that request instead
	// (ConnectRecord), so under a service this is connect-on-boot. A
	// server always serves its spaces.
	Connect bool `env:"THINKPOL_CONNECT" default:"true" flag:"connect" help:"a device connects when it starts (connect-on-boot), unless the last thinkpol connect or disconnect of this boot said otherwise; otherwise it waits for thinkpol connect"`
	// APISocket is the local API's Unix socket, in a directory of its own;
	// empty serves no local API.
	APISocket string `env:"THINKPOL_API_SOCKET" flag:"api-socket" help:"the local API's socket, in a directory of its own; empty: no local API"`
	// APIGroup is the group (a name or a gid) whose members may use the
	// local API besides root; if no such group exists, only root may.
	APIGroup string `env:"THINKPOL_API_GROUP" default:"thinkpol" flag:"api-group" help:"the group whose members may use the local API besides root"`
	// DNS runs the node's resolver (DESIGN.md "DNS is routing"): a
	// device's answers its overlay names and resolves the rest by its
	// rules, and the OS resolves through it while the device is
	// connected; an exit's is the resolver devices ask through the
	// tunnel.
	DNS bool `env:"THINKPOL_DNS" default:"true" flag:"dns" help:"run the node's resolver: a device's OS resolves through it while connected, an exit's serves devices through the tunnel"`
	// DNSUpstream is what the node's resolver asks, comma-separated IPs
	// (port 53) or IP:ports: a device's domestic resolver, an exit's
	// upstream. Empty: a device asks what the OS used, an exit the
	// public resolvers (Quad9, then Cloudflare).
	DNSUpstream string `env:"THINKPOL_DNS_UPSTREAM" flag:"dns-upstream" help:"what the resolver asks, IPs or IP:ports, comma-separated: a device's domestic resolver, an exit's upstream; empty: a device asks what the OS used, an exit the public resolvers (Quad9, then Cloudflare)"`
	// EgressAllowed are prefixes (comma-separated) an exit's spaces may
	// reach although they are private or provider networks, which egress
	// otherwise refuses (supervisor.Options.EgressAllowed): a network that
	// is this node's internet.
	EgressAllowed string `env:"THINKPOL_EGRESS_ALLOWED" flag:"egress-allowed" help:"comma-separated private prefixes an exit's spaces may still reach"`
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

// LoadConfig reads the configuration from the environment and the default:
// tags. Unlike go-kernel's usual setup it reads no .env files: a node's
// configuration is its environment and its flags. It doesn't validate, and
// StateDir and APISocket stay empty when unset: their defaults vary by OS
// (DefaultStateDir, DefaultAPISocket), which a tag can't.
func LoadConfig() (Config, error) {
	c, err := config.LoadWith[Config](config.WithoutEnvFiles(), config.DeferValidate())
	if err != nil {
		return Config{}, err
	}
	return *c, nil
}

// ApplyOSDefaults fills what the environment left unset (LoadConfig) with
// this OS's defaults: a config tag can't vary by OS. A variable set empty
// stays empty.
func ApplyOSDefaults(cfg *Config) {
	if _, ok := os.LookupEnv("THINKPOL_STATE_DIR"); !ok {
		cfg.StateDir = DefaultStateDir
	}
	if _, ok := os.LookupEnv("THINKPOL_API_SOCKET"); !ok {
		cfg.APISocket = DefaultAPISocket()
	}
}

// DefaultAPISocket is where the local API listens by default; empty where
// it has no socket yet (Windows: a named pipe, TP-047). On macOS not under
// /var/run, which is group-writable (root:daemon 0775) and so fails the
// API's parent check, and not under /var, a symlink: /private/var/db is
// root's alone all the way up. Not inside netcfg.StateDir either, which is
// 0700: the API group couldn't reach the socket.
func DefaultAPISocket() string {
	switch runtime.GOOS {
	case "windows":
		return ""
	case "darwin":
		return "/private/var/db/thinkpol-api/api.sock"
	}
	return "/run/thinkpol-api/api.sock"
}

// MapPath is the map file's path.
func (c Config) MapPath() string {
	if c.MapFile != "" {
		return c.MapFile
	}
	return filepath.Join(c.StateDir, MapFileName)
}

// Validate rejects a configuration `thinkpol up` can't run with. It is
// go-kernel config's validation hook (config.Validate).
func (c Config) Validate() error {
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
