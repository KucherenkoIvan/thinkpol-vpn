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
	// ModeDevice, the default, runs one space's engine in-process, on
	// the node's own TUN and sockets.
	ModeDevice Mode = "device"
	// ModeServer runs a supervisor that owns the public listeners and one
	// sandboxed worker per space (docs/design/server-agent.md "Server agent").
	ModeServer Mode = "server"
)

// Config is what `thinkpol up` runs with: the flags, then the environment,
// then the node file (ApplyNodeFile), then the defaults. The flag: and
// help: tags are the flags (config.BindFlags), so a setting is named in
// one place.
type Config struct {
	// StateDir holds the node's keys and its map (see LoadState).
	StateDir string `env:"THINKPOL_STATE_DIR" flag:"state" help:"state directory: node.key, space.pub and map.bin"`
	// MapFile is the map's path; empty means map.bin in StateDir.
	MapFile string `env:"THINKPOL_MAP" flag:"map" help:"the map file, if not map.bin in the state directory"`
	// Mode is the node's own: the map's node kind never picks it (PRD
	// A4: a node forwards nothing unless its operator runs it as a
	// server).
	Mode Mode `env:"THINKPOL_MODE" default:"device" flag:"mode" help:"device (forwards nothing) or server"`
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
	// otherwise it waits for the local API's Connect. Not read with
	// Service. A server always serves its spaces.
	Connect bool `env:"THINKPOL_CONNECT" default:"true" flag:"connect" help:"a device connects when it starts; otherwise it waits for thinkpol connect (not read with -service)"`
	// Service is set by the service's definition: the device keeps its
	// connect choice for the boot (ConnectRecord), and the device's
	// connect-on-boot (DeviceFile, a member's toggle) decides the boot's
	// first start. It needs the local API, without which nothing could
	// change the choice.
	Service bool `env:"THINKPOL_SERVICE" flag:"service" help:"run as the host's service: the device's connect-on-boot decides a boot's first start, a later start in the same boot comes back as the device was left"`
	// APISocket is the local API's Unix socket, in a directory of its own;
	// empty serves no local API.
	APISocket string `env:"THINKPOL_API_SOCKET" flag:"api-socket" help:"the local API's socket, in a directory of its own; empty: no local API"`
	// APIGroup is the group (a name or a gid) whose members may use the
	// local API besides root; if no such group exists, only root may.
	APIGroup string `env:"THINKPOL_API_GROUP" default:"thinkpol" flag:"api-group" help:"the group whose members may use the local API besides root"`
	// DNS runs the node's resolver (docs/design/routing.md "DNS is routing"): a
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
// tags. Unlike go-kernel's usual setup it reads no .env files: the node's
// own file is NodeFile, which ApplyNodeFile reads once the flags are
// parsed, since -state says where it is. It doesn't validate, and
// StateDir and APISocket stay empty when unset: their defaults vary by OS
// (DefaultStateDir, DefaultAPISocket), which a tag can't.
//
// A value that doesn't parse (THINKPOL_LINK_MTU=abc) is a *ConfigError,
// as Validate's are.
func LoadConfig() (Config, error) {
	c, err := config.LoadWith[Config](config.WithoutEnvFiles(), config.DeferValidate())
	if err != nil {
		return Config{}, &ConfigError{err}
	}
	return *c, nil
}

// oldConnectOnBootVariable is what service definitions set before
// connect-on-boot moved to DeviceFile.
const oldConnectOnBootVariable = "THINKPOL_CONNECT_ON_BOOT"

// CheckEnvironment refuses, as a *ConfigError, an environment only an
// older service definition sets: such a definition runs `up` without
// -service, and -connect's default would connect at every start, a
// member's disconnect undone by the next restart (PRD D5).
func CheckEnvironment() error {
	if _, ok := os.LookupEnv(oldConnectOnBootVariable); ok {
		return &ConfigError{fmt.Errorf("%s is set: the service's definition is older than this binary; run thinkpol service install to replace it (connect-on-boot is now thinkpol connect-on-boot on|off)", oldConnectOnBootVariable)}
	}
	return nil
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

// Validate rejects a configuration `thinkpol up` can't run with, as a
// *ConfigError. It is go-kernel config's validation hook (config.Validate).
func (c Config) Validate() error {
	var errs []error
	if c.StateDir == "" {
		errs = append(errs, errors.New("no state directory"))
	}
	errs = append(errs, checkMode(c.Mode))
	if _, err := ParseLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	if c.Interface != "" {
		errs = append(errs, checkInterfaceName(c.Interface))
	}
	errs = append(errs, checkLinkMTU(c.LinkMTU))
	if c.Service && c.APISocket == "" {
		errs = append(errs, errors.New("the service keeps the device's connect choice, which only the local API changes: set an API socket"))
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
	errs = append(errs, checkMapPoll(c.MapPoll))
	if err := errors.Join(errs...); err != nil {
		return &ConfigError{err}
	}
	return nil
}

func checkMode(m Mode) error {
	switch m {
	case ModeDevice, ModeServer:
		return nil
	case "auto":
		return fmt.Errorf("mode %q is gone: want %s or %s (a server sets %s)", m, ModeDevice, ModeServer, ModeServer)
	}
	return fmt.Errorf("mode %q: want %s or %s", m, ModeDevice, ModeServer)
}

// checkLinkMTU: below 576 plus a link's overhead nothing fits.
func checkLinkMTU(mtu int) error {
	if mtu != 0 && (mtu < 576 || mtu > 65535) {
		return fmt.Errorf("link MTU %d: want 576 to 65535, or 0 for the default", mtu)
	}
	return nil
}

func checkMapPoll(d time.Duration) error {
	if d < 100*time.Millisecond {
		return fmt.Errorf("map poll interval %v: want at least 100ms", d)
	}
	return nil
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
