package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KucherenkoIvan/go-kernel/config"
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
	// Interface names the overlay TUN.
	Interface string `env:"THINKPOL_INTERFACE" default:"thinkpol0"`
	// LinkMTU is the MTU of the network under the node's links.
	LinkMTU int `env:"THINKPOL_LINK_MTU" default:"1500"`
	// MapPoll is how often the map file is checked for a change; SIGHUP
	// checks it at once.
	MapPoll time.Duration `env:"THINKPOL_MAP_POLL" default:"5s"`
}

// LoadConfig reads the configuration from the environment, with the
// defaults above. Unlike go-kernel's usual setup it reads no .env files: a
// node's configuration is its environment and its flags.
func LoadConfig() (Config, error) {
	c, err := config.Load[Config](os.DevNull)
	if err != nil {
		return Config{}, err
	}
	return *c, nil
}

// MapPath is the map file's path.
func (c Config) MapPath() string {
	if c.MapFile != "" {
		return c.MapFile
	}
	return filepath.Join(c.StateDir, MapFile)
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
	if err := checkInterfaceName(c.Interface); err != nil {
		errs = append(errs, err)
	}
	// IPv6 needs 1280 on every link; below 576 + the overhead nothing fits.
	if c.LinkMTU < 576 || c.LinkMTU > 65535 {
		errs = append(errs, fmt.Errorf("link MTU %d: want 576 to 65535", c.LinkMTU))
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
