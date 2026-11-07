package agent

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// NodeFile, in the state directory, is the operator's settings for this
// node (docs/design/configuration.md "Node level"): JSON, root's, 0600,
// written by hand or by provisioning, never by the agent. `thinkpol up`
// reads it at start (ApplyNodeFile); a setting given as a flag or in the
// environment wins over it. None is fine: every setting has its default.
const NodeFile = "node.json"

// nodeFileLimit bounds the file.
const nodeFileLimit = 64 << 10

// NodeSettings is NodeFile's keys: the node's operating settings, nothing
// about members or history (PRD S1). Each is a pointer, so a key left out
// is told from one set to its zero value. The flags and variables that
// say where the node's own files are and who may reach them (-state,
// -map, -api-socket, -api-group) or how it is run (-service, -connect)
// are not in it.
type NodeSettings struct {
	Mode          *Mode     `json:"mode"`
	Interface     *string   `json:"interface"`
	LinkMTU       *int      `json:"link_mtu"`
	LogLevel      *string   `json:"log_level"`
	MapPoll       *string   `json:"map_poll"`
	DNS           *bool     `json:"dns"`
	DNSUpstream   *[]string `json:"dns_upstream"`
	EgressAllowed *[]string `json:"egress_allowed"`
}

// ConfigError is a configuration `thinkpol up` can't run with: the node
// file's, or what the environment and the flags set. The command exits
// with EX_CONFIG (78).
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// ApplyNodeFile reads NodeFile in cfg.StateDir and takes each setting it
// holds that neither the environment (THINKPOL_*) nor a flag set: flags
// are `up`'s, parsed (config.BindFlags; nil: none given). A missing file
// changes nothing. A file that can't be read, isn't valid JSON, or holds an
// unknown key or a bad value is a *ConfigError naming the file and the key
// or the value, whichever source would have won: the file is the
// operator's, and a mistake in it is never passed over.
func ApplyNodeFile(cfg *Config, flags *flag.FlagSet) error {
	s, err := ReadNodeFile(cfg.StateDir)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	if flags != nil {
		flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	}
	given := func(field string) bool {
		f, ok := reflect.TypeFor[Config]().FieldByName(field)
		if !ok {
			panic("agent: no Config field " + field)
		}
		if _, ok := os.LookupEnv(f.Tag.Get("env")); ok {
			return true
		}
		return set[f.Tag.Get("flag")]
	}
	if s.Mode != nil && !given("Mode") {
		cfg.Mode = *s.Mode
	}
	if s.Interface != nil && !given("Interface") {
		cfg.Interface = *s.Interface
	}
	if s.LinkMTU != nil && !given("LinkMTU") {
		cfg.LinkMTU = *s.LinkMTU
	}
	if s.LogLevel != nil && !given("LogLevel") {
		cfg.LogLevel = *s.LogLevel
	}
	if s.MapPoll != nil && !given("MapPoll") {
		cfg.MapPoll, _ = time.ParseDuration(*s.MapPoll) // checked by ReadNodeFile
	}
	if s.DNS != nil && !given("DNS") {
		cfg.DNS = *s.DNS
	}
	if s.DNSUpstream != nil && !given("DNSUpstream") {
		cfg.DNSUpstream = strings.Join(*s.DNSUpstream, ",")
	}
	if s.EgressAllowed != nil && !given("EgressAllowed") {
		cfg.EgressAllowed = strings.Join(*s.EgressAllowed, ",")
	}
	return nil
}

// ReadNodeFile reads and checks NodeFile in dir: a regular file (no
// symlink) of the service's user (root), readable by no one else
// (checkNodeFileOwnerMode); none is no settings. Every error but a state
// directory that can't be opened is a *ConfigError naming the file.
func ReadNodeFile(dir string) (NodeSettings, error) {
	var s NodeSettings
	path := filepath.Join(dir, NodeFile)
	d, err := openTrustedDir(dir)
	if err != nil {
		return s, fmt.Errorf("state directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	data, fi, err := d.read(NodeFile, false, nodeFileLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, &ConfigError{err}
	}
	if uid, ok := fileOwner(fi); ok {
		if err := checkNodeFileOwnerMode(path, uid, os.Geteuid(), fi.Mode().Perm()); err != nil {
			return s, &ConfigError{err}
		}
	}
	if err := decodeSettings(data, &s); err != nil {
		return s, &ConfigError{fmt.Errorf("%s: %w", path, err)}
	}
	if err := s.check(); err != nil {
		return s, &ConfigError{fmt.Errorf("%s: %w", path, err)}
	}
	return s, nil
}

// checkNodeFileOwnerMode refuses a node file that isn't the agent's
// user's (euid: root, as the service runs) or that others may read:
// the operator's settings are root's alone, 0600. A non-root agent (a
// test) can't read a root file of 0600, so its own uid stands in for
// root.
func checkNodeFileOwnerMode(path string, uid, euid int, perm fs.FileMode) error {
	if uid != euid {
		want := "root's (chown root it)"
		if euid != 0 {
			want = fmt.Sprintf("uid %d's", euid)
		}
		return fmt.Errorf("%s: owned by uid %d: want %s", path, uid, want)
	}
	if perm&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o: want 0600 (chmod 600 it)", path, perm)
	}
	return nil
}

// check checks each value as Config.Validate would, naming its key.
func (s NodeSettings) check() error {
	var errs []error
	bad := func(key string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("key %q: %w", key, err))
		}
	}
	if s.Mode != nil {
		bad("mode", checkMode(*s.Mode))
	}
	if s.Interface != nil {
		bad("interface", checkInterfaceName(*s.Interface))
	}
	if s.LinkMTU != nil {
		bad("link_mtu", checkLinkMTU(*s.LinkMTU))
	}
	if s.LogLevel != nil {
		_, err := ParseLevel(*s.LogLevel)
		bad("log_level", err)
	}
	if s.MapPoll != nil {
		d, err := time.ParseDuration(*s.MapPoll)
		if err != nil {
			err = fmt.Errorf("%q: want a duration like 5s", *s.MapPoll)
		} else {
			err = checkMapPoll(d)
		}
		bad("map_poll", err)
	}
	if s.DNSUpstream != nil {
		for _, u := range *s.DNSUpstream {
			ups, err := ParseUpstreams(u)
			if err == nil && len(ups) != 1 {
				err = fmt.Errorf("DNS upstream %q: want one IP or IP:port per entry", u)
			}
			bad("dns_upstream", err)
		}
	}
	if s.EgressAllowed != nil {
		for _, p := range *s.EgressAllowed {
			got, err := Config{EgressAllowed: p}.EgressAllowedPrefixes()
			if err == nil && len(got) != 1 {
				err = fmt.Errorf("egress allowed %q: want one prefix per entry", p)
			}
			bad("egress_allowed", err)
		}
	}
	return errors.Join(errs...)
}
