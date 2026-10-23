//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/evidence"
)

// privateConfigPath is the private config file: -config, else
// $THINKPOL_DEVICETEST_CONFIG, else thinkpol-devicetest/config.yaml in
// the user's config directory. It names the exit server, so it lives
// outside every repository.
func privateConfigPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if p := os.Getenv("THINKPOL_DEVICETEST_CONFIG"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "thinkpol-devicetest", "config.yaml"), nil
}

// loadPrivateConfig reads the private config file, read only by plans
// that need the exit server: refused unless it is a regular file of this
// user's, mode 0600, outside every git checkout.
func loadPrivateConfig(flag string) ([]byte, error) {
	path, err := privateConfigPath(flag)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateConfig(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func checkPrivateConfig(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s: not a regular file", path)
	case !ok || int(st.Uid) != os.Getuid():
		return fmt.Errorf("%s: not yours", path)
	case fi.Mode().Perm() != 0o600:
		return fmt.Errorf("%s: mode %04o, want 0600 (it names the exit server)", path, fi.Mode().Perm())
	}
	if repo := evidence.GitCheckout(filepath.Dir(path)); repo != "" {
		return fmt.Errorf("%s is inside the git checkout %s: private config never goes into one", path, repo)
	}
	return nil
}
