//go:build linux || darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// toolDirs are where the host's tools are looked up, never $PATH: install
// runs as root.
var toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// toolTimeout bounds one tool's run; stopping the agent can take its
// TimeoutStopSec (60 s) and launchd's ExitTimeOut (60 s).
const toolTimeout = 2 * time.Minute

// HostInstaller is the Installer for this host: its service manager, the
// running binary, the node's default state directory and the agent's
// runtime directories.
func HostInstaller(out io.Writer) (Installer, error) {
	exe, err := os.Executable()
	if err != nil {
		return Installer{}, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return Installer{}, err
	}
	return Installer{
		Root:        "/",
		System:      hostSystem(),
		Run:         runTool,
		Executable:  exe,
		Ready:       nodeReady,
		RuntimeDirs: []string{agent.HostLockDir(), filepath.Dir(agent.DefaultAPISocket())},
		Out:         out,
	}, nil
}

// CheckRoot refuses unless the process runs as root: the service is
// installed for the whole host.
func CheckRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("the service is the host's: run this as root (sudo)")
	}
	return nil
}

// InstallingUser is who ran sudo, to be added to the group: sudo's
// SUDO_USER, unless that is root.
func InstallingUser() string {
	if u := os.Getenv("SUDO_USER"); u != "root" {
		return u
	}
	return ""
}

// nodeReady checks the node's default state directory as `thinkpol up`
// would read it: without keys and a map the service would only restart.
func nodeReady() error {
	_, err := agent.LoadState(agent.DefaultStateDir, filepath.Join(agent.DefaultStateDir, agent.MapFileName))
	return err
}

func runTool(ctx context.Context, tool string, args ...string) (string, error) {
	path, err := findTool(tool)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + strings.Join(toolDirs, ":"), "LANG=C", "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", tool, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func findTool(name string) (string, error) {
	for _, dir := range toolDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", name, strings.Join(toolDirs, ", "))
}
