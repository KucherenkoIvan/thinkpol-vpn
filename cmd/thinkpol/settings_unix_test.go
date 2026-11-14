//go:build unix

package main

import (
	"context"
	"regexp"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// settingNode is a device that keeps the kill switch and connect-on-boot
// it is set to.
type settingNode struct {
	exitNode
	mu sync.Mutex
}

func (n *settingNode) Status() agent.Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.st
}

func (n *settingNode) SetKillSwitch(_ context.Context, on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.st.KillSwitch.On, n.st.KillSwitch.Active = on, on
	return nil
}

func (n *settingNode) SetConnectOnBoot(on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.st.ConnectOnBoot = on
	return nil
}

// A setting is `<setting> [value]` (docs/design/api-overview.md,
// "Verdicts"): with no value the command prints the setting alone, with
// one it sets it and prints the status that shows it.
func TestASettingIsShownWithNoValueAndSetWithOne(t *testing.T) {
	node := &settingNode{exitNode: exitNode{st: connectedDevice(t).st}}
	node.st.KillSwitch.Enforced = true
	socket := serveStatus(t, node)
	for _, c := range []struct {
		setting    string
		shown      map[string]string // by value: what the bare command prints
		statusLine string            // the status's line, after the value
	}{
		{"kill-switch", map[string]string{"off": "kill-switch: off, allow-LAN off\n", "on": "kill-switch: on, allow-LAN off (in place)\n"}, `kill switch: +`},
		{"connect-on-boot", map[string]string{"off": "connect-on-boot: off\n", "on": "connect-on-boot: on\n"}, `connect-on-boot: +`},
	} {
		for _, value := range []string{"off", "on", "off"} {
			if code, stdout, stderr := runCLI(t, c.setting, "-socket", socket, value); code != exitOK || !regexp.MustCompile(`(?m)^`+c.statusLine+value+`\b`).MatchString(stdout) {
				t.Errorf("%s %s: exit %d\n%s%s", c.setting, value, code, stdout, stderr)
			}
			if code, stdout, stderr := runCLI(t, c.setting, "-socket", socket); code != exitOK || stdout != c.shown[value] {
				t.Errorf("%s after %s: exit %d, printed %q, want %q\n%s", c.setting, value, code, stdout, c.shown[value], stderr)
			}
		}
	}
}
