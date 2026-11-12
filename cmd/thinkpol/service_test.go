package main

import (
	"strings"
	"testing"
)

// connect-on-boot is the device's setting now: the service's command and
// install's flag say what replaced them, before anything looks at the host.
func TestTheServicesConnectOnBootSaysWhatReplacedIt(t *testing.T) {
	for _, args := range [][]string{
		{"service", "install", "-connect-on-boot", "on"},
		{"service", "connect-on-boot"},
		{"service", "connect-on-boot", "on"},
	} {
		code, _, stderr := runCLI(t, args...)
		if code != 1 || !strings.Contains(stderr, "thinkpol connect-on-boot [on|off]") {
			t.Errorf("%v: exit %d\n%s", args, code, stderr)
		}
	}
}

// The member's connect-on-boot takes on or off, nothing else, before the
// local API is dialed.
func TestConnectOnBootIsOnOrOff(t *testing.T) {
	for _, cmd := range []string{"connect-on-boot", "kill-switch", "allow-lan"} {
		for _, values := range [][]string{{"yes"}, {"true"}, {"on", "off"}} {
			args := append([]string{cmd, "-socket", "/nonexistent/api.sock"}, values...)
			code, _, stderr := runCLI(t, args...)
			if code != 2 || !strings.Contains(stderr, "[on|off]") {
				t.Errorf("%v: exit %d\n%s", args, code, stderr)
			}
		}
	}
}
