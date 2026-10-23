//go:build darwin || linux

package safety

import (
	"runtime"
	"testing"
)

func TestOnlyListingsRunAsRoot(t *testing.T) {
	allowed := map[string][][]string{
		"darwin": {
			{"pfctl", "-s", "Interfaces", "-v"},
			{"pfctl", "-a", "com.apple", "-s", "Anchors"},
			{"pfctl", "-a", "com.apple/000.thinkpol", "-s", "rules", "-v"},
			{"pfctl", "-s", "References"},
			{"pfctl", "-a", "com.apple/000.thinkpol", "-t", "thinkpol_exempt6", "-T", "show"},
			{"scutil", "--dns"},
			{"netstat", "-rn", "-f", "inet6"},
			{"ifconfig", "en0"},
		},
		"linux": {{"ip", "route", "show", "table", "all"}, {"ip", "-6", "addr", "show"}},
	}
	refused := [][]string{
		{},
		{"pfctl", "-f", "/etc/pf.conf"},
		{"pfctl", "-e"},
		{"pfctl", "-d"},
		{"pfctl", "-F", "all"},
		{"pfctl", "-X", "123"},
		{"pfctl", "-a", "com.apple/000.thinkpol", "-F", "rules"},
		{"pfctl", "-s", "rules", "-f", "/tmp/x"},
		{"pfctl", "-s rules"},
		{"pfctl", "-a", "-f", "-s", "rules"},
		{"/sbin/pfctl", "-s", "rules"},
		{"scutil"},
		{"route", "-n", "delete", "default"},
		{"sh", "-c", "true"},
		{"ip", "route", "add", "192.0.2.0/24", "dev", "lo"},
		{"ip", "link", "set", "lo", "down"},
	}
	for _, argv := range allowed[runtime.GOOS] {
		if got, err := RootRead(argv); err != nil || got[0][0] != '/' {
			t.Errorf("%q refused: %v %v", argv, got, err)
		}
	}
	for _, argv := range refused {
		if got, err := RootRead(argv); err == nil {
			t.Errorf("%q allowed: %q", argv, got)
		}
	}
}
