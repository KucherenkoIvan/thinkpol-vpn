package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

// plistDict reads a launchd plist's top-level dict as key → its value's
// element and text, the way launchd would see the keys: a test's own
// reader, so it doesn't share a bug with LaunchdPlist.
func plistDict(t *testing.T, data []byte) map[string]plistValue {
	t.Helper()
	var doc struct {
		XMLName xml.Name `xml:"plist"`
		Dict    struct {
			Items []struct {
				XMLName xml.Name
				Text    string       `xml:",chardata"`
				Items   []plistValue `xml:",any"`
			} `xml:",any"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("not XML: %v\n%s", err, data)
	}
	out := map[string]plistValue{}
	items := doc.Dict.Items
	if len(items)%2 != 0 {
		t.Fatalf("a key without a value:\n%s", data)
	}
	for i := 0; i < len(items); i += 2 {
		if items[i].XMLName.Local != "key" {
			t.Fatalf("%s where a key should be", items[i].XMLName.Local)
		}
		v := items[i+1]
		out[items[i].Text] = plistValue{XMLName: v.XMLName, Text: v.Text, Items: v.Items}
	}
	return out
}

// plistValue is one value: its element (string, true, array, ...), its
// text, and what it holds.
type plistValue struct {
	XMLName xml.Name
	Text    string       `xml:",chardata"`
	Items   []plistValue `xml:",any"`
}

func (v plistValue) strings() []string {
	var out []string
	for _, i := range v.Items {
		out = append(out, i.XMLName.Local+":"+i.Text)
	}
	return out
}

// trace is a device's crash trace file, with a character XML escapes.
const trace = "/var/lib/thinkpol/crash&trace"

// Both definitions run `up -service` and set nothing else: no
// environment, so connect-on-boot is only the device's. A device's sends
// the agent's stderr to its crash trace; a server's keeps no file.
func TestTheLaunchdPlistRunsTheAgentAndRestartsIt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		crashTrace string
	}{{"device", trace}, {"server", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			d := plistDict(t, LaunchdPlist(Definition{Binary: BinaryPath, CrashTrace: tc.crashTrace}))
			want := map[string]string{
				"Label": "string:" + Label, "RunAtLoad": "true:", "KeepAlive": "true:",
				"ThrottleInterval": "integer:5", "ExitTimeOut": "integer:60",
			}
			if tc.crashTrace != "" {
				want["StandardErrorPath"] = "string:" + tc.crashTrace
			}
			for k, w := range want {
				if got := d[k].XMLName.Local + ":" + strings.TrimSpace(d[k].Text); got != w {
					t.Errorf("%s: %s, want %s", k, got, w)
				}
			}
			if got := strings.Join(d["ProgramArguments"].strings(), " "); got != "string:"+BinaryPath+" string:up string:-service" {
				t.Errorf("ProgramArguments: %s", got)
			}
			if _, ok := d["EnvironmentVariables"]; ok {
				t.Error("EnvironmentVariables is set")
			}
			// The agent writes no log to disk (PRD S2): stdout goes
			// nowhere, stderr only to a device's crash trace.
			if _, ok := d["StandardOutPath"]; ok {
				t.Error("StandardOutPath is set")
			}
			if _, ok := d["StandardErrorPath"]; ok && tc.crashTrace == "" {
				t.Error("a server's StandardErrorPath is set")
			}
			if len(d) != len(want)+1 {
				t.Errorf("keys %v", d)
			}
		})
	}
}

func TestTheSystemdUnitRunsTheAgentAndRestartsIt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		crashTrace string
	}{{"device", trace}, {"server", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			unit := string(SystemdUnit(Definition{Binary: BinaryPath, CrashTrace: tc.crashTrace}))
			sections := map[string]map[string]string{}
			var cur map[string]string
			for _, l := range strings.Split(unit, "\n") {
				switch {
				case l == "" || strings.HasPrefix(l, "#"):
				case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
					cur = map[string]string{}
					sections[l] = cur
				default:
					k, v, ok := strings.Cut(l, "=")
					if !ok || cur == nil {
						t.Fatalf("line %q", l)
					}
					cur[k] = v
				}
			}
			want := map[string]map[string]string{
				"[Unit]":    {"StartLimitIntervalSec": "0"},
				"[Service]": {"ExecStart": BinaryPath + " up -service", "ExecReload": "/bin/kill -HUP $MAINPID", "Restart": "always", "RestartSec": "5", "KillMode": "mixed"},
				"[Install]": {"WantedBy": "multi-user.target"},
			}
			// Appended: truncate: would empty it before the agent reads the
			// previous run's trace.
			if tc.crashTrace != "" {
				want["[Service]"]["StandardError"] = "append:" + tc.crashTrace
			}
			for s, kv := range want {
				for k, v := range kv {
					if got := sections[s][k]; got != v {
						t.Errorf("%s %s=%q, want %q", s, k, got, v)
					}
				}
			}
			// The agent makes /run/thinkpol itself: systemd's would delete
			// the host lock's inode when the unit stops (package agent). A
			// server's stderr stays the journal (RR40), stdout everyone's.
			unset := []string{"RuntimeDirectory", "RuntimeDirectoryPreserve", "Environment", "EnvironmentFile", "StandardOutput"}
			if tc.crashTrace == "" {
				unset = append(unset, "StandardError")
			}
			for _, k := range unset {
				if _, ok := sections["[Service]"][k]; ok {
					t.Errorf("[Service] sets %s", k)
				}
			}
		})
	}
}
