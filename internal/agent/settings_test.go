package agent

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/go-kernel/config"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
)

// unsetTHINKPOL hides the developer's exported THINKPOL_ variables from
// the test: t.Setenv restores each one at cleanup.
func unsetTHINKPOL(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "THINKPOL_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
}

// settingsDir is a state directory of the right modes holding only file
// (nil: none) as name.
func settingsDir(t *testing.T, name string, file []byte) string {
	t.Helper()
	dir := filepath.Join(tempDir(t), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if file != nil {
		writeFile(t, filepath.Join(dir, name), file, 0o600)
	}
	return dir
}

// The node file is JSON, read strictly: anything but one object of known
// keys with values of the right type and range is refused, naming the key
// or the value, as a ConfigError (up's exit 78).
func TestTheNodeFileIsStrictJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string // "-": no file
		want string // the error names this; "": accepted
	}{
		{"no file", "-", ""},
		{"no settings", "{}", ""},
		{"every key", `{"mode": "device", "interface": "tp0", "link_mtu": 1400, "log_level": "debug", "map_poll": "2s",
			"dns": false, "dns_upstream": ["192.0.2.53", "[2001:db8::53]:5353"], "egress_allowed": ["10.0.0.0/8"]}`, ""},
		{"empty file", "", "empty: write {}"},
		{"blank file", " \n\t\n", "empty: write {}"},
		{"invalid JSON", `{"mode": }`, "invalid JSON at byte 9"},
		{"a trailing comma", `{"mode": "device",}`, "invalid JSON"},
		{"cut short", `{"mode": "device"`, "invalid JSON"},
		{"not an object", `["mode"]`, "want a JSON object"},
		{"null", `null`, "want a JSON object"},
		{"two objects", `{} {}`, "more after the object"},
		{"a duplicate key", `{"mode": "device", "link_mtu": 1400, "mode": "server"}`, `key "mode" given twice`},
		{"an unknown key", `{"link_mut": 1400}`, `unknown key "link_mut"`},
		{"a key of another case", `{"Mode": "device"}`, `unknown key "Mode"`},
		{"a number as a string", `{"link_mtu": "1400"}`, `key "link_mtu": want a whole number, not string`},
		{"a fraction", `{"link_mtu": 1400.5}`, `key "link_mtu": want a whole number, not number 1400.5`},
		{"a string as a bool", `{"dns": "on"}`, `key "dns": want true or false, not string`},
		{"a string for a list", `{"dns_upstream": "192.0.2.53"}`, `key "dns_upstream": want a list, not string`},
		{"a number in a list", `{"egress_allowed": [10]}`, `want a string, not number`},
		{"a bad mode", `{"mode": "exit"}`, `key "mode": mode "exit"`},
		{"a bad interface", `{"interface": "a/b"}`, `key "interface": interface name "a/b"`},
		{"a link MTU too small", `{"link_mtu": 100}`, `key "link_mtu": link MTU 100`},
		{"a bad log level", `{"log_level": "loud"}`, `key "log_level"`},
		{"a bad duration", `{"map_poll": "5"}`, `key "map_poll": "5": want a duration`},
		{"a map poll too short", `{"map_poll": "1ms"}`, `key "map_poll": map poll interval 1ms`},
		{"a bad upstream", `{"dns_upstream": ["resolver.example.net"]}`, `key "dns_upstream": DNS upstream "resolver.example.net"`},
		{"two upstreams in one entry", `{"dns_upstream": ["192.0.2.53,192.0.2.54"]}`, `want one IP or IP:port per entry`},
		{"a bad prefix", `{"egress_allowed": ["10.0.0.0/33"]}`, `key "egress_allowed": egress allowed "10.0.0.0/33"`},
	} {
		var file []byte
		if tc.file != "-" {
			file = []byte(tc.file)
		}
		dir := settingsDir(t, NodeFile, file)
		_, err := ReadNodeFile(dir)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), filepath.Join(dir, NodeFile)) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
		if !errors.As(err, new(*ConfigError)) {
			t.Errorf("%s: %v is no ConfigError", tc.name, err)
		}
	}
}

// Keys are checked at every depth (TP-111's ceiling and TP-048's toggles
// will nest): exactly, and once per object.
func TestSettingsKeysAreCheckedAtEveryDepth(t *testing.T) {
	type nested struct {
		A *struct {
			B *int `json:"b"`
		} `json:"a"`
		L []struct {
			C int `json:"c"`
		} `json:"l"`
	}
	for file, want := range map[string]string{
		`{"a": {"b": 1}, "l": [{"c": 1}, {"c": 2}]}`: "",
		`{"a": {"b": 1, "b": 2}}`:                    `key "b" given twice`,
		`{"a": {"B": 1}}`:                            `unknown key "B"`,
		`{"l": [{"c": 1}, {"C": 2}]}`:                `unknown key "C"`,
		`{"l": [{"c": 1, "c": 2}]}`:                  `key "c" given twice`,
		`{"a": {"b": "1"}}`:                          `key "a.b": want a whole number, not string`,
	} {
		var v nested
		err := decodeSettings([]byte(file), &v)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: got %v, want %q", file, err, want)
		}
	}
}

// A node file others could change is refused like the state directory's
// other files.
func TestANodeFileOthersCanChangeIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owners and modes are TP-047's on Windows")
	}
	dir := settingsDir(t, NodeFile, []byte(`{}`))
	if err := os.Chmod(filepath.Join(dir, NodeFile), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNodeFile(dir); err == nil || !strings.Contains(err.Error(), "lets others change it") {
		t.Fatalf("got %v", err)
	}
}

// Precedence: a setting given as a flag wins over the environment, which
// wins over the node file, which wins over the default. The settings come
// together as `up` puts them together: LoadConfig, the flags bound over
// it and parsed, then ApplyNodeFile.
func TestNodeSettingsPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		file  string
		env   map[string]string
		args  []string
		check func(Config) bool
	}{
		{"the default", `{}`, nil, nil,
			func(c Config) bool {
				return c.LinkMTU == 0 && c.Mode == ModeAuto && c.DNS && c.MapPoll == 5*time.Second
			}},
		{"the file over the default", `{"link_mtu": 1400, "mode": "device", "dns": false, "map_poll": "2s"}`, nil, nil,
			func(c Config) bool {
				return c.LinkMTU == 1400 && c.Mode == ModeDevice && !c.DNS && c.MapPoll == 2*time.Second
			}},
		{"the environment over the file", `{"link_mtu": 1400, "mode": "device"}`, map[string]string{"THINKPOL_LINK_MTU": "1300"}, nil,
			func(c Config) bool { return c.LinkMTU == 1300 && c.Mode == ModeDevice }},
		{"the environment over the default", `{}`, map[string]string{"THINKPOL_LINK_MTU": "1300"}, nil,
			func(c Config) bool { return c.LinkMTU == 1300 }},
		{"a flag over the environment and the file", `{"link_mtu": 1400}`, map[string]string{"THINKPOL_LINK_MTU": "1300"}, []string{"-link-mtu", "1200"},
			func(c Config) bool { return c.LinkMTU == 1200 }},
		{"a flag over the file", `{"link_mtu": 1400, "mode": "server"}`, nil, []string{"-link-mtu", "1200"},
			func(c Config) bool { return c.LinkMTU == 1200 && c.Mode == ModeServer }},
		{"a flag given its default still wins", `{"dns": false}`, nil, []string{"-dns=true"},
			func(c Config) bool { return c.DNS }},
		{"a variable set empty still wins", `{"dns_upstream": ["192.0.2.53"]}`, map[string]string{"THINKPOL_DNS_UPSTREAM": ""}, nil,
			func(c Config) bool { return c.DNSUpstream == "" }},
		{"lists", `{"dns_upstream": ["192.0.2.53", "192.0.2.54:5353"], "egress_allowed": ["10.0.0.0/8", "2001:db8::/32"]}`, nil, nil,
			func(c Config) bool {
				return c.DNSUpstream == "192.0.2.53,192.0.2.54:5353" && c.EgressAllowed == "10.0.0.0/8,2001:db8::/32"
			}},
		{"a list from the environment", `{"dns_upstream": ["192.0.2.53"]}`, map[string]string{"THINKPOL_DNS_UPSTREAM": "192.0.2.1"}, nil,
			func(c Config) bool { return c.DNSUpstream == "192.0.2.1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsetTHINKPOL(t)
			dir := settingsDir(t, NodeFile, []byte(tc.file))
			t.Setenv("THINKPOL_STATE_DIR", dir)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			ApplyOSDefaults(&cfg)
			fs := flag.NewFlagSet("up", flag.ContinueOnError)
			if err := config.BindFlags(fs, &cfg); err != nil {
				t.Fatal(err)
			}
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if err := ApplyNodeFile(&cfg, fs); err != nil {
				t.Fatal(err)
			}
			if !tc.check(cfg) {
				t.Fatalf("got %+v", cfg)
			}
		})
	}
}

// The device file is JSON, read as strictly as the node file, and one that
// can't be read stops the node from starting rather than reading as none.
func TestTheDeviceFileIsStrictJSON(t *testing.T) {
	s := newTestSpace(t)
	for _, tc := range []struct {
		name string
		file string
		want string // "": accepted
	}{
		{"no settings", `{}`, ""},
		{"every key", `{"connect_on_boot": true, "rule_preset": "all-but-domestic", "rules": ["cidr:192.0.2.0/24 -> direct"]}`, ""},
		{"empty file", ``, "empty"},
		{"invalid JSON", `{"connect_on_boot": tru}`, "invalid JSON"},
		{"a duplicate key", `{"connect_on_boot": true, "connect_on_boot": false}`, `key "connect_on_boot" given twice`},
		{"an unknown key", `{"kill_switch": true}`, `unknown key "kill_switch"`},
		{"on for true", `{"connect_on_boot": "on"}`, `key "connect_on_boot": want true or false, not string`},
		{"a bad preset", `{"rule_preset": "sometimes"}`, `key "rule_preset"`},
		{"a bad rule", `{"rules": ["nonsense"]}`, `key "rules", rule 1`},
	} {
		dir := s.stateDir(t, s.b, 1)
		writeFile(t, filepath.Join(dir, DeviceFile), []byte(tc.file), 0o600)
		n, err := Prepare(testConfig(dir), Logs{}, testPlatform())
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), DeviceFile) || !errors.As(err, new(*ConfigError)) {
			t.Errorf("%s: got %v (node %v), want %q", tc.name, err, n != nil, tc.want)
		}
	}
}

// What the service writes, it reads back the same.
func TestTheDeviceFileReadsBackWhatIsWritten(t *testing.T) {
	var l rules.Local
	if err := l.UnmarshalText([]byte("preset everything\ncidr:192.0.2.0/24 -> direct\ndomain:example.net -> block\n")); err != nil {
		t.Fatal(err)
	}
	for _, s := range []DeviceSettings{{}, {ConnectOnBoot: true, Rules: l}} {
		data, err := s.marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseDeviceSettings(data)
		if err != nil {
			t.Fatalf("%v\n%s", err, data)
		}
		// A person reading the file sees a rule as `status` shows it.
		if len(s.Rules.Rules) > 0 && !bytes.Contains(data, []byte(`"cidr:192.0.2.0/24 -> direct"`)) {
			t.Fatalf("the rule isn't written as is:\n%s", data)
		}
		a, _ := got.Rules.MarshalText()
		b, _ := s.Rules.MarshalText()
		if got.ConnectOnBoot != s.ConnectOnBoot || !bytes.Equal(a, b) {
			t.Fatalf("wrote %+v, read %+v\n%s", s, got, data)
		}
	}
}

// A state directory with rules.local and no device file starts with the
// same preset and own rules; the start writes them into the device file
// (0600) and removes rules.local, and says so. One that holds both (a
// start that stopped between the two) keeps the device file.
func TestRulesLocalIsCarriedOverIntoTheDeviceFile(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, LocalRulesFile), []byte("preset everything\ncidr:192.0.2.0/24 -> direct\n"), 0o644)
	var log bytes.Buffer
	logs, err := NewLogs("info", &log)
	if err != nil {
		t.Fatal(err)
	}
	start := func() *Node {
		t.Helper()
		n, err := Prepare(testConfig(dir), logs, testPlatform())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.Adapters(nil); errors.Is(err, ErrUnsupported) {
			t.Skip(err)
		} else if err != nil {
			t.Fatal(err)
		}
		return n
	}
	n := start()
	if st := n.Status(); st.RulePreset != "everything" || len(n.device.Rules.Rules) != 1 {
		t.Fatalf("started with %q, %+v", st.RulePreset, n.device.Rules)
	}
	if _, err := os.Lstat(filepath.Join(dir, LocalRulesFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rules.local is left: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, DeviceFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the device file: %v %v", fi, err)
	}
	if !strings.Contains(log.String(), "rules.local is removed") {
		t.Fatalf("the log doesn't say so:\n%s", log.String())
	}
	// The next start reads the device file alone.
	n = start()
	if st := n.Status(); st.RulePreset != "everything" || len(n.device.Rules.Rules) != 1 {
		t.Fatalf("restarted with %q, %+v", st.RulePreset, n.device.Rules)
	}
	// Both: rules.local is what a stopped carry-over left, and goes.
	writeFile(t, filepath.Join(dir, LocalRulesFile), []byte("preset space\n"), 0o644)
	n = start()
	if st := n.Status(); st.RulePreset != "everything" {
		t.Fatalf("with both, started with %q", st.RulePreset)
	}
	if _, err := os.Lstat(filepath.Join(dir, LocalRulesFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rules.local is left: %v", err)
	}
}
