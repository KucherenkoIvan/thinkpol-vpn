package service

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// launchd's own reader accepts the plist: plutil -lint, then plutil's JSON
// of it, on a copy in the test's directory (plutil only reads it).
func TestPlutilReadsTheLaunchdPlist(t *testing.T) {
	if _, err := os.Stat("/usr/bin/plutil"); err != nil {
		t.Skip("no plutil")
	}
	for _, on := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), Label+".plist")
		if err := os.WriteFile(path, LaunchdPlist(Definition{Binary: BinaryPath, ConnectOnBoot: on}), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
			t.Fatalf("plutil -lint: %v\n%s", err, out)
		}
		out, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path).Output()
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Label            string
			ProgramArguments []string
			Env              map[string]string `json:"EnvironmentVariables"`
			RunAtLoad        bool
			KeepAlive        bool
			ThrottleInterval int
			ExitTimeOut      int
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		connect := map[bool]string{true: "on", false: "off"}[on]
		if got.Label != Label || len(got.ProgramArguments) != 2 || got.ProgramArguments[0] != BinaryPath || got.ProgramArguments[1] != "up" ||
			len(got.Env) != 1 || got.Env["THINKPOL_CONNECT_ON_BOOT"] != connect || !got.RunAtLoad || !got.KeepAlive ||
			got.ThrottleInterval != RestartAfter || got.ExitTimeOut != 60 {
			t.Fatalf("plutil reads %+v", got)
		}
	}
}
