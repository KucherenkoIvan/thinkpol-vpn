package service

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// launchd's own reader accepts a device's plist: plutil -lint, then plutil's JSON
// of it, on a copy in the test's directory (plutil only reads it).
func TestPlutilReadsTheLaunchdPlist(t *testing.T) {
	if _, err := os.Stat("/usr/bin/plutil"); err != nil {
		t.Skip("no plutil")
	}
	path := filepath.Join(t.TempDir(), Label+".plist")
	if err := os.WriteFile(path, LaunchdPlist(Definition{Binary: BinaryPath, CrashTrace: trace}), 0o644); err != nil {
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
		StderrPath       string `json:"StandardErrorPath"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Label != Label || strings.Join(got.ProgramArguments, " ") != BinaryPath+" up -service" ||
		len(got.Env) != 0 || !got.RunAtLoad || !got.KeepAlive ||
		got.ThrottleInterval != RestartAfterSeconds || got.ExitTimeOut != StopTimeoutSeconds || got.StderrPath != trace {
		t.Fatalf("plutil reads %+v", got)
	}
}
