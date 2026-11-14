//go:build unix

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/grpclog"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir/trusteddirtest"
)

// failingState is node's state directory with a map Prepare refuses.
func failingState(t *testing.T, node string) string {
	t.Helper()
	state, _ := m0State(t, node)
	if err := os.WriteFile(filepath.Join(state, agent.MapFileName), []byte("not a map"), 0o644); err != nil {
		t.Fatal(err)
	}
	return state
}

// isPrepareError says err is failingState's map refused by Prepare.
func isPrepareError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is not a valid map")
}

// keepUpGlobals restores what runUp sets for the whole process.
func keepUpGlobals(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(prev)
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, os.Stderr))
	})
}

// A start of a node that isn't known to be a device, under a device's
// definition, keeps no trace even when it fails before the node runs:
// the file is gone and its error goes nowhere. A device's failed start
// keeps the previous run's trace: one its node file names a device,
// whatever its map. A device mode by flag alone, or by default, doesn't
// name one: the map that would show it can't be read.
func TestOnlyAKnownDevicesFailedStartKeepsTheTrace(t *testing.T) {
	unsetTHINKPOL(t)
	keepUpGlobals(t)
	withNodeFile := func(state, mode string) string {
		if err := os.WriteFile(filepath.Join(state, agent.NodeFile), []byte(`{"mode": "`+mode+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return state
	}
	for name, tc := range map[string]struct {
		args []string
		kept bool
	}{
		"a server by its flag":      {[]string{"-state", failingState(t, "device-a"), "-mode", "server"}, false},
		"a server by its node file": {[]string{"-state", withNodeFile(failingState(t, "device-a"), "server")}, false},
		"a device by default":       {[]string{"-state", failingState(t, "device-a")}, false},
		"a device by its flag":      {[]string{"-state", failingState(t, "device-a"), "-mode", "device"}, false},
		"a device by its node file": {[]string{"-state", withNodeFile(failingState(t, "server-1"), "device")}, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(trusteddirtest.TempDir(t), agent.CrashTraceFile)
			crashTracePath = func() string { return path }
			t.Cleanup(func() { crashTracePath = agent.CrashTracePath })
			if err := os.WriteFile(path, []byte("panic: the previous run\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stderr, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stderr.Close() }()
			err = runUp(context.Background(), env{stdin: strings.NewReader(""), stdout: io.Discard, stderr: stderr}, append(tc.args, "-api-socket", ""))
			if !isPrepareError(err) {
				t.Fatalf("the start failed with %v, not in Prepare", err)
			}
			got, rerr := os.ReadFile(path)
			switch {
			case tc.kept && string(got) != "panic: the previous run\n":
				t.Fatalf("start failed with %v; file %q, %v", err, got, rerr)
			case !tc.kept && rerr == nil:
				t.Fatalf("start failed with %v; the file is still there: %q", err, got)
			}
		})
	}
}

// up sends grpc's log to the agent's, and under -service sends nothing
// to a regular file stderr that isn't the trace (PRD S2).
func TestUpRoutesItsLog(t *testing.T) {
	unsetTHINKPOL(t)
	keepUpGlobals(t)
	up := func(t *testing.T, stderr io.Writer, extra ...string) {
		t.Helper()
		// -service needs a socket; the start fails before it is made.
		args := append([]string{"-state", failingState(t, "server-1"), "-api-socket", filepath.Join(trusteddirtest.TempDir(t), "api.sock")}, extra...)
		if err := runUp(context.Background(), env{stdin: strings.NewReader(""), stdout: io.Discard, stderr: stderr}, args); !isPrepareError(err) {
			t.Fatalf("the start failed with %v, not in Prepare", err)
		}
		grpclog.Error("a grpc failure")
	}
	t.Run("grpc's log", func(t *testing.T) {
		var out bytes.Buffer
		up(t, &out)
		if !strings.Contains(out.String(), "a grpc failure") || !strings.Contains(out.String(), "component=grpc") {
			t.Fatalf("log:\n%s", out.String())
		}
	})
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "a file", true: "a file under -service"}[service], func(t *testing.T) {
			path := filepath.Join(trusteddirtest.TempDir(t), "stderr")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			var extra []string
			if service {
				extra = []string{"-service"}
			}
			up(t, f, extra...)
			got, _ := os.ReadFile(path)
			if logged := strings.Contains(string(got), "a grpc failure"); logged == service {
				t.Fatalf("-service %v, file:\n%s", service, got)
			}
		})
	}
}
