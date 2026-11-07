package localapi

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"google.golang.org/grpc/grpclog"
)

// grpc's errors reach the agent's log, not stderr (a device's crash
// trace); its info only at debug.
func TestGRPCLogsToTheAgentsLog(t *testing.T) {
	var out bytes.Buffer
	RouteGRPCLog(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, os.Stderr)) })
	grpclog.Error("transport: a failure")
	grpclog.Info("chatter")
	got := out.String()
	if !strings.Contains(got, "transport: a failure") || !strings.Contains(got, "component=grpc") || strings.Contains(got, "chatter") {
		t.Fatalf("log:\n%s", got)
	}
}

// grpc's Fatal also writes its message to stderr, so a device's crash
// trace says why the agent exited.
func TestGRPCFatalWritesToStderr(t *testing.T) {
	if os.Getenv("THINKPOL_TEST_GRPC_FATAL") == "1" {
		RouteGRPCLog(slog.New(slog.DiscardHandler))
		grpclog.Fatal("a fatal grpc failure")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGRPCFatalWritesToStderr$")
	cmd.Env = append(os.Environ(), "THINKPOL_TEST_GRPC_FATAL=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "a fatal grpc failure") {
		t.Fatalf("exit %v, stderr:\n%s", err, stderr.String())
	}
}
