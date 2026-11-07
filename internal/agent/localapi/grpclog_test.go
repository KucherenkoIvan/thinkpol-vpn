package localapi

import (
	"bytes"
	"io"
	"log/slog"
	"os"
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
