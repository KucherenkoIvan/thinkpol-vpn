package localapi

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// DiagSchemaVersion is the schema of Diagnose's snapshot
// (Diagnostics.schema_version): bumped when a field is removed or changes
// meaning, not when one is added.
const DiagSchemaVersion = 1

func (s *server) Diagnose(ctx context.Context, _ *localapiv1.DiagnoseRequest) (*localapiv1.DiagnoseResponse, error) {
	d := s.node.Diagnose(ctx)
	return &localapiv1.DiagnoseResponse{Diagnostics: diagnosticsProto(d, time.Now(), s.version)}, nil
}

// diagnosticsProto is d on the wire, taken at now by an agent of version.
func diagnosticsProto(d agent.Diagnostics, now time.Time, version string) *localapiv1.Diagnostics {
	return &localapiv1.Diagnostics{
		SchemaVersion: DiagSchemaVersion,
		TakenAt:       timestamppb.New(now),
		Os:            runtime.GOOS,
		AgentVersion:  version,
		Status:        statusProto(d.Status),
		Tun:           interfaceProto(d.TUN),
	}
}

func interfaceProto(r agent.InterfaceReport) *localapiv1.DiagInterface {
	if r.Unreadable != "" {
		return &localapiv1.DiagInterface{Unreadable: r.Unreadable}
	}
	out := &localapiv1.DiagInterface{
		Name: r.Name, Index: uint32(max(r.Index, 0)), Mtu: uint32(max(r.MTU, 0)), Up: r.Up, Running: r.Running,
	}
	for _, p := range r.Addrs {
		out.Addresses = append(out.Addresses, p.String())
	}
	return out
}

// Diagnose is the node's diagnostics snapshot.
func (c *Client) Diagnose(ctx context.Context) (*localapiv1.Diagnostics, error) {
	resp, err := c.api.Diagnose(ctx, &localapiv1.DiagnoseRequest{})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetDiagnostics(), nil
}

// WriteJSONFile writes m as WriteJSON does to a new file at path, mode
// 0600, replacing what is there (a symlink itself, never its target): it
// is written beside path and renamed over it, so a reader never sees half
// of it.
func WriteJSONFile(path string, m proto.Message) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if err := WriteJSON(f, m); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
