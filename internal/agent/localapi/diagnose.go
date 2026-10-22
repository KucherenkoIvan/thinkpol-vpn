package localapi

import (
	"context"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// DiagSchemaVersion is the schema of Diagnose's snapshot
// (Diagnostics.schema_version): bumped when a field is removed or changes
// meaning, not when one is added.
const DiagSchemaVersion = 1

// Diagnose serves the snapshot: whole to root and the service's user, to
// the group without the parts that name public addresses.
func (s *server) Diagnose(ctx context.Context, _ *localapiv1.DiagnoseRequest) (*localapiv1.DiagnoseResponse, error) {
	d := s.node.Diagnose(ctx, callerAccess(ctx, s.policy) >= AccessAdmin)
	return &localapiv1.DiagnoseResponse{Diagnostics: diagnosticsProto(d, time.Now(), s.version)}, nil
}

// callerAccess is what the caller of ctx may do under p.
func callerAccess(ctx context.Context, p Policy) Access {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return AccessNone
	}
	c, ok := pr.AuthInfo.(Caller)
	if !ok {
		return AccessNone
	}
	return p.Access(c)
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
		Routes:        routesProto(d.Routes),
		Rules:         rulesProto(d.Routes),
		Guard:         guardProto(d.Guard),
	}
}

func routesProto(in netcfg.Inspection) *localapiv1.DiagRoutes {
	if in.RoutesUnreadable != "" {
		return &localapiv1.DiagRoutes{Unreadable: in.RoutesUnreadable}
	}
	out := &localapiv1.DiagRoutes{}
	for _, r := range in.Routes {
		out.Routes = append(out.Routes, &localapiv1.DiagRoute{
			Owner: r.Owner.String(), Family: r.Family.String(), Destination: prefixString(r.Dst), Type: r.Type,
			Gateway: addrString(r.Gateway), Interface: r.Interface, Metric: uint32(max(r.Metric, 0)),
			Table: uint32(max(r.Table, 0)), Scope: r.Scope,
		})
	}
	return out
}

func rulesProto(in netcfg.Inspection) *localapiv1.DiagRules {
	if in.RulesUnreadable != "" {
		return &localapiv1.DiagRules{Unreadable: in.RulesUnreadable}
	}
	out := &localapiv1.DiagRules{}
	for _, r := range in.Rules {
		out.Rules = append(out.Rules, &localapiv1.DiagRule{
			Owner: r.Owner.String(), Family: r.Family.String(), Priority: uint32(max(r.Priority, 0)),
			Table: uint32(max(r.Table, 0)), Destination: prefixString(r.Dst), Oif: r.Oif, Mark: r.Mark, Mask: r.Mask,
			Invert: r.Invert, SuppressPrefixlen: int32(max(min(r.SuppressPrefixlen, math.MaxInt32), -1)), Other: r.Other,
		})
	}
	return out
}

func guardProto(g routetable.GuardReport) *localapiv1.DiagGuard {
	if g.Unreadable != "" {
		return &localapiv1.DiagGuard{Unreadable: g.Unreadable, Where: g.Where}
	}
	out := &localapiv1.DiagGuard{Where: g.Where, Present: g.Present}
	if !g.Present {
		return out
	}
	out.Rules = &localapiv1.DiagGuardRules{Unreadable: g.RulesUnreadable}
	if g.RulesUnreadable == "" {
		for _, r := range g.Rules {
			out.Rules.Rules = append(out.Rules.Rules, &localapiv1.DiagGuardRule{
				Chain: r.Chain, Text: r.Text, Counted: r.Counted, Packets: r.Packets, Bytes: r.Bytes,
				Evaluations: r.Evaluations, States: r.States,
			})
		}
	}
	out.Exempt = &localapiv1.DiagPrefixes{Unreadable: g.ExemptUnreadable}
	if g.ExemptUnreadable == "" {
		for _, p := range g.Exempt {
			out.Exempt.Prefixes = append(out.Exempt.Prefixes, p.String())
		}
	}
	if nf := g.NFTables; nf != nil {
		out.Nftables = &localapiv1.DiagNftables{Dormant: nf.Dormant}
		for _, c := range nf.Chains {
			out.Nftables.Chains = append(out.Nftables.Chains, &localapiv1.DiagNftChain{
				Name: c.Name, Hook: c.Hook, Priority: int32(max(min(c.Priority, math.MaxInt32), math.MinInt32)), Policy: c.Policy,
			})
		}
	}
	if pf := g.PF; pf != nil {
		out.Pf = pfProto(pf)
	}
	return out
}

func pfProto(pf *routetable.PFReport) *localapiv1.DiagPf {
	out := &localapiv1.DiagPf{
		Enabled:   &localapiv1.DiagPfEnabled{Unreadable: pf.EnabledUnreadable},
		Hook:      &localapiv1.DiagPfHook{Unreadable: pf.HookUnreadable},
		Reference: &localapiv1.DiagPfReference{Unreadable: pf.ReferenceUnreadable},
	}
	if pf.EnabledUnreadable == "" {
		out.Enabled.Enabled = pf.Enabled
	}
	if pf.HookUnreadable == "" {
		out.Hook.State = pf.Hook
	}
	if r := pf.Reference; pf.ReferenceUnreadable == "" && r != nil {
		out.Reference.Recorded, out.Reference.Pid, out.Reference.PidOnly, out.Reference.Held = r.Recorded, uint32(max(r.Pid, 0)), r.PidOnly, r.Held
	}
	return out
}

// prefixString and addrString are "" for the zero value.
func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
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
