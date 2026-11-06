package localapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// DiagSchemaVersion is the schema of Diagnose's snapshot
// (Diagnostics.schema_version). It is bumped when a field is removed or
// renamed or its type or meaning changes, not when one is added;
// `unreadable` texts are free-form, and enumerated string values (a
// route's type, an Apply's step) may grow without a bump.
const DiagSchemaVersion = 1

// Diagnose serves the snapshot: whole to root and the service's user, to
// the group without the parts that name public addresses.
func (s *server) Diagnose(ctx context.Context, _ *localapiv1.DiagnoseRequest) (*localapiv1.DiagnoseResponse, error) {
	c, ok := callerFrom(ctx)
	d := s.node.Diagnose(ctx, ok && s.policy.isAdmin(c))
	return &localapiv1.DiagnoseResponse{Diagnostics: diagnosticsProto(d, time.Now(), s.version)}, nil
}

// diagnosticsProto is d on the wire, taken at now by an agent of version.
func diagnosticsProto(d agent.Diagnostics, now time.Time, version string) *localapiv1.Diagnostics {
	return &localapiv1.Diagnostics{
		SchemaVersion: DiagSchemaVersion,
		TakenAt:       timestamppb.New(now),
		Os:            runtime.GOOS,
		AgentVersion:  version,
		HostParts:     d.HostParts,
		Status:        statusProto(d.Status),
		Tun:           interfaceProto(d.TUN),
		LastApply:     applyProto(d.LastApply),
		Routes:        routesProto(d.Routes),
		PolicyRules:   rulesProto(d.Routes),
		Guard:         guardProto(d.Guard),
		Dns:           dnsProto(d.DNS),
	}
}

func applyProto(a agent.ApplyReport) *localapiv1.DiagApply {
	if a.Unreadable != "" {
		return &localapiv1.DiagApply{Unreadable: a.Unreadable}
	}
	out := &localapiv1.DiagApply{Started: timestamp(a.Trace.Started), Took: durationpb.New(a.Trace.Took), Failed: string(a.Trace.Failed)}
	for _, s := range a.Trace.Steps {
		out.Steps = append(out.Steps, &localapiv1.DiagApplyStep{Step: string(s.Step), Took: durationpb.New(s.Took), Failed: s.Failed})
	}
	return out
}

func dnsProto(r dns.HostReport) *localapiv1.DiagDns {
	if r.Unreadable != "" {
		return &localapiv1.DiagDns{Unreadable: r.Unreadable}
	}
	out := &localapiv1.DiagDns{}
	for _, s := range r.Sources {
		src := &localapiv1.DiagDnsSource{Name: s.Name, Unreadable: s.Unreadable}
		if s.Unreadable == "" {
			src.Present = s.Present
			for _, res := range s.Resolvers {
				src.Resolvers = append(src.Resolvers, &localapiv1.DiagResolver{
					Interface: res.Interface, Scoped: res.Scoped, Servers: res.Servers, Domains: res.Domains, Search: res.Search,
					Order: uint32(max(res.Order, 0)), Flags: res.Flags, Reach: res.Reach, Options: res.Options, NodeWritten: res.NodeWritten,
				})
			}
		}
		out.Sources = append(out.Sources, src)
	}
	return out
}

func routesProto(in netcfg.Inspection) *localapiv1.DiagRoutes {
	if in.RoutesUnreadable != "" {
		return &localapiv1.DiagRoutes{Unreadable: in.RoutesUnreadable}
	}
	out := &localapiv1.DiagRoutes{}
	for _, r := range in.Routes {
		out.Routes = append(out.Routes, routeProto(r))
	}
	for _, r := range in.UnrecordedProto2 {
		out.UnrecordedProto2 = append(out.UnrecordedProto2, routeProto(r))
	}
	return out
}

func routeProto(r netcfg.HostRoute) *localapiv1.DiagRoute {
	owner := ""
	if r.Owner != 0 {
		owner = r.Owner.String()
	}
	return &localapiv1.DiagRoute{
		Owner: owner, Family: r.Family.String(), Destination: prefixString(r.Dst), Type: r.Type,
		Gateway: addrString(r.Gateway), Interface: r.Interface, Metric: uint32(max(r.Metric, 0)),
		Table: uint32(max(r.Table, 0)), Scope: r.Scope,
	}
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
			Invert: r.Invert, SuppressPrefixlen: int32(max(min(r.SuppressPrefixlen, math.MaxInt32), -1)), Action: r.Action, Other: r.Other,
		})
	}
	return out
}

// guardProto is g on the wire. A guard read in part has each part as it
// was read: rules and exempt are there (empty when there is no guard),
// present unset (left out of the JSON) when it couldn't be told.
func guardProto(g routetable.GuardReport) *localapiv1.DiagGuard {
	if g.Unreadable != "" {
		return &localapiv1.DiagGuard{Unreadable: g.Unreadable, Where: g.Where}
	}
	out := &localapiv1.DiagGuard{
		Where:  g.Where,
		Rules:  &localapiv1.DiagGuardRules{Unreadable: g.RulesUnreadable},
		Exempt: &localapiv1.DiagPrefixes{Unreadable: g.ExemptUnreadable},
	}
	if !g.PresentUnknown {
		out.Present = &g.Present
	}
	if g.RulesUnreadable == "" {
		for _, r := range g.Rules {
			out.Rules.Rules = append(out.Rules.Rules, &localapiv1.DiagGuardRule{
				Chain: r.Chain, Text: r.Text, Counted: r.Counted, Packets: r.Packets, Bytes: r.Bytes,
				Evaluations: r.Evaluations, States: r.States,
			})
		}
	}
	if g.ExemptUnreadable == "" {
		for _, p := range g.Exempt {
			out.Exempt.Prefixes = append(out.Exempt.Prefixes, p.String())
		}
	}
	if nf := g.NFTables; nf != nil {
		out.Nftables = &localapiv1.DiagNftables{Dormant: nf.Dormant, ChainsUnreadable: nf.ChainsUnreadable}
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
		Enabled:    &localapiv1.DiagPfEnabled{Unreadable: pf.EnabledUnreadable},
		GuardCheck: &localapiv1.DiagPfGuardCheck{Unreadable: pf.GuardCheckUnreadable},
		Reference:  &localapiv1.DiagPfReference{Unreadable: pf.ReferenceUnreadable},
	}
	if pf.EnabledUnreadable == "" {
		out.Enabled.Enabled = pf.Enabled
	}
	if pf.GuardCheckUnreadable == "" {
		c := out.GuardCheck
		c.State, c.MainRules, c.Skipped, c.AnchorsBefore = pf.GuardCheck, pf.MainRules, pf.Skipped, pf.AnchorsBefore
	}
	if r := pf.Reference; pf.ReferenceUnreadable == "" && r != nil {
		out.Reference.Recorded, out.Reference.Stale, out.Reference.Pid, out.Reference.PidOnly = r.Recorded, r.Stale, uint32(max(r.Pid, 0)), r.PidOnly
		out.Reference.HeldUnreadable = r.HeldUnreadable
		if r.HeldUnreadable == "" {
			out.Reference.Held = r.Held
		}
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

func interfaceProto(r netcfg.InterfaceReport) *localapiv1.DiagInterface {
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

// WriteDiagnostics writes d as `thinkpol diag` prints it, the snapshot's
// v1 form: JSON with the schema's own field names (snake_case) and every
// field present, an unset one as its zero value or null.
func WriteDiagnostics(w io.Writer, d *localapiv1.Diagnostics) error {
	b, err := protojson.MarshalOptions{Multiline: true, UseProtoNames: true, EmitUnpopulated: true}.Marshal(d)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// ErrNotAFile: -o names something there that isn't a regular file (a
// device, /dev/null, a directory, a symlink): replacing it could change
// the host.
var ErrNotAFile = errors.New("not a regular file: refusing to replace it")

// WriteDiagnosticsFile writes d as WriteDiagnostics does to a new file at
// path, mode 0600, synced, replacing what is there only if that is a
// regular file. Anything else there is refused (ErrNotAFile): a device
// (/dev/null), a directory, and any symlink, whatever it points to
// (/dev/stdout is a link through /proc/self/fd/1 to whatever stdout is,
// a file included); whoever means to replace a link removes it first. It
// is written beside path and renamed over it, so a reader never sees half
// of it.
func WriteDiagnosticsFile(path string, d *localapiv1.Diagnostics) (err error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotAFile)
	}
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
	if err := WriteDiagnostics(f, d); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
