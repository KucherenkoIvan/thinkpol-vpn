package localapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/KucherenkoIvan/go-kernel/grpckit"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// Access is what a caller may do.
type Access uint8

const (
	// AccessNone: nothing.
	AccessNone Access = iota
	// AccessControl: the status, the spaces, connect and disconnect, rule
	// presets, the diagnostics' parts without public addresses.
	AccessControl
	// AccessAdmin: everything, the agent's log too.
	AccessAdmin
)

func (a Access) String() string {
	switch a {
	case AccessNone:
		return "none"
	case AccessControl:
		return "control"
	case AccessAdmin:
		return "admin"
	}
	return "Access(" + strconv.Itoa(int(a)) + ")"
}

// methodAccess is the level each call needs; a call not listed needs
// AccessAdmin.
var methodAccess = map[string]Access{
	localapiv1.LocalService_GetStatus_FullMethodName:     AccessControl,
	localapiv1.LocalService_WatchStatus_FullMethodName:   AccessControl,
	localapiv1.LocalService_ListSpaces_FullMethodName:    AccessControl,
	localapiv1.LocalService_Connect_FullMethodName:       AccessControl,
	localapiv1.LocalService_Disconnect_FullMethodName:    AccessControl,
	localapiv1.LocalService_SetRulePreset_FullMethodName: AccessControl,
	localapiv1.LocalService_Diagnose_FullMethodName:      AccessControl,
	localapiv1.LocalService_TailLogs_FullMethodName:      AccessAdmin,
}

// Caller is a local API client's process by its credentials, as the
// kernel reported them when it connected.
type Caller struct {
	UID uint32
	// GIDs are its effective group and its supplementary groups.
	GIDs []uint32
}

func (Caller) AuthType() string { return "peer credentials" }

// Membership tells whether a user is a member of a group by the OS's
// group database, which the caller's recorded groups can fall short of.
type Membership interface {
	IsMember(ctx context.Context, uid, gid uint32) (bool, error)
}

// Policy decides what callers may do: root and the service's own user may
// do everything, the group's members may control the node, and no one else
// may do anything.
type Policy struct {
	// ServiceUID is the user the service runs as.
	ServiceUID uint32
	// Group is the gid whose members control the node; meaningful only
	// with HasGroup.
	Group    uint32
	HasGroup bool
	// Membership, if set, is asked about a caller whose recorded groups
	// lack Group (macOS: Directory Services, as the file system asks); an
	// error means not a member. nil: the recorded groups only.
	Membership Membership
}

// NewPolicy is the policy of a service running as this process, with the
// group named group (in /etc/group, or on macOS in Directory Services), or
// numbered (a gid): none if group is empty or no such group exists (then
// only root and the service's user may use the API). On macOS, with a
// group, its Membership asks Directory Services.
func NewPolicy(group string) (Policy, error) {
	p, err := policyFor(group)
	if err != nil {
		return Policy{}, err
	}
	if p.HasGroup {
		p.Membership = systemMembership()
	}
	return p, nil
}

func policyFor(group string) (Policy, error) {
	p := Policy{ServiceUID: uint32(os.Geteuid())}
	if group == "" {
		return p, nil
	}
	if gid, err := strconv.ParseUint(group, 10, 32); err == nil {
		p.Group, p.HasGroup = uint32(gid), true
		return p, nil
	}
	g, err := user.LookupGroup(group)
	if errors.As(err, new(user.UnknownGroupError)) {
		// The pure-Go lookup reads /etc/group only; macOS keeps its
		// groups in Directory Services.
		if gid, ok := systemGroup(group); ok {
			p.Group, p.HasGroup = gid, true
		}
		return p, nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("group %q: %w", group, err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return Policy{}, fmt.Errorf("group %q: gid %q: %w", group, g.Gid, err)
	}
	p.Group, p.HasGroup = uint32(gid), true
	return p, nil
}

// isAdmin reports whether c may do everything: by its uid alone.
func (p Policy) isAdmin(c Caller) bool { return c.UID == 0 || c.UID == p.ServiceUID }

// access is what c may do, and why Membership couldn't say, if it was
// asked and failed: then c is not a member.
func (p Policy) access(ctx context.Context, c Caller) (Access, error) {
	switch {
	case p.isAdmin(c):
		return AccessAdmin, nil
	case !p.HasGroup:
		return AccessNone, nil
	case slices.Contains(c.GIDs, p.Group):
		return AccessControl, nil
	case p.Membership == nil:
		return AccessNone, nil
	}
	member, err := p.Membership.IsMember(ctx, c.UID, p.Group)
	if err != nil || !member {
		return AccessNone, err
	}
	return AccessControl, nil
}

// allow checks the caller of method, from ctx, against the policy, and
// logs a refusal with the caller's uid and the group it was checked
// against (not its groups: only how many the kernel recorded). A root-only
// call is refused as ErrRootOnly before any group is looked up; a caller
// whose membership the OS couldn't settle is refused as
// ErrMembershipUnknown; a caller that left during the lookup is refused
// nothing, and gets its context's end.
func (p Policy) allow(ctx context.Context, log *slog.Logger, method string) error {
	need, ok := methodAccess[method]
	if !ok {
		need = AccessAdmin
	}
	c, ok := callerFrom(ctx)
	if !ok {
		log.Info("local API call refused: no peer credentials", "method", method, "refusal", ErrPermissionDenied.Code)
		return ErrPermissionDenied
	}
	if need == AccessAdmin && !p.isAdmin(c) {
		// No membership grants this one: the OS isn't asked.
		p.logRefusal(ctx, log, ErrRootOnly, method, c, need)
		return ErrRootOnly
	}
	got, err := p.access(ctx, c)
	if got >= need {
		return nil
	}
	if err != nil && ctx.Err() != nil {
		// Judged by ctx, not by err: a Directory Services timeout is a
		// DeadlineExceeded too, and that one is a failure to report.
		log.Debug("local API call abandoned during the membership lookup", "method", method, "uid", c.UID)
		return ctx.Err()
	}
	if err != nil {
		p.logRefusal(ctx, log, ErrMembershipUnknown, method, c, need, "has", got.String(), "membership_err", err)
		return ErrMembershipUnknown
	}
	p.logRefusal(ctx, log, ErrPermissionDenied, method, c, need, "has", got.String())
	return ErrPermissionDenied
}

// logRefusal logs c's call of method refused as refusal, with what was
// looked up, if anything (extra: what c has, why the OS couldn't say).
// ErrMembershipUnknown is a warning, the others are routine.
func (p Policy) logRefusal(ctx context.Context, log *slog.Logger, refusal Error, method string, c Caller, need Access, extra ...any) {
	attrs := []any{"method", method, "refusal", refusal.Code, "uid", c.UID, "needs", need.String(), "recorded_groups", len(c.GIDs)}
	if p.HasGroup {
		attrs = append(attrs, "group", p.Group)
	}
	attrs = append(attrs, extra...)
	level := slog.LevelInfo
	if refusal == ErrMembershipUnknown {
		level = slog.LevelWarn
	}
	log.Log(ctx, level, "local API call refused", attrs...)
}

// callerFrom is the caller of ctx, as the transport recorded it.
func callerFrom(ctx context.Context) (Caller, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return Caller{}, false
	}
	c, ok := pr.AuthInfo.(Caller)
	return c, ok
}

// serverOptions are the policy's interceptors, unary and streaming, which
// log refusals to log, and the transport credentials that put each
// caller's credentials on its connection.
func (p Policy) serverOptions(log *slog.Logger) []grpckit.ServerOption {
	return []grpckit.ServerOption{
		grpckit.WithUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := p.allow(ctx, log, info.FullMethod); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpckit.WithStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := p.allow(ss.Context(), log, info.FullMethod); err != nil {
				return err
			}
			return h(srv, ss)
		}),
		grpckit.WithGRPCOptions(grpc.Creds(peerCredentials{})),
	}
}

// peerCredentials are transport credentials that only read who connected:
// the connection stays a plain local socket.
type peerCredentials struct{}

func (peerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(syscall.Conn)
	if _, unix := conn.LocalAddr().(*net.UnixAddr); !ok || !unix {
		return nil, nil, errors.New("localapi: not a Unix socket connection")
	}
	c, err := callerOf(uc)
	if err != nil {
		return nil, nil, fmt.Errorf("localapi: peer credentials: %w", err)
	}
	return conn, c, nil
}

func (peerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("localapi: peer credentials are server-side only")
}

func (peerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peer credentials"}
}

func (c peerCredentials) Clone() credentials.TransportCredentials { return c }

//nolint:staticcheck // part of the interface, deprecated
func (peerCredentials) OverrideServerName(string) error { return nil }
