package localapi

import (
	"context"
	"errors"
	"fmt"
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
	// presets.
	AccessControl
	// AccessAdmin: everything, the agent's log too.
	AccessAdmin
)

// methodAccess is the level each call needs; a call not listed needs
// AccessAdmin.
var methodAccess = map[string]Access{
	localapiv1.LocalService_GetStatus_FullMethodName:     AccessControl,
	localapiv1.LocalService_WatchStatus_FullMethodName:   AccessControl,
	localapiv1.LocalService_ListSpaces_FullMethodName:    AccessControl,
	localapiv1.LocalService_Connect_FullMethodName:       AccessControl,
	localapiv1.LocalService_Disconnect_FullMethodName:    AccessControl,
	localapiv1.LocalService_SetRulePreset_FullMethodName: AccessControl,
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
}

// NewPolicy is the policy of a service running as this process, with the
// group named group, or numbered (a gid: where the pure-Go lookup can't see
// the system's groups, as on macOS): none if group is empty or no such
// group exists (then only root and the service's user may use the API).
func NewPolicy(group string) (Policy, error) {
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

// Access is what c may do.
func (p Policy) Access(c Caller) Access {
	switch {
	case c.UID == 0 || c.UID == p.ServiceUID:
		return AccessAdmin
	case p.HasGroup && slices.Contains(c.GIDs, p.Group):
		return AccessControl
	}
	return AccessNone
}

// allow checks the caller of method, from ctx, against the policy.
func (p Policy) allow(ctx context.Context, method string) error {
	need, ok := methodAccess[method]
	if !ok {
		need = AccessAdmin
	}
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return ErrPermissionDenied
	}
	c, ok := pr.AuthInfo.(Caller)
	if !ok || p.Access(c) < need {
		return ErrPermissionDenied
	}
	return nil
}

// serverOptions are the policy's interceptors, unary and streaming, and
// the transport credentials that put each caller's credentials on its
// connection.
func (p Policy) serverOptions() []grpckit.ServerOption {
	return []grpckit.ServerOption{
		grpckit.WithUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := p.allow(ctx, info.FullMethod); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpckit.WithStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := p.allow(ss.Context(), info.FullMethod); err != nil {
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
