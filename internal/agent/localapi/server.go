package localapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KucherenkoIvan/go-kernel/app"
	"github.com/KucherenkoIvan/go-kernel/grpckit"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// Node is what the API serves: a running node (*agent.Node).
type Node interface {
	Status() agent.Status
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
}

// RulePresets switches a device's routing rules to a preset; the rule
// engine's (TP-015).
type RulePresets interface {
	// SetPreset switches to preset; ErrUnknownPreset if there is none by
	// that name.
	SetPreset(ctx context.Context, preset string) error
}

// Options are what the local API serves, and where.
type Options struct {
	// Socket is the socket's absolute path, in a directory of its own.
	Socket string
	// Group names the group whose members may control the node; empty, or
	// a group that doesn't exist, leaves the API to root.
	Group string
	Node  Node
	// Logs is the agent's in-memory log.
	Logs *logring.Ring
	// RulePresets is nil until the node has a rule engine.
	RulePresets RulePresets
	// Log gets the API's own events: refused calls at debug, failures.
	Log *slog.Logger
}

// Adapter serves the local API until ctx ends, as one of the service's
// app adapters: the socket is opened when it starts, so failing to open
// it stops the service like any other adapter's failure.
func Adapter(o Options) app.Adapter {
	return app.Adapter{Name: "local API", Run: func(ctx context.Context) error {
		p, err := NewPolicy(o.Group)
		if err != nil {
			return err
		}
		if o.Log != nil && o.Group != "" && !p.HasGroup {
			o.Log.Warn("no such group: the local API is root's only", "group", o.Group)
		}
		l, err := Listen(o.Socket, p)
		if err != nil {
			return err
		}
		return grpckit.Serve(ctx, NewGRPCServer(ctx, o, p), l)
	}}
}

// NewGRPCServer is the API on a gRPC server, behind p, until shutdown
// ends: streams end then too, so a stop doesn't wait out their grace
// period.
func NewGRPCServer(shutdown context.Context, o Options, p Policy) *grpc.Server {
	opts := append([]grpckit.ServerOption(nil), p.serverOptions()...)
	if o.Log != nil {
		opts = append(opts, grpckit.WithLogger(o.Log))
	}
	for e, code := range errorCodes {
		opts = append(opts, grpckit.WithErrorCode(e.Code, code))
	}
	srv := grpckit.NewServer(opts...)
	localapiv1.RegisterLocalServiceServer(srv, &server{node: o.Node, logs: o.Logs, presets: o.RulePresets, shutdown: shutdown.Done()})
	return srv
}

type server struct {
	localapiv1.UnimplementedLocalServiceServer
	node     Node
	logs     *logring.Ring
	presets  RulePresets
	shutdown <-chan struct{}
}

// Bounds of WatchStatus's interval.
const (
	minWatchInterval     = 250 * time.Millisecond
	defaultWatchInterval = time.Second
)

// logsPoll is how often a followed log is checked for new lines.
const logsPoll = 200 * time.Millisecond

func (s *server) GetStatus(context.Context, *localapiv1.GetStatusRequest) (*localapiv1.GetStatusResponse, error) {
	return &localapiv1.GetStatusResponse{Status: statusProto(s.node.Status())}, nil
}

func (s *server) WatchStatus(req *localapiv1.WatchStatusRequest, stream grpc.ServerStreamingServer[localapiv1.WatchStatusResponse]) error {
	every := defaultWatchInterval
	if req.GetInterval() != nil {
		every = max(req.GetInterval().AsDuration(), minWatchInterval)
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if err := stream.Send(&localapiv1.WatchStatusResponse{Status: statusProto(s.node.Status())}); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-s.shutdown:
			return nil
		case <-tick.C:
		}
	}
}

func (s *server) Connect(ctx context.Context, _ *localapiv1.ConnectRequest) (*localapiv1.ConnectResponse, error) {
	if err := s.node.Connect(ctx); err != nil {
		return nil, nodeError(err)
	}
	return &localapiv1.ConnectResponse{Status: statusProto(s.node.Status())}, nil
}

func (s *server) Disconnect(ctx context.Context, _ *localapiv1.DisconnectRequest) (*localapiv1.DisconnectResponse, error) {
	if err := s.node.Disconnect(ctx); err != nil {
		return nil, nodeError(err)
	}
	return &localapiv1.DisconnectResponse{Status: statusProto(s.node.Status())}, nil
}

// nodeError is what a client is told of a failed Connect or Disconnect: a
// failed start only by its step, whose detail went to the node's log.
func nodeError(err error) error {
	var se *agent.StartError
	switch {
	case errors.Is(err, agent.ErrServerMode):
		return ErrServerMode
	case errors.Is(err, agent.ErrNotRunning):
		return ErrNotRunning
	case errors.As(err, &se):
		return status.Errorf(codes.Unavailable, "starting the data plane failed at step %q; the service's log has the details", se.Step)
	}
	return err
}

func (s *server) ListSpaces(context.Context, *localapiv1.ListSpacesRequest) (*localapiv1.ListSpacesResponse, error) {
	// One space per node until a device enrolls in several (D9, TP-049).
	return &localapiv1.ListSpacesResponse{Spaces: []*localapiv1.Space{{Id: s.node.Status().Space.String(), Active: true}}}, nil
}

func (s *server) SetRulePreset(ctx context.Context, req *localapiv1.SetRulePresetRequest) (*localapiv1.SetRulePresetResponse, error) {
	if s.presets == nil {
		return nil, ErrPresetsUnavailable
	}
	if err := s.presets.SetPreset(ctx, req.GetPreset()); err != nil {
		return nil, err
	}
	return &localapiv1.SetRulePresetResponse{}, nil
}

func (s *server) TailLogs(req *localapiv1.TailLogsRequest, stream grpc.ServerStreamingServer[localapiv1.TailLogsResponse]) error {
	n := int(req.GetLines())
	if n == 0 {
		n = 100
	}
	lines, next, _ := s.logs.Since(0)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if err := stream.Send(&localapiv1.TailLogsResponse{Lines: lines}); err != nil {
		return err
	}
	if !req.GetFollow() {
		return nil
	}
	tick := time.NewTicker(logsPoll)
	defer tick.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-s.shutdown:
			return nil
		case <-tick.C:
		}
		var missed uint64
		lines, next, missed = s.logs.Since(next)
		if len(lines) == 0 && missed == 0 {
			continue
		}
		if err := stream.Send(&localapiv1.TailLogsResponse{Lines: lines, Missed: missed}); err != nil {
			return err
		}
	}
}
