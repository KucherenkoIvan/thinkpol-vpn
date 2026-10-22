package localapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sync"
	"time"

	"google.golang.org/grpc"

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
	SetRulePreset(ctx context.Context, preset string) error
	Diagnose(ctx context.Context, host bool) agent.Diagnostics
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
	// Log gets the API's own events: refused calls at debug, failures.
	Log *slog.Logger
	// RetryAfter is how long to wait before serving again after the API
	// failed; 0 is DefaultRetryAfter.
	RetryAfter time.Duration
	// Version is the agent's, for Diagnose's snapshot.
	Version string
}

// DefaultRetryAfter paces the local API's attempts to serve again.
const DefaultRetryAfter = 10 * time.Second

// Adapter serves the local API until ctx ends, as one of the service's
// app adapters. The API failing (its socket can't be opened, serving
// broke) never stops the node: the VPN keeps running without it, the
// failure is logged as an error, and the API is tried again every
// RetryAfter.
func Adapter(o Options) app.Adapter {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.RetryAfter == 0 {
		o.RetryAfter = DefaultRetryAfter
	}
	return app.Adapter{Name: "local API", Run: func(ctx context.Context) error {
		for {
			err := serveOnce(ctx, o)
			if ctx.Err() != nil {
				return nil
			}
			o.Log.Error("the local API is down: the node runs on without it; retrying", "socket", o.Socket, "in", o.RetryAfter, "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(o.RetryAfter):
			}
		}
	}}
}

func serveOnce(ctx context.Context, o Options) error {
	p, err := NewPolicy(o.Group)
	if err != nil {
		return err
	}
	if o.Group != "" && !p.HasGroup {
		o.Log.Warn("no such group: the local API is root's only", "group", o.Group)
	}
	l, err := Listen(o.Socket, p)
	if err != nil {
		return err
	}
	o.Log.Info("local API listening", "socket", o.Socket)
	return grpckit.Serve(ctx, NewGRPCServer(ctx, o, p), l)
}

// MaxStreams bounds the calls in flight on one connection.
const MaxStreams = 16

// NewGRPCServer is the API on a gRPC server, behind p, until shutdown
// ends: streams end then too, so a stop doesn't wait out their grace
// period.
func NewGRPCServer(shutdown context.Context, o Options, p Policy) *grpc.Server {
	opts := append([]grpckit.ServerOption(nil), p.serverOptions()...)
	opts = append(opts, grpckit.WithGRPCOptions(grpc.MaxConcurrentStreams(MaxStreams)))
	if o.Log != nil {
		opts = append(opts, grpckit.WithLogger(o.Log))
	}
	for _, r := range refusals {
		opts = append(opts, grpckit.WithErrorCode(r.err.Code, r.code))
	}
	srv := grpckit.NewServer(opts...)
	localapiv1.RegisterLocalServiceServer(srv, &server{node: o.Node, logs: o.Logs, version: o.Version, policy: p, shutdown: shutdown.Done()})
	return srv
}

type server struct {
	localapiv1.UnimplementedLocalServiceServer
	node     Node
	logs     *logring.Ring
	version  string
	policy   Policy
	shutdown <-chan struct{}

	// The status watchers share: taken at most once per
	// minWatchInterval, however many watch.
	mu       sync.Mutex
	shared   *localapiv1.Status
	sharedAt time.Time
}

// sharedStatus is the node's status as of at most minWatchInterval ago.
// The message is shared: nobody may change it.
func (s *server) sharedStatus() *localapiv1.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shared == nil || time.Since(s.sharedAt) >= minWatchInterval {
		s.shared, s.sharedAt = statusProto(s.node.Status()), time.Now()
	}
	return s.shared
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
		if err := stream.Send(&localapiv1.WatchStatusResponse{Status: s.sharedStatus()}); err != nil {
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

// nodeError is what a client is told of a node's refusal or failure: a
// failed start only by its step, whose detail went to the node's log.
func nodeError(err error) error {
	var se *agent.StartError
	switch {
	case errors.Is(err, agent.ErrServerMode):
		return ErrServerMode
	case errors.Is(err, agent.ErrNotRunning):
		return ErrNotRunning
	case errors.Is(err, agent.ErrUnknownPreset):
		return ErrUnknownPreset
	case errors.Is(err, agent.ErrPresetUnavailable):
		return ErrPresetUnavailable
	case errors.Is(err, agent.ErrDNSUnprotected):
		return ErrDNSUnprotected
	case errors.As(err, &se):
		return startFailed(se.Step)
	}
	return err
}

func (s *server) ListSpaces(context.Context, *localapiv1.ListSpacesRequest) (*localapiv1.ListSpacesResponse, error) {
	// One space per node until a device enrolls in several (D9, TP-049).
	return &localapiv1.ListSpacesResponse{Spaces: []*localapiv1.Space{{Id: s.node.Status().Space.String(), Active: true}}}, nil
}

func (s *server) SetRulePreset(ctx context.Context, req *localapiv1.SetRulePresetRequest) (*localapiv1.SetRulePresetResponse, error) {
	if err := s.node.SetRulePreset(ctx, req.GetPreset()); err != nil {
		return nil, nodeError(err)
	}
	return &localapiv1.SetRulePresetResponse{Status: statusProto(s.node.Status())}, nil
}

func (s *server) TailLogs(req *localapiv1.TailLogsRequest, stream grpc.ServerStreamingServer[localapiv1.TailLogsResponse]) error {
	// Through uint64, so the count stays positive where int is 32 bits.
	n := int(min(uint64(req.GetLines()), math.MaxInt32))
	if n == 0 {
		n = 100
	}
	lines, next, _ := s.logs.Since(0)
	lines = lines[len(lines)-min(n, len(lines)):]
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
