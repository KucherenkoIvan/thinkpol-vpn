package localapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/KucherenkoIvan/go-kernel/grpckit"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// Client is a local API client: the CLI's, later the tray app's. What it
// returns is sanitized (every string disarmed for a terminal) and its
// errors are explained for a person; errors.Is finds ErrPermissionDenied,
// ErrRootOnly, ErrNotRunning, ErrServerMode and the other refusals in them
// ([IsPermission] either of the first two).
type Client struct {
	conn *grpc.ClientConn
	api  localapiv1.LocalServiceClient
	path string
}

// Dial connects to the local API at path. It tries the socket first, so
// that a missing service or a caller without access is told so plainly.
//
// The client doesn't authenticate the server: the socket's directory is
// the trust anchor. Listen keeps it the service user's (root's, as
// installed), writable by that user alone, in a parent no one else can
// write to (ownDir, checkParent), so only the service can have put a
// socket at the default path. Those checks are all that keeps another
// process from posing as the service; they must stay exact. A path given
// by hand is trusted as given.
func Dial(path string) (*Client, error) {
	probe, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, dialError(path, err)
	}
	_ = probe.Close()
	target := "unix:" + path
	if filepath.IsAbs(path) {
		target = "unix://" + path
	}
	conn, err := grpckit.Connect(target)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, api: localapiv1.NewLocalServiceClient(conn), path: path}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Status is the node's status.
func (c *Client) Status(ctx context.Context) (*localapiv1.Status, error) {
	resp, err := c.api.GetStatus(ctx, &localapiv1.GetStatusRequest{})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetStatus(), nil
}

// WatchStatus calls fn with the status every interval (0: the service's
// default) until ctx ends (nil), fn fails, or the service stops.
func (c *Client) WatchStatus(ctx context.Context, interval time.Duration, fn func(*localapiv1.Status) error) error {
	req := &localapiv1.WatchStatusRequest{}
	if interval > 0 {
		req.Interval = durationpb.New(interval)
	}
	stream, err := c.api.WatchStatus(ctx, req)
	if err != nil {
		return c.explain(err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return c.streamEnd(ctx, err)
		}
		if err := fn(sanitized(resp).GetStatus()); err != nil {
			return err
		}
	}
}

// Connect connects the device and returns its status once it is up.
func (c *Client) Connect(ctx context.Context) (*localapiv1.Status, error) {
	resp, err := c.api.Connect(ctx, &localapiv1.ConnectRequest{})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetStatus(), nil
}

// Disconnect disconnects the device and returns its status once it is
// down.
func (c *Client) Disconnect(ctx context.Context) (*localapiv1.Status, error) {
	resp, err := c.api.Disconnect(ctx, &localapiv1.DisconnectRequest{})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetStatus(), nil
}

// Spaces are the spaces the node is enrolled in.
func (c *Client) Spaces(ctx context.Context) ([]*localapiv1.Space, error) {
	resp, err := c.api.ListSpaces(ctx, &localapiv1.ListSpacesRequest{})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetSpaces(), nil
}

// SetRulePreset switches the device's routing rules to preset and
// returns its status.
func (c *Client) SetRulePreset(ctx context.Context, preset string) (*localapiv1.Status, error) {
	resp, err := c.api.SetRulePreset(ctx, &localapiv1.SetRulePresetRequest{Preset: preset})
	if err != nil {
		return nil, c.explain(err)
	}
	return sanitized(resp).GetStatus(), nil
}

// TailLogs calls fn with the agent's last lines (0: the service's
// default), then, when following, with new lines as they come, until ctx
// ends (nil), fn fails, or the service stops. missed counts lines the ring
// dropped before they could be sent.
func (c *Client) TailLogs(ctx context.Context, lines int, follow bool, fn func(lines []string, missed uint64) error) error {
	stream, err := c.api.TailLogs(ctx, &localapiv1.TailLogsRequest{Lines: uint32(min(uint64(max(lines, 0)), math.MaxUint32)), Follow: follow})
	if err != nil {
		return c.explain(err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return c.streamEnd(ctx, err)
		}
		resp = sanitized(resp)
		if err := fn(resp.GetLines(), resp.GetMissed()); err != nil {
			return err
		}
	}
}

// streamEnd is a stream's end: io.EOF or ctx's end is a clean one.
func (c *Client) streamEnd(ctx context.Context, err error) error {
	if errors.Is(err, io.EOF) || ctx.Err() != nil {
		return nil
	}
	return c.explain(err)
}

// clientError is an error explained for a person, wrapping what it is.
type clientError struct {
	msg string
	err error
}

func (e *clientError) Error() string { return e.msg }
func (e *clientError) Unwrap() error { return e.err }

func dialError(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return &clientError{fmt.Sprintf("%s (%s)", refusalMsg(ErrPermissionDenied), path), ErrPermissionDenied}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		return &clientError{fmt.Sprintf("the thinkpol service is not running (nothing listens at %s)", path), ErrNotRunning}
	}
	return fmt.Errorf("connecting to the local API at %s: %w", path, err)
}

// explain turns what a call failed with into something a person can act
// on. Anything the service said is sanitized.
func (c *Client) explain(err error) error {
	if err == nil {
		return nil
	}
	var remote *grpckit.RemoteDomainError
	if errors.As(err, &remote) {
		if step, ok := strings.CutPrefix(remote.Code, startFailedPrefix); ok {
			return &clientError{fmt.Sprintf("starting the data plane failed at step %q; the service's log has the details", agent.Sanitize(step)), ErrStartFailed}
		}
		for _, r := range refusals {
			if remote.Code == r.err.Code {
				return &clientError{r.msg, r.err}
			}
		}
		return fmt.Errorf("refused: %s", agent.Sanitize(remote.Code))
	}
	if st, ok := status.FromError(err); ok {
		return fmt.Errorf("%s: %s", st.Code(), agent.Sanitize(st.Message()))
	}
	return err
}
