package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path: "diag",
		args: "[-socket path] [-o file|-]",
		summary: "print a JSON snapshot of what the node changed on the host (root's names entry and other public addresses); " +
			"with no agent answering, root's reads the host itself (exit 0 with none running; 69 with one holding the socket silent, or coming up during the read)",
		run: runDiag,
	})
}

func runDiag(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("diag")
	out := cmd.String("o", "-", "write the snapshot to this file, mode 0600 (- prints it)")
	if err := parseFlags(cmd.FlagSet, e, args); err != nil {
		return err
	}
	if !noArgs(cmd.FlagSet) {
		return errUsage
	}
	d, err := localapi.DiagnoseOrReadHost(ctx, *cmd.socket, diagWait, diagReadHost, resolveVersion(), e.stderr)
	if d == nil {
		return err
	}
	var werr error
	if *out != "-" && *out != "" {
		werr = localapi.WriteDiagnosticsFile(*out, d)
	} else {
		werr = localapi.WriteDiagnostics(e.stdout, d)
	}
	if werr != nil && err != nil {
		// The snapshot didn't get out: that is the failure (1), with
		// the agent's silence only said, not exited by.
		return fmt.Errorf("%w (and %v)", werr, err)
	}
	return errors.Join(err, werr)
}

// diagWait and diagReadHost are diag's, tests' to replace.
var (
	diagWait                         = localapi.DiagnoseWait
	diagReadHost localapi.HostReader = readHost
)

// readHost is the host's snapshot without the agent, read with the
// readers the agent's own platform uses.
func readHost(ctx context.Context, presence agent.AgentPresence) (agent.Diagnostics, error) {
	return agent.DiagnoseHost(ctx, platform().Inspect, presence, agent.CrashTracePath())
}
