package main

import (
	"context"
	"errors"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path: "diag",
		args: "[-socket path] [-o file|-]",
		summary: "print a JSON snapshot of what the node changed on the host (root's names entry and other public addresses); " +
			"with no agent answering, root's reads the host itself (agent: not_running, exit 0; not_answering, exit 69)",
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
	d, err := localapi.DiagnoseOrReadHost(ctx, *cmd.socket, localapi.DiagnoseWait, readHost, resolveVersion())
	if d == nil {
		return err
	}
	if *out != "-" && *out != "" {
		return errors.Join(err, localapi.WriteDiagnosticsFile(*out, d))
	}
	return errors.Join(err, localapi.WriteDiagnostics(e.stdout, d))
}

// readHost is the host's snapshot without the agent, read with the
// readers the agent's own platform uses.
func readHost(ctx context.Context, presence agent.AgentPresence) (agent.Diagnostics, error) {
	return agent.DiagnoseHost(ctx, platform().Inspect, presence, agent.CrashTracePath())
}
