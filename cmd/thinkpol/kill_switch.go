package main

import (
	"context"
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "kill-switch",
		args:    "[-socket path] [on|off]",
		summary: "show or set the kill switch: while it is on and the tunnel is down, nothing leaves but traffic to the entries (off by default; at once); " + agent.KillSwitchStopNote,
		run:     runKillSwitch,
	})
}

func runKillSwitch(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("kill-switch")
	c, err := cmd.dial(e, args, onOffArgs)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if cmd.NArg() == 0 {
		k, err := c.KillSwitch(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(e.stdout, "kill-switch: %s\n", localapi.KillSwitchText(k))
		return err
	}
	st, err := c.SetKillSwitch(ctx, cmd.Arg(0) == "on")
	return printOutcome(ctx, e, c, st, err)
}
