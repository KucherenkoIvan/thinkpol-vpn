package main

import (
	"context"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "rules preset",
		args:    "[-socket path] <space|everything|all-but-domestic>",
		summary: "switch this device's routing rules to a preset",
		run:     runRulesPreset,
	})
}

func runRulesPreset(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("rules preset")
	c, err := cmd.dial(e, args, oneArg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	st, err := c.SetRulePreset(ctx, cmd.Arg(0))
	if err != nil {
		return err
	}
	return localapi.WriteStatus(e.stdout, st, time.Now())
}
