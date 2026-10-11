package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "rules preset",
		args:    "[-socket path] <everything|all-but-domestic>",
		summary: "switch this device's routing rules to a preset",
		run:     runRulesPreset,
	})
}

func runRulesPreset(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("rules preset", flag.ContinueOnError)
	socket := fs.String("socket", agent.APISocket(), "the local API's socket (THINKPOL_API_SOCKET)")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}
	c, err := localapi.Dial(*socket)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return c.SetRulePreset(ctx, fs.Arg(0))
}
