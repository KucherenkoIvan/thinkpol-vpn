package main

import (
	"context"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "diag",
		args:    "[-socket path] [-o file]",
		summary: "print a JSON snapshot of what the node changed on the host (root sees all of it)",
		run:     runDiag,
	})
}

func runDiag(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("diag")
	out := cmd.String("o", "", "write the snapshot to this file, mode 0600, instead of printing it")
	c, err := cmd.dial(e, args, noArgs)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	d, err := c.Diagnose(ctx)
	if err != nil {
		return err
	}
	if *out != "" {
		return localapi.WriteJSONFile(*out, d)
	}
	return localapi.WriteJSON(e.stdout, d)
}
