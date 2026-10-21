package main

import (
	"context"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "spaces",
		args:    "[-socket path]",
		summary: "list the spaces this node is enrolled in",
		run:     runSpaces,
	})
}

func runSpaces(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("spaces")
	c, err := cmd.dial(e, args, noArgs)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	spaces, err := c.Spaces(ctx)
	if err != nil {
		return err
	}
	return localapi.WriteSpaces(e.stdout, spaces)
}
