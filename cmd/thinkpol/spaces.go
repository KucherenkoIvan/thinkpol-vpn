package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
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
	fs := flag.NewFlagSet("spaces", flag.ContinueOnError)
	socket := fs.String("socket", agent.APISocket(), "the local API's socket (THINKPOL_API_SOCKET)")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	c, err := localapi.Dial(*socket)
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
