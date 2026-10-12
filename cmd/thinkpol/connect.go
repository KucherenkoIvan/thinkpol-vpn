package main

import (
	"context"
	"flag"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "connect",
		args:    "[-socket path]",
		summary: "connect this device: bring its data plane up on the latest map",
		run:     runConnect,
	})
}

func runConnect(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
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
	st, err := c.Connect(ctx)
	if err != nil {
		return err
	}
	return localapi.WriteStatus(e.stdout, st, time.Now())
}
