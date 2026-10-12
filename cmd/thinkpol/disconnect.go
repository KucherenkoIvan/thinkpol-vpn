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
		path:    "disconnect",
		args:    "[-socket path]",
		summary: "disconnect this device: take its data plane down (the service keeps running)",
		run:     runDisconnect,
	})
}

func runDisconnect(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("disconnect", flag.ContinueOnError)
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
	st, err := c.Disconnect(ctx)
	if err != nil {
		return err
	}
	return localapi.WriteStatus(e.stdout, st, time.Now())
}
