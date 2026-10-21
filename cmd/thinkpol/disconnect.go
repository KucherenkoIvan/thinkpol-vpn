package main

import (
	"context"
	"time"

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
	cmd := newAPICommand("disconnect")
	c, err := cmd.dial(e, args, noArgs)
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
