package main

import (
	"context"
	"time"

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
	cmd := newAPICommand("connect")
	c, err := cmd.dial(e, args, noArgs)
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
