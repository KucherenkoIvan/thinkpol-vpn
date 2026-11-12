package main

import (
	"context"
	"fmt"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "allow-lan",
		args:    "[-socket path] [on|off]",
		summary: "show or set whether the kill switch lets the LAN out: private and link-local addresses, local multicast; not its DNS while the tunnel is down (off by default; at once)",
		run:     runAllowLAN,
	})
}

func runAllowLAN(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("allow-lan")
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
		_, err = fmt.Fprintf(e.stdout, "allow-lan: %s\n", onOff(k.GetAllowLan()))
		return err
	}
	st, err := c.SetAllowLAN(ctx, cmd.Arg(0) == "on")
	if err != nil {
		return err
	}
	return localapi.WriteStatus(e.stdout, st, time.Now())
}
