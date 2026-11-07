package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "connect-on-boot",
		args:    "[-socket path] [on|off]",
		summary: "show or set whether the service connects this device at boot (off by default; from the next boot)",
		run:     runConnectOnBoot,
	})
}

func runConnectOnBoot(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("connect-on-boot")
	c, err := cmd.dial(e, args, func(fs *flag.FlagSet) bool {
		return fs.NArg() == 0 || fs.NArg() == 1 && (fs.Arg(0) == "on" || fs.Arg(0) == "off")
	})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if cmd.NArg() == 0 {
		on, err := c.ConnectOnBoot(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(e.stdout, "connect-on-boot: %s\n", onOff(on))
		return err
	}
	st, err := c.SetConnectOnBoot(ctx, cmd.Arg(0) == "on")
	if err != nil {
		return err
	}
	return localapi.WriteStatus(e.stdout, st, time.Now())
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
