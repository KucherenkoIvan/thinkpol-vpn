package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

func init() {
	register(command{
		path:    "service uninstall",
		summary: "stop the service and remove it, its binary and its group (the node's keys and map stay); as root",
		run:     runServiceUninstall,
	})
}

func runServiceUninstall(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ContinueOnError)
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	if err := service.CheckRoot(); err != nil {
		return err
	}
	in, err := service.HostInstaller(e.stdout, platform())
	if err != nil {
		return err
	}
	return in.Uninstall(ctx)
}
