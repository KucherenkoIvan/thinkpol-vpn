package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

func init() {
	register(command{
		path:    "service install",
		args:    "[-connect-on-boot] [-user name]",
		summary: "run this node as a service (systemd, launchd), started at boot; as root",
		run:     runServiceInstall,
	})
}

func runServiceInstall(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	connect := fs.Bool("connect-on-boot", false, "connect at boot; unset: as installed, else off")
	user := fs.String("user", service.InstallingUser(), "added to the thinkpol group, which may use the local API; empty: no one")
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
	opts := service.Options{User: *user}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "connect-on-boot" {
			opts.ConnectOnBoot = connect
		}
	})
	return in.Install(ctx, opts)
}
