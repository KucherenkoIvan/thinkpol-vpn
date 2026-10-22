package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

func init() {
	register(command{
		path:    "service connect-on-boot",
		args:    "[on|off]",
		summary: "show or set whether the service connects this device at boot (off by default); setting it needs root",
		run:     runServiceConnectOnBoot,
	})
}

func runServiceConnectOnBoot(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("service connect-on-boot", flag.ContinueOnError)
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	in, err := service.HostInstaller(e.stdout)
	if err != nil {
		return err
	}
	switch {
	case fs.NArg() == 0:
		on, err := in.ConnectOnBoot()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(e.stdout, "connect-on-boot: %s\n", service.OnOff(on))
		return err
	case fs.NArg() == 1 && (fs.Arg(0) == service.OnOff(true) || fs.Arg(0) == service.OnOff(false)):
		if err := service.CheckRoot(); err != nil {
			return err
		}
		return in.SetConnectOnBoot(ctx, fs.Arg(0) == service.OnOff(true))
	}
	return errUsage
}
