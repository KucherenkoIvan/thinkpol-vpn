package main

import (
	"context"
	"flag"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

func init() {
	register(command{
		path:    "status",
		args:    "[-socket path] [-json] [-watch] [-interval d]",
		summary: "show the running node's state: connection, space, health, peers",
		run:     runStatus,
	})
}

func runStatus(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := fs.String("socket", agent.APISocket(), "the local API's socket (THINKPOL_API_SOCKET)")
	asJSON := fs.Bool("json", false, "print the status as JSON")
	watch := fs.Bool("watch", false, "keep printing the status until interrupted")
	interval := fs.Duration("interval", time.Second, "with -watch, how often")
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
	write := func(st *localapiv1.Status) error {
		if *asJSON {
			return localapi.WriteJSON(e.stdout, st)
		}
		return localapi.WriteStatus(e.stdout, st, time.Now())
	}
	if *watch {
		first := true
		return c.WatchStatus(ctx, *interval, func(st *localapiv1.Status) error {
			if !first && !*asJSON {
				if _, err := e.stdout.Write([]byte("\n")); err != nil {
					return err
				}
			}
			first = false
			return write(st)
		})
	}
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	return write(st)
}
