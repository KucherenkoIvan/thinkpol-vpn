package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func init() {
	register(command{
		path:    "worker",
		args:    "-space <id>",
		summary: "run one space's worker (started by the supervisor, never by hand)",
		hidden:  true,
		run:     runWorker,
	})
}

func runWorker(ctx context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	space := fs.String("space", "", "the space's id, hex")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *space == "" {
		return errUsage
	}
	id, err := netmap.ParseSpaceID(*space)
	if err != nil {
		return err
	}
	// The worker's stderr goes to the supervisor's in-memory ring for its
	// space. TP-011 replaces Idle with the space's data plane.
	return worker.Run(ctx, id, worker.Idle)
}
