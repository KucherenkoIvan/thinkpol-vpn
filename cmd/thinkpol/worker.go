package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
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
	// The supervisor passes THINKPOL_LOG_LEVEL; the worker's stderr goes to
	// its space's in-memory ring and the node's log stream.
	cfg, err := agent.LoadConfig()
	if err != nil {
		return err
	}
	logs, err := agent.NewLogs(cfg.LogLevel, e.stderr)
	if err != nil {
		return err
	}
	return worker.Run(ctx, id, agent.Worker(logs.Logger))
}
