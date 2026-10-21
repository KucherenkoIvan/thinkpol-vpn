package main

import (
	"context"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:    "logs",
		args:    "[-socket path] [-n lines] [-f]",
		summary: "print the running node's in-memory log (root only)",
		run:     runLogs,
	})
}

func runLogs(ctx context.Context, e env, args []string) error {
	cmd := newAPICommand("logs")
	lines := cmd.Int("n", 100, "how many of the last lines to print")
	follow := cmd.Bool("f", false, "keep printing new lines until interrupted")
	c, err := cmd.dial(e, args, func(fs *flag.FlagSet) bool { return fs.NArg() == 0 && *lines >= 1 })
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return c.TailLogs(ctx, *lines, *follow, func(lines []string, missed uint64) error {
		return localapi.WriteLogLines(e.stdout, lines, missed)
	})
}
