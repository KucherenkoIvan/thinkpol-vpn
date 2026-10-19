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
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	socket := fs.String("socket", apiSocket(), "the local API's socket (THINKPOL_API_SOCKET)")
	lines := fs.Int("n", 100, "how many of the last lines to print")
	follow := fs.Bool("f", false, "keep printing new lines until interrupted")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *lines < 1 {
		return errUsage
	}
	c, err := localapi.Dial(*socket)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return c.TailLogs(ctx, *lines, *follow, func(lines []string, missed uint64) error {
		return localapi.WriteLogLines(e.stdout, lines, missed)
	})
}
