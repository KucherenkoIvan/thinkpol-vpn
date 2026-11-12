package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

func init() {
	register(command{
		path:    "rollback",
		summary: "after an agent died: remove what it left on this host (routes, leak guard, DNS changes, the kill switch) and record this boot disconnected; as root, refused while an agent runs",
		run:     runRollback,
	})
}

func runRollback(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	if os.Geteuid() != 0 {
		return errors.New("rollback changes the host's routing, firewall and resolvers: run it as root (sudo)")
	}
	r, err := agent.Rollback(platform())
	if werr := r.Write(e.stdout); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}
