package main

import (
	"context"
	"errors"
	"flag"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

func init() {
	register(command{
		path:    "rollback",
		summary: "after an agent died: remove what it left on this host (routes, leak guard, DNS changes, the kill switch) and record this boot disconnected; as root, refused (exit 75) while another thinkpol process holds the host",
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
	r, err := agent.Rollback(platform(), agent.DefaultStateDir)
	if errors.Is(err, agent.ErrAnotherAgent) {
		err = tempFailError{err}
	}
	if perr := r.Print(e.stdout); perr != nil {
		return errors.Join(err, perr)
	}
	return err
}
