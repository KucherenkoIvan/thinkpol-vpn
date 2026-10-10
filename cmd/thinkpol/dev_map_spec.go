package main

import (
	"context"
	"flag"
	"io"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
)

func init() {
	register(command{
		path:    "dev map spec",
		summary: "development tooling: print the map spec format, annotated",
		run:     runDevMapSpec,
	})
}

func runDevMapSpec(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev map spec", flag.ContinueOnError)
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	_, err := io.WriteString(e.stdout, devmap.Reference)
	return err
}
