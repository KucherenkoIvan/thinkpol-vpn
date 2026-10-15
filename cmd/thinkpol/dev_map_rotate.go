package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func init() {
	register(command{
		path:    "dev map rotate",
		args:    "[-keys dir] [-out file] <spec.yaml>",
		summary: "development tooling: rebuild the deployed map with fresh link credentials and a version past it",
		run:     runDevMapRotate,
	})
}

// Rotating is the pre-controller way to change a running network: the spec
// is rebuilt with fresh link secrets and a version past the map the nodes
// hold, so they take it. Copying the file to the nodes is the runbook's
// (docs/runbook-pre-controller.md); the controller publishes maps from M4.
func runDevMapRotate(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev map rotate", flag.ContinueOnError)
	dir := fs.String("keys", "keys", "key directory: space.key, space.pub and <name>.pub for every node")
	out := fs.String("out", "map.bin", "file to rotate: the deployed map is read from it and the next one written to it")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	spec, err := devmap.ParseSpec(fs.Arg(0), data, os.LookupEnv)
	if err != nil {
		return err
	}
	if err := devmap.ReadLists(spec, os.ReadFile); err != nil {
		return err
	}
	keys, err := devmap.LoadKeys(*dir, spec)
	if err != nil {
		return err
	}
	previous, err := os.ReadFile(*out)
	if err != nil {
		return fmt.Errorf("%s: %w; a rotation replaces a deployed map, the first build is dev map build", *out, err)
	}
	if _, err := netmap.Verify(previous, keys.Trust()); err != nil {
		return fmt.Errorf("%s is not a valid map of space %v: %w", *out, keys.Space, err)
	}
	// The version past the deployed map makes nodes take the rotation; the
	// fresh secrets (nil: crypto/rand) are what rotates every link's
	// credential.
	version := devmap.NextVersion(time.Now(), previous, keys.Trust())
	env, err := devmap.Build(spec, keys, version, nil)
	if err != nil {
		return err
	}
	if err := devmap.WriteMap(*out, env); err != nil {
		return err
	}
	names := make([]string, len(spec.Nodes))
	for i, n := range spec.Nodes {
		names[i] = n.Name
	}
	_, err = fmt.Fprintf(e.stdout,
		"map version %d of space %v: %d nodes, %d bytes, written to %s\nrotate: copy %s to every node's map file; every node takes the same file, within its map poll or on SIGHUP: %s\n",
		version, keys.Space, len(spec.Nodes), len(env), *out, *out, strings.Join(names, ", "))
	return err
}