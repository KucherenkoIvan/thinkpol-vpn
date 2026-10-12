package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
)

func init() {
	register(command{
		path:    "dev map build",
		args:    "[-keys dir] [-out file] [-version n] [-secrets-seed s] <spec.yaml>",
		summary: "development tooling: build and sign a map from a spec (format: dev map spec)",
		run:     runDevMapBuild,
	})
}

func runDevMapBuild(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev map build", flag.ContinueOnError)
	dir := fs.String("keys", "keys", "key directory: space.key, space.pub and <name>.pub for every node")
	out := fs.String("out", "map.bin", "file to write the signed map to")
	version := fs.Uint64("version", 0, "map version (default: the current Unix time, or one past the map in -out if that is higher)")
	seed := fs.String("secrets-seed", "", "derive the link secrets from this seed instead of at random, so builds of one spec share them (lab tests only: the seed gives away every link)")
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
	if *version == 0 {
		previous, _ := os.ReadFile(*out) // a missing or foreign map just doesn't count
		*version = devmap.NextVersion(time.Now(), previous, keys.Trust())
	}
	var random io.Reader // crypto/rand
	if *seed != "" {
		random = devmap.SeededSecrets(*seed)
	}
	env, err := devmap.Build(spec, keys, *version, random)
	if err != nil {
		return err
	}
	if err := devmap.WriteMap(*out, env); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.stdout, "map version %d of space %v: %d nodes, %d bytes, written to %s\n", *version, keys.Space, len(spec.Nodes), len(env), *out)
	return err
}
