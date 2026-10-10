package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func init() {
	register(command{
		path:    "dev map inspect",
		args:    "[-keys dir] [-node-key file] <map.bin>",
		summary: "development tooling: verify a map and print its header, and a node's section",
		run:     runDevMapInspect,
	})
}

func runDevMapInspect(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev map inspect", flag.ContinueOnError)
	dir := fs.String("keys", "keys", "key directory: the map is verified against its space.pub, and its <name>.pub files name node ids")
	nodeKey := fs.String("node-key", "", "a node's <name>.key: print the section sealed to it")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}
	trust, err := devmap.ReadTrust(filepath.Join(*dir, devmap.TrustFile))
	if err != nil {
		return err
	}
	env, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := netmap.Verify(env, trust)
	if err != nil {
		return fmt.Errorf("%s is not a valid map of space %v: %w", fs.Arg(0), trust.SpaceID, err)
	}
	if _, err := fmt.Fprintf(e.stdout, "valid map, signed by the space key in %s\n", filepath.Join(*dir, devmap.TrustFile)); err != nil {
		return err
	}
	if err := devmap.DescribeHeader(e.stdout, m); err != nil {
		return err
	}
	if *nodeKey == "" {
		return nil
	}
	key, err := devmap.ReadNodeKey(*nodeKey)
	if err != nil {
		return err
	}
	section, err := m.Open(key.Map)
	if err != nil {
		return fmt.Errorf("%s: %w", *nodeKey, err)
	}
	names, err := devmap.ReadNames(*dir, trust.SpaceID)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(e.stdout, "\nsection for %s\n", *nodeKey); err != nil {
		return err
	}
	return devmap.DescribeSection(e.stdout, section, names)
}
