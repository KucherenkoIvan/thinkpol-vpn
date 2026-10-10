package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
)

func init() {
	register(command{
		path:    "dev keygen node",
		args:    "[-out dir] <name>...",
		summary: "development tooling: make nodes' ids, map and WireGuard keys",
		run:     runDevKeygenNode,
	})
}

func runDevKeygenNode(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev keygen node", flag.ContinueOnError)
	dir := fs.String("out", "keys", "key directory to write <name>.key and <name>.pub into")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errUsage
	}
	keys, err := devmap.GenerateNodes(*dir, fs.Args())
	if err != nil {
		return err
	}
	for i, name := range fs.Args() {
		if _, err := fmt.Fprintf(e.stdout, "node %s, id %v\n  %s  private, for %s only\n  %s  public, for the map builder\n",
			name, keys[i].ID, filepath.Join(*dir, devmap.NodeKeyFile(name)), name, filepath.Join(*dir, devmap.NodePublicFile(name))); err != nil {
			return err
		}
	}
	return nil
}
