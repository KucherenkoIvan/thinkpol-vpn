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
		summary: "development tooling: make nodes' map and WireGuard keys",
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
	for _, name := range fs.Args() {
		if err := devmap.CheckName(name); err != nil {
			return err
		}
	}
	for _, name := range fs.Args() {
		k, err := devmap.NewNodeKey(nil)
		if err != nil {
			return err
		}
		if err := devmap.WriteNodeKey(*dir, name, k); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(e.stdout, "node %s\n  %s  private, for %s only\n  %s  public, for the map builder\n",
			name, filepath.Join(*dir, devmap.NodeKeyFile(name)), name, filepath.Join(*dir, devmap.NodePublicFile(name))); err != nil {
			return err
		}
	}
	return nil
}
