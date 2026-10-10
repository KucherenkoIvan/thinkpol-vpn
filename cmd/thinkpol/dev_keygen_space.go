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
		path:    "dev keygen space",
		args:    "[-out dir]",
		summary: "development tooling: make a space's id, signing and recovery keys",
		run:     runDevKeygenSpace,
	})
}

func runDevKeygenSpace(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev keygen space", flag.ContinueOnError)
	dir := fs.String("out", "keys", "key directory to write space.key, recovery.key and space.pub into")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	k, err := devmap.NewSpaceKeys(nil)
	if err != nil {
		return err
	}
	if err := devmap.WriteSpaceKeys(*dir, k); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.stdout, "space %v\n  %s  signing key (private)\n  %s  recovery key (private, keep it offline)\n  %s  public keys, for every node\n",
		k.ID, filepath.Join(*dir, devmap.SpaceKeyFile), filepath.Join(*dir, devmap.RecoveryKeyFile), filepath.Join(*dir, devmap.TrustFile))
	return err
}
