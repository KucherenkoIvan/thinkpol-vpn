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
		args:    "[-out dir] [-recovery-out dir]",
		summary: "development tooling: make a space's id, IPv6 network, signing and recovery keys",
		run:     runDevKeygenSpace,
	})
}

func runDevKeygenSpace(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev keygen space", flag.ContinueOnError)
	dir := fs.String("out", "keys", "key directory to write space.key and space.pub into")
	recoveryDir := fs.String("recovery-out", "", "directory for recovery.key, e.g. removable media to keep offline (default: -out)")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	if *recoveryDir == "" {
		*recoveryDir = *dir
	}
	k, err := devmap.GenerateSpace(*dir, *recoveryDir)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.stdout, "space %v, IPv6 %v\n  %s  signing key (private)\n  %s  public keys, for every node\n  %s  recovery key (private): move it offline, nothing here needs it\n",
		k.ID, k.IPv6Network, filepath.Join(*dir, devmap.SpaceKeyFile), filepath.Join(*dir, devmap.TrustFile), filepath.Join(*recoveryDir, devmap.RecoveryKeyFile))
	return err
}
