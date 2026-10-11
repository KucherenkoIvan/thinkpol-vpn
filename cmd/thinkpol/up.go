package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

func init() {
	register(command{
		path:    "up",
		args:    "[-state dir] [-map file] [-mode auto|device|server] [flags]",
		summary: "run this node from the keys and map in its state directory (environment: THINKPOL_*)",
		run:     runUp,
	})
}

func runUp(ctx context.Context, e env, args []string) error {
	cfg, err := agent.LoadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.StringVar(&cfg.StateDir, "state", cfg.StateDir, "state directory: node.key, space.pub and map.bin (THINKPOL_STATE_DIR)")
	fs.StringVar(&cfg.MapFile, "map", cfg.MapFile, "the map file, if not map.bin in the state directory (THINKPOL_MAP)")
	mode := fs.String("mode", string(cfg.Mode), "auto (by the node's kind in the map), device or server (THINKPOL_MODE)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug, info, warn or error; logs go to stderr only (THINKPOL_LOG_LEVEL)")
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "the overlay TUN's name (THINKPOL_INTERFACE)")
	fs.IntVar(&cfg.LinkMTU, "link-mtu", cfg.LinkMTU, "MTU of the network under the links (THINKPOL_LINK_MTU)")
	fs.DurationVar(&cfg.MapPoll, "map-poll", cfg.MapPoll, "how often to check the map file for a change; SIGHUP checks at once (THINKPOL_MAP_POLL)")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	cfg.Mode = agent.Mode(*mode)
	if err := cfg.Check(); err != nil {
		return err
	}
	logs, err := agent.NewLogs(cfg.LogLevel, e.stderr)
	if err != nil {
		return err
	}
	// go-kernel's app logs through the default logger.
	slog.SetDefault(logs.Logger)
	node, err := agent.Prepare(cfg, logs)
	if err != nil {
		return err
	}
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	return node.Run(ctx, reload)
}
