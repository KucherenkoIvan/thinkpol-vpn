package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/KucherenkoIvan/go-kernel/app"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
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
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "the overlay TUN's name; empty: the platform's default (THINKPOL_INTERFACE)")
	fs.IntVar(&cfg.LinkMTU, "link-mtu", cfg.LinkMTU, "MTU of the network under the links; 0: 1500 (THINKPOL_LINK_MTU)")
	fs.DurationVar(&cfg.MapPoll, "map-poll", cfg.MapPoll, "how often to check the map file for a change; SIGHUP checks at once (THINKPOL_MAP_POLL)")
	fs.BoolVar(&cfg.Connect, "connect", cfg.Connect, "a device connects when it starts; otherwise it waits for thinkpol connect (THINKPOL_CONNECT)")
	fs.StringVar(&cfg.APISocket, "api-socket", cfg.APISocket, "the local API's socket, in a directory of its own; empty: no local API (THINKPOL_API_SOCKET)")
	fs.StringVar(&cfg.APIGroup, "api-group", cfg.APIGroup, "the group whose members may use the local API besides root (THINKPOL_API_GROUP)")
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
	adapters, err := node.Adapters(reload)
	if err != nil {
		return err
	}
	if cfg.APISocket != "" {
		adapters = append(adapters, localapi.Adapter(localapi.Options{
			Socket: cfg.APISocket, Group: cfg.APIGroup, Node: node, Logs: logs.Ring,
			Log: logs.With("component", "local API"),
		}))
	}
	return app.Run(ctx, adapters...)
}
