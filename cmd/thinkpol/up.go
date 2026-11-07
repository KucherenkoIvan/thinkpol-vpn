package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/KucherenkoIvan/go-kernel/app"
	"github.com/KucherenkoIvan/go-kernel/config"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

func init() {
	register(command{
		path:        "up",
		args:        "[-state dir] [-map file] [-mode auto|device|server] [flags]",
		summary:     "run this node from the keys and map in its state directory (settings: flags, THINKPOL_*, node.json)",
		ownsSignals: true,
		run:         runUp,
	})
}

func runUp(ctx context.Context, e env, args []string) error {
	// First: under a device's service stderr is the crash trace file,
	// holding the previous run's trace until the node has it.
	errFile, _ := e.stderr.(*os.File)
	trace, err := agent.TakeCrashTrace(agent.CrashTracePath(), errFile)
	if err != nil {
		return err
	}
	if err := agent.CheckEnvironment(); err != nil {
		return err
	}
	cfg, err := agent.LoadConfig()
	if err != nil {
		return err
	}
	agent.ApplyOSDefaults(&cfg)
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	if err := config.BindFlags(fs, &cfg); err != nil {
		return err
	}
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	if err := agent.ApplyNodeFile(&cfg, fs); err != nil {
		return err
	}
	if err := config.Validate(&cfg); err != nil {
		return err
	}
	logs, err := agent.NewLogs(cfg.LogLevel, trace.LogOutput(e.stderr, cfg.Service))
	if err != nil {
		return err
	}
	// What logs through slog's default (nsthread) or grpc's reaches the
	// node's log too.
	slog.SetDefault(logs.Logger)
	localapi.RouteGRPCLog(logs.Logger)
	node, err := agent.Prepare(cfg, logs, platform())
	if err != nil {
		return err
	}
	if err := node.KeepLastRun(trace); err != nil {
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
			Log: logs.With("component", "local API"), Version: resolveVersion(),
		}))
	}
	return agent.CleanStop(app.RunWith(ctx, app.Options{Logger: logs.Logger}, adapters...))
}
