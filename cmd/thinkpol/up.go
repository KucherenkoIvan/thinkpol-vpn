package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
		args:        "[-state dir] [-map file] [-mode device|server] [flags]",
		summary:     "run this node from the keys and map in its state directory (settings: flags, THINKPOL_*, node.json)",
		ownsSignals: true,
		run:         runUp,
	})
}

// crashTracePath is the device's crash trace file (a test's own).
var crashTracePath = agent.CrashTracePath

func runUp(ctx context.Context, e env, args []string) error {
	// First: under a device's service stderr is the crash trace file,
	// holding the previous run's trace until the node has it.
	errFile, _ := e.stderr.(*os.File)
	trace, err := agent.TakeCrashTrace(crashTracePath(), errFile)
	if err != nil {
		return err
	}
	cfg, err := upConfig(e, args)
	if derr := trace.KeepOnlyOnADevice(cfg); derr != nil {
		// derr decides the exit: -h (0) or a usage error (64) would hide
		// it, exiting as if the trace were kept.
		if err == nil || errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsagePrinted) || errors.Is(err, errUsage) {
			return derr
		}
		return fmt.Errorf("%w; and %v", derr, err)
	}
	if err != nil {
		// The node file is read from the state directory, up's input.
		return inputAt(err, nil, []string{cfg.StateDir})
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
		// Prepare reads the state directory and the map first: up's
		// named inputs.
		return inputAt(err, []string{cfg.MapPath()}, []string{cfg.StateDir})
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

// upConfig is up's configuration: the environment's, the flags' and the
// node file's, validated; the zero Config when the environment's can't be
// read.
func upConfig(e env, args []string) (agent.Config, error) {
	if err := agent.CheckEnvironment(); err != nil {
		return agent.Config{}, err
	}
	cfg, err := agent.LoadConfig()
	if err != nil {
		return cfg, err
	}
	agent.ApplyOSDefaults(&cfg)
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	if err := config.BindFlags(fs, &cfg); err != nil {
		return cfg, err
	}
	if err := parseFlags(fs, e, args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, errUsage
	}
	if err := agent.ApplyNodeFile(&cfg, fs); err != nil {
		return cfg, err
	}
	return cfg, config.Validate(&cfg)
}
