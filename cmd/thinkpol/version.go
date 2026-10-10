package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is set at link time by `make build`
// (-ldflags "-X main.version=..."); otherwise it comes from the build info.
var version string

func init() {
	register(command{path: "version", summary: "print the version", run: runVersion})
}

func runVersion(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errUsage
	}
	_, err := fmt.Fprintf(e.stdout, "thinkpol %s %s %s/%s\n", resolveVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return err
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	// `go build` stamps a version derived from the VCS; `go run` and
	// `go test` report "(devel)" or nothing.
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
