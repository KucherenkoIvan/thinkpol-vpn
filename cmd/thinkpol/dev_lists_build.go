package main

import (
	"context"
	"flag"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

func init() {
	register(command{
		path:    "dev lists build",
		args:    "[-format v2fly|dbip] [-only ru,by] [-out dir] <source>",
		summary: "development tooling: build GeoIP list blobs (<out>/<name>.geoip) from a local v2fly geoip.dat or DB-IP Lite CSV; prints the source's attribution",
		run:     runDevListsBuild,
	})
}

// runDevListsBuild builds the lists (lists.BuildFile) and prints their
// table and the source's attribution (lists.WriteReport).
func runDevListsBuild(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("dev lists build", flag.ContinueOnError)
	format := fs.String("format", "", "source format, v2fly or dbip (default: from the file name, *.dat or *.csv, optionally .gz)")
	only := fs.String("only", "", "comma-separated list names to build, e.g. ru,by (default: every list in the source)")
	out := fs.String("out", ".", "directory to write the blobs to")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}
	var names []string
	if *only != "" {
		names = strings.Split(strings.ToLower(*only), ",")
	}
	f, built, err := lists.BuildFile(fs.Arg(0), lists.Format(*format), names, *out)
	if err != nil {
		return err
	}
	return lists.WriteReport(e.stdout, e.stderr, f, built)
}
