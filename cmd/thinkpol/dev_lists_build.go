package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

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

// runDevListsBuild never downloads: the source is a file the operator fetched
// and whose license they keep; the attribution it asks for is printed under
// the table. The table is the evidence for a list's blob: SHA-256, size, and
// entries in (prefixes, or DB-IP's ranges) against prefixes out.
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
	source := fs.Arg(0)

	f := lists.Format(*format)
	if f == "" {
		var err error
		if f, err = lists.FormatFromPath(source); err != nil {
			return err
		}
	}
	var names []string
	if *only != "" {
		names = strings.Split(strings.ToLower(*only), ",")
	}

	file, err := os.Open(source)
	if err != nil {
		return err
	}
	imported, err := lists.Import(file, f, names)
	_ = file.Close()
	if err != nil {
		return err
	}
	built := lists.BuildAll(imported)

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	_, _ = fmt.Fprintln(tw, "name\tsha256\tbytes\tv4 in\tv4 out\tv6 in\tv6 out\t")
	for _, l := range built {
		if err := os.WriteFile(filepath.Join(*out, l.Name+".geoip"), l.Blob, 0o644); err != nil {
			return err
		}
		st := l.Stats
		_, _ = fmt.Fprintf(tw, "%s\t%x\t%d\t%d\t%d\t%d\t%d\t\n", l.Name, l.SHA256, len(l.Blob), st.Added4, st.Prefixes4, st.Added6, st.Prefixes6)
		if st.Skipped > 0 {
			_, _ = fmt.Fprintf(e.stderr, "warning: %s: left out %d IPv6 entries overlapping the IPv4-mapped range ::ffff:0:0/96\n", l.Name, st.Skipped)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.stdout, "\n%s\n", f.Attribution())
	return err
}
