package lists

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
)

// BuildFile builds the lists of source, a file in format f (empty: from
// its name, FormatFromPath), only those named in only (every list in it
// when empty), and writes each into dir as <name>.geoip. It returns the
// lists built in name order, and the source's format, whose Attribution
// goes with them. It never downloads: the source is a file the operator
// fetched, under its own license.
func BuildFile(source string, f Format, only []string, dir string) (Format, []List, error) {
	if f == "" {
		var err error
		if f, err = FormatFromPath(source); err != nil {
			return "", nil, err
		}
	}
	file, err := os.Open(source)
	if err != nil {
		return "", nil, err
	}
	imported, err := Import(file, f, only)
	_ = file.Close()
	if err != nil {
		return "", nil, err
	}
	built := BuildAll(imported)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	for _, l := range built {
		if err := os.WriteFile(filepath.Join(dir, l.Name+".geoip"), l.Blob, 0o644); err != nil {
			return "", nil, err
		}
	}
	return f, built, nil
}

// WriteReport writes, for lists built from a source of format f, the
// evidence for each list's blob to out (a table: SHA-256, size, and
// entries in, prefixes or DB-IP's ranges, against prefixes out), then the
// attribution the source's license asks for; warnings goes what a list
// left out.
func WriteReport(out, warnings io.Writer, f Format, built []List) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', tabwriter.AlignRight)
	_, _ = fmt.Fprintln(tw, "name\tsha256\tbytes\tv4 in\tv4 out\tv6 in\tv6 out\t")
	for _, l := range built {
		st := l.Stats
		_, _ = fmt.Fprintf(tw, "%s\t%x\t%d\t%d\t%d\t%d\t%d\t\n", l.Name, l.SHA256, len(l.Blob), st.Added4, st.Prefixes4, st.Added6, st.Prefixes6)
		if st.Skipped > 0 {
			_, _ = fmt.Fprintf(warnings, "warning: %s: left out %d IPv6 entries overlapping the IPv4-mapped range ::ffff:0:0/96\n", l.Name, st.Skipped)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\n%s\n", f.Attribution())
	return err
}
