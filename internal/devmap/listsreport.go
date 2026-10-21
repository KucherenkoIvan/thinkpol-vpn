package devmap

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// WriteListsReport writes, for lists built from a source of format f, the
// evidence for each list's blob to out (a table: SHA-256, size, and
// entries in, prefixes or DB-IP's ranges, against prefixes out), then the
// attribution the source's license asks for; warnings goes what a list
// left out.
func WriteListsReport(out, warnings io.Writer, f lists.Format, built []lists.List) error {
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
