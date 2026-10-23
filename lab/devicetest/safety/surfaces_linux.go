package safety

import (
	"errors"
	"fmt"
	"strings"
)

// surfaces are what the core records of a Linux host: only the lab uses
// it, to test the core as root, so only the IPv4 main table (a fresh
// node's IPv6 link-local routes still come and go while it settles).
func surfaces() []Surface {
	return []Surface{{Name: "routes", Argv: []string{ipPath(), "-4", "route", "show", "table", "main"}, Norm: textLines, Next: "delete the route by hand"}}
}

func textLines(out output) ([]string, error) {
	if out.Err != "" {
		return nil, errors.New(out.Err)
	}
	if out.Code != 0 {
		return nil, fmt.Errorf("exit %d: %s", out.Code, strings.TrimSpace(string(out.Stderr)))
	}
	lines := []string{}
	for _, l := range strings.Split(string(out.Stdout), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
