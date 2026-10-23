package safety

import (
	"errors"
	"fmt"
	"strings"
)

// surfaces are what the core records of a Linux host: only the lab uses
// it, to test the core as root, so only the IPv4 main table (a fresh
// node's IPv6 link-local routes still come and go while it settles).
func surfaces() []surface {
	return []surface{{name: "routes", argv: []string{ipPath(), "-4", "route", "show", "table", "main"}, norm: textLines, next: "delete the route by hand"}}
}

func textLines(out output) ([]string, error) {
	if out.Err != "" {
		return nil, errors.New(out.Err)
	}
	if out.Code != 0 {
		return nil, fmt.Errorf("exit %d: %s", out.Code, strings.TrimSpace(string(out.Stderr)))
	}
	return listingLines(out.Stdout), nil
}
