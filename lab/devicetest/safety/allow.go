//go:build darwin || linux

package safety

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// readShape is a command root may run for a plan: its absolute path and
// the arguments allowed, as one space-joined string.
type readShape struct {
	path string
	args *regexp.Regexp
}

// RootRead is the command the helper runs for a plan's root read (argv
// with a bare command name first). Only read-only listings of the shapes
// in reads are allowed: a plan changes the host only through an action.
func RootRead(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("an empty command")
	}
	shape, ok := reads()[argv[0]]
	if !ok {
		return nil, fmt.Errorf("%q is not a command root may read with", argv[0])
	}
	for _, a := range argv[1:] {
		if a == "" || strings.ContainsAny(a, " \t\n") {
			return nil, fmt.Errorf("argument %q: one word each", a)
		}
	}
	if !shape.args.MatchString(strings.Join(argv[1:], " ")) {
		return nil, fmt.Errorf("%q is not a read root may run", strings.Join(argv, " "))
	}
	return append([]string{shape.path}, argv[1:]...), nil
}
