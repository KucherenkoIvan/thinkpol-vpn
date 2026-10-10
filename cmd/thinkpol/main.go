// Command thinkpol is the one thinkpol-vpn binary: node agent, client
// service, CLI and admin panel.
//
// Each subcommand lives in its own file and registers itself from init, so
// adding a command never touches this file.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout io.Writer) error
}

var commands = map[string]command{}

func register(c command) {
	if _, dup := commands[c.name]; dup {
		panic("thinkpol: command registered twice: " + c.name)
	}
	commands[c.name] = c
}

// errUsage makes run print the usage and exit with status 2.
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage())
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, usage())
		return 0
	}
	c, ok := commands[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "thinkpol: unknown command %q\n\n%s", args[0], usage())
		return 2
	}
	if err := c.run(ctx, args[1:], stdout); err != nil {
		if errors.Is(err, errUsage) {
			_, _ = io.WriteString(stderr, usage())
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "thinkpol %s: %v\n", c.name, err)
		return 1
	}
	return 0
}

func usage() string {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("usage: thinkpol <command> [arguments]\n\ncommands:\n")
	for _, name := range names {
		fmt.Fprintf(&b, "  %-12s %s\n", name, commands[name].summary)
	}
	return b.String()
}
