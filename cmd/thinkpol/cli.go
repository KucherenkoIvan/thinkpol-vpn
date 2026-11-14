package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// command is one subcommand. Its path is space-separated ("version",
// "dev map build"): a command group is nothing but a shared prefix, so
// adding `dev lists build` is one new file that registers that path.
type command struct {
	path        string
	args        string // argument synopsis, e.g. "[-out file] <spec.yaml>"
	summary     string
	hidden      bool // runs, but is left out of the usage listings (internal commands)
	ownsSignals bool // long-running under app.RunWith, which owns SIGINT/SIGTERM: main installs no NotifyContext for it
	run         func(ctx context.Context, e env, args []string) error
}

// env is the process's standard streams, swapped for buffers in tests.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

var commands = map[string]command{}

func register(c command) {
	if c.path == "" || strings.Join(strings.Fields(c.path), " ") != c.path || strings.HasPrefix(c.path, "-") {
		panic(fmt.Sprintf("thinkpol: bad command path %q", c.path))
	}
	if _, dup := commands[c.path]; dup {
		panic("thinkpol: command registered twice: " + c.path)
	}
	// A group prefix is never itself a command, so `thinkpol dev` always
	// lists the group instead of running something.
	for path := range commands {
		if strings.HasPrefix(path, c.path+" ") || strings.HasPrefix(c.path, path+" ") {
			panic(fmt.Sprintf("thinkpol: command %q and command %q: a group prefix can't be a command", c.path, path))
		}
	}
	commands[c.path] = c
}

var (
	// errUsage from a command makes run print the command's synopsis and
	// exit with exitUsage.
	errUsage = errors.New("usage")
	// errUsagePrinted is errUsage after parseFlags already printed it.
	errUsagePrinted = errors.New("usage printed")
)

// parseFlags parses args into fs, which must be named after the command's
// path. -h prints the synopsis and the flags and returns flag.ErrHelp (exit
// 0); a bad flag prints the error and the same help (exitUsage, where Go's
// flag package would exit 2).
func parseFlags(fs *flag.FlagSet, e env, args []string) error {
	fs.SetOutput(e.stderr)
	fs.Usage = func() {
		synopsis(e.stderr, fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsagePrinted
	}
	return nil
}

// apiSocket is the local API's socket: THINKPOL_API_SOCKET if set (empty
// for none), else the platform's default.
func apiSocket() string {
	if p, ok := os.LookupEnv("THINKPOL_API_SOCKET"); ok {
		return p
	}
	return agent.DefaultAPISocket()
}

// apiCommand is the flag set of a command that talks to the running
// node's local API: its own flags, and the API's -socket.
type apiCommand struct {
	*flag.FlagSet
	socket *string
}

func newAPICommand(name string) apiCommand {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return apiCommand{fs, fs.String("socket", apiSocket(), "the local API's socket (THINKPOL_API_SOCKET)")}
}

// dial parses args, refuses them (errUsage) unless argsOK says the
// command takes what they hold, and dials the local API. The caller
// closes the client.
func (c apiCommand) dial(e env, args []string, argsOK func(*flag.FlagSet) bool) (*localapi.Client, error) {
	if err := parseFlags(c.FlagSet, e, args); err != nil {
		return nil, err
	}
	if !argsOK(c.FlagSet) {
		return nil, errUsage
	}
	return localapi.Dial(*c.socket)
}

// printOutcome prints the status a call that changes the node returned
// with no error. A call that failed with exitFailure (the state not
// reached, or reached in part: connected without DNS protection, a
// toggle kept while the kill switch isn't enforced, a preset kept and
// enforced failing closed) prints the status as it is now, if the service
// still answers within statusAfterFailure: the verdict's 1 is "not
// reached, with the status printed", so the failure is read with where
// it left the node. err is returned either way, with the status's
// printing error, if any.
func printOutcome(ctx context.Context, e env, c *localapi.Client, st *localapiv1.Status, err error) error {
	if err == nil {
		return localapi.WriteStatus(e.stdout, st, time.Now())
	}
	if exitCode(err) != exitFailure {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, statusAfterFailure)
	defer cancel()
	now, serr := c.Status(sctx)
	if serr != nil {
		return err
	}
	return errors.Join(err, localapi.WriteStatus(e.stdout, now, time.Now()))
}

// statusAfterFailure bounds printOutcome's second call: the failure is
// told whether or not the status comes.
const statusAfterFailure = 5 * time.Second

// noArgs and oneArg are apiCommand.dial's usual argsOK.
func noArgs(fs *flag.FlagSet) bool { return fs.NArg() == 0 }
func oneArg(fs *flag.FlagSet) bool { return fs.NArg() == 1 }

// onOffArgs takes no argument or one, on or off: a toggle's command.
func onOffArgs(fs *flag.FlagSet) bool {
	return fs.NArg() == 0 || fs.NArg() == 1 && (fs.Arg(0) == "on" || fs.Arg(0) == "off")
}

// commandWords counts args' leading words: the command path's candidate
// words. Flags and arguments with spaces end a path.
func commandWords(args []string) int {
	words := 0
	for words < len(args) && !strings.HasPrefix(args[words], "-") && !strings.ContainsAny(args[words], " \t\n") {
		words++
	}
	return words
}

// matchCommand resolves args' leading words to a registered command,
// with the arguments after its path.
func matchCommand(args []string) (command, []string, bool) {
	for n := commandWords(args); n > 0; n-- {
		if c, ok := commands[strings.Join(args[:n], " ")]; ok {
			return c, args[n:], true
		}
	}
	return command{}, nil, false
}

func run(ctx context.Context, e env, args []string) int {
	if len(args) == 0 {
		listCommands(e.stderr, "")
		return exitUsage
	}
	if isHelp(args[0]) {
		listCommands(e.stdout, "")
		return 0
	}

	if c, rest, ok := matchCommand(args); ok {
		err := c.run(ctx, e, rest)
		code := exitCode(err)
		switch {
		case code == exitOK, errors.Is(err, errUsagePrinted):
		case errors.Is(err, errUsage):
			synopsis(e.stderr, c.path)
		default:
			_, _ = fmt.Fprintf(e.stderr, "thinkpol %s: %v%s\n", c.path, err, codeSuffix(err))
		}
		return code
	}

	// No command matched: list the longest group the words name, if any.
	for n := commandWords(args); n > 0; n-- {
		group := strings.Join(args[:n], " ")
		if !isGroup(group) {
			continue
		}
		if n < len(args) && isHelp(args[n]) {
			listCommands(e.stdout, group)
			return 0
		}
		if n < len(args) && !strings.HasPrefix(args[n], "-") {
			_, _ = fmt.Fprintf(e.stderr, "thinkpol: unknown command %q\n\n", group+" "+args[n])
		}
		listCommands(e.stderr, group)
		return exitUsage
	}
	_, _ = fmt.Fprintf(e.stderr, "thinkpol: unknown command %q\n\n", args[0])
	listCommands(e.stderr, "")
	return exitUsage
}

// codeSuffix is the local API's code for err, " [code]", so a script
// reads which refusal it was from stderr; empty when the API named none.
func codeSuffix(err error) string {
	var refusal localapi.Error
	if !errors.As(err, &refusal) || refusal.Code == "" {
		return ""
	}
	return " [" + refusal.Code + "]"
}

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "-help" || arg == "--help"
}

func isGroup(prefix string) bool {
	for path, c := range commands {
		if !c.hidden && strings.HasPrefix(path, prefix+" ") {
			return true
		}
	}
	return false
}

// synopsis prints one command's usage line and summary.
func synopsis(w io.Writer, path string) {
	c, ok := commands[path]
	if !ok {
		panic(fmt.Sprintf("thinkpol: no command %q (a FlagSet passed to parseFlags must be named after its command)", path))
	}
	line := "usage: thinkpol " + path
	if c.args != "" {
		line += " " + c.args
	}
	if c.summary != "" {
		line += "\n\n" + c.summary
	}
	_, _ = fmt.Fprintln(w, line)
}

// listCommands prints the visible commands under group ("" for all).
func listCommands(w io.Writer, group string) {
	prefix, head := "", "thinkpol"
	if group != "" {
		prefix, head = group+" ", "thinkpol "+group
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "usage: %s <command> [arguments]\n\ncommands:\n", head)
	for _, path := range slices.Sorted(maps.Keys(commands)) {
		if c := commands[path]; !c.hidden && strings.HasPrefix(path, prefix) {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\n", path, c.summary)
		}
	}
	_ = tw.Flush()
}
