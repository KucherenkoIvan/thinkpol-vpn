// Command thinkpol is the one thinkpol-vpn binary: node agent, client
// service, CLI and admin panel.
//
// Each command lives in its own file and registers itself from init (see
// cli.go), so adding a command never touches shared code. Command files are
// composition roots: they parse flags, build adapters and call into
// internal/, nothing more. A command returns an error and never picks its
// exit code: exitCode (exitcode.go) maps every failure to BSD sysexits,
// the contract scripts branch on. A command marks the inputs it names
// (input, inputAt): only those make 66 and 77 of a missing or unreadable
// file; any other errno is 1.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	args := os.Args[1:]
	e := env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	// A service command runs under app.RunWith, which owns SIGINT/SIGTERM:
	// a second handler would swallow the signal that force-quits a hung
	// shutdown. Plain commands take the NotifyContext.
	if c, _, ok := matchCommand(args); ok && c.ownsSignals {
		os.Exit(run(context.Background(), e, args))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal cancels ctx, restore the default handling so a
	// second Ctrl-C kills a command that is slow to shut down.
	context.AfterFunc(ctx, stop)
	code := run(ctx, e, args)
	stop()
	os.Exit(code)
}
