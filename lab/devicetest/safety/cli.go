//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// errAnswered marks an error the user side has already, as the protocol's
// answer: devicetest-root doesn't print it again.
var errAnswered = errors.New("answered")

// answered is err, marked as sent to the user side (nil stays nil).
func answered(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(errAnswered, err)
}

// RootMain is devicetest-root: args are a mode and its flags. "helper"
// (the launch script starts it for a run), "deadman" (the helper starts
// it) and "root-restore" (the launch script starts it for `devicetest
// restore`). The state directory is never an argument. It returns the
// exit status, and prints an error to log unless the user side has it as
// an answer already.
func RootMain(ctx context.Context, args []string, in io.Reader, out, log io.Writer) int {
	return rootMain(ctx, args, defaultState(), in, out, log)
}

func rootMain(ctx context.Context, args []string, state stateConfig, in io.Reader, out, log io.Writer) int {
	// First, for every mode: until here Go's own QUIT and TERM handlers can
	// kill the root copy (launchScript). A gone reader is a write error,
	// not death by SIGPIPE, so the helper and root-restore always get to
	// remove their root copy.
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	if len(args) == 0 {
		_, _ = fmt.Fprintln(log, "devicetest-root: started by devicetest, never by hand")
		return 2
	}
	var err error
	switch mode, rest := args[0], args[1:]; mode {
	case "helper":
		err = helperMain(ctx, rest, state, in, out, log)
	case "deadman":
		err = deadmanMain(ctx, rest, state)
	case "root-restore":
		err = restoreMain(ctx, rest, state, out)
	default:
		err = fmt.Errorf("no mode %q", mode)
	}
	if err == nil {
		return 0
	}
	if !errors.Is(err, errAnswered) {
		_, _ = fmt.Fprintln(log, "devicetest-root:", err)
	}
	return 1
}

func helperMain(ctx context.Context, args []string, state stateConfig, in io.Reader, out, log io.Writer) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	run := fs.String("run", "", "the run's id")
	ev := fs.String("evidence", "", "the run's evidence folder (the user's)")
	uid := fs.Int("uid", -1, "the evidence folder's owner")
	gid := fs.Int("gid", -1, "the evidence folder's group")
	budget := fs.Duration("budget", 0, "the dead-man's deadline")
	rootCopy := fs.String("root-copy", "", "the launch script's directory (it adds this)")
	err := fs.Parse(args)
	if err == nil {
		err = checkLaunched(*rootCopy, state)
	}
	if err == nil && (*run == "" || *uid < 0 || *gid < 0 || *budget <= 0 || *ev == "") {
		err = errors.New("helper: -run, -evidence, -uid, -gid and -budget are needed")
	}
	if err == nil {
		err = helper(ctx, helperConfig{state: state, run: *run, evidence: *ev, uid: *uid, gid: *gid, budget: *budget,
			rootCopy: *rootCopy, in: in, out: out, log: log})
		if !errors.Is(err, errNotStarted) {
			return err // a run that started removes its root copy when it ends
		}
	} else {
		_ = json.NewEncoder(out).Encode(Response{Err: err.Error()})
		err = answered(err)
	}
	return errors.Join(err, removeRootCopy(*rootCopy))
}

func deadmanMain(ctx context.Context, args []string, state stateConfig) error {
	fs := flag.NewFlagSet("deadman", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	run := fs.String("run", "", "the run's id")
	pid := fs.Int("helper-pid", 0, "the helper it watches")
	start := fs.Int64("helper-start", 0, "the helper's start time, as the kernel records it")
	deadline := fs.Duration("deadline", 0, "the plan's budget")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !state.allowNonRoot {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := checkRootCopy(filepath.Dir(exe)); err != nil {
			return err
		}
	}
	return deadman(ctx, state, *run, deadmanConfig{helperPID: *pid, helperStart: *start, deadline: *deadline})
}

// restoreMain restores the run pending a restore, or with -forget closes
// it by name, and prints the result as one Response line. Like the
// helper, it outlives a closed terminal and a gone reader (rootMain), so
// it always gets to remove its root copy.
func restoreMain(ctx context.Context, args []string, state stateConfig, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rootCopy := fs.String("root-copy", "", "the launch script's directory (it adds this)")
	forget := fs.String("forget", "", "close the pending run RUN in a later boot than its own")
	err := fs.Parse(args)
	if err == nil {
		err = checkLaunched(*rootCopy, state)
	}
	var res Result
	if err == nil {
		by := "devicetest restore, at " + time.Now().UTC().Format(time.RFC3339)
		if *forget != "" {
			res, err = forgetRun(ctx, state, *forget, by+", -forget "+*forget)
		} else {
			res, err = restoreRun(ctx, state, by, "")
		}
	}
	resp := Response{OK: err == nil, Result: &res}
	if err != nil {
		resp.Err = err.Error()
	}
	_ = json.NewEncoder(out).Encode(resp)
	return errors.Join(answered(err), removeRootCopy(*rootCopy))
}

// checkLaunched refuses a root mode that the launch script didn't start
// from a root copy (the core's tests aside).
func checkLaunched(rootCopy string, state stateConfig) error {
	if rootCopy == "" && state.allowNonRoot {
		return nil
	}
	return checkRootCopy(rootCopy)
}
