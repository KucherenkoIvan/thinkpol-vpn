//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// The root modes' entry points, for devicetest-root's main: the arguments
// after the mode's name. The state directory is never an argument.

// HelperMain is the "helper" mode, which the launch script starts.
func HelperMain(ctx context.Context, args []string, in io.Reader, out, log io.Writer) error {
	return helperMain(ctx, args, defaultState(), in, out, log)
}

// DeadmanMain is the "deadman" mode, which the helper starts.
func DeadmanMain(ctx context.Context, args []string) error {
	return deadmanMain(ctx, args, defaultState())
}

// RestoreMain is the "root-restore" mode, which the launch script starts
// for `devicetest restore`: it restores the run pending a restore and
// prints the result as one Response line.
func RestoreMain(ctx context.Context, args []string, out io.Writer) error {
	return restoreMain(ctx, args, defaultState(), out)
}

func helperMain(ctx context.Context, args []string, state stateConfig, in io.Reader, out, log io.Writer) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
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
	if err == nil && (*uid < 0 || *gid < 0 || *budget <= 0 || *ev == "") {
		err = errors.New("helper: -run, -evidence, -uid, -gid and -budget are needed")
	}
	if err == nil {
		err = helper(ctx, helperConfig{state: state, run: *run, evidence: *ev, uid: *uid, gid: *gid, budget: *budget,
			rootCopy: *rootCopy, in: in, out: out, log: log})
		if !errors.Is(err, errNotStarted) {
			return err // a run that started removes its root copy when it ends
		}
	}
	return errors.Join(err, removeRootCopy(*rootCopy))
}

func deadmanMain(ctx context.Context, args []string, state stateConfig) error {
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	fs := flag.NewFlagSet("deadman", flag.ContinueOnError)
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

func restoreMain(ctx context.Context, args []string, state stateConfig, out io.Writer) error {
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	rootCopy := fs.String("root-copy", "", "the launch script's directory (it adds this)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := checkLaunched(*rootCopy, state); err != nil {
		return errors.Join(err, removeRootCopy(*rootCopy))
	}
	res, err := restoreRun(ctx, state, "devicetest restore, at "+time.Now().UTC().Format(time.RFC3339))
	resp := Response{OK: err == nil, Result: &res}
	if err != nil {
		resp.Err = err.Error()
	}
	_ = json.NewEncoder(out).Encode(resp)
	return errors.Join(err, removeRootCopy(*rootCopy))
}

// checkLaunched refuses a root mode that the launch script didn't start
// from a root copy (the core's tests aside).
func checkLaunched(rootCopy string, state stateConfig) error {
	if rootCopy == "" && state.allowNonRoot {
		return nil
	}
	return checkRootCopy(rootCopy)
}
