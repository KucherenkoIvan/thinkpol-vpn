//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"
)

// The root modes' entry points: devicetest's main and the core's tests
// call these with the arguments after the mode's name. The state directory
// is never an argument: it is the StateConfig's.

// HelperMain is the "helper" mode.
func HelperMain(ctx context.Context, args []string, state StateConfig, in io.Reader, out, log io.Writer) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	run := fs.String("run", "", "the run's id")
	evidence := fs.String("evidence", "", "the run's evidence folder (the user's)")
	uid := fs.Int("uid", -1, "the evidence folder's owner")
	gid := fs.Int("gid", -1, "the evidence folder's group")
	budget := fs.Duration("budget", 0, "the dead-man's deadline")
	rootCopy := fs.String("root-copy", "", "the launch script's directory (it adds this)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := checkLaunched(*rootCopy, state); err != nil {
		return err
	}
	if *uid < 0 || *gid < 0 || *budget <= 0 || *evidence == "" {
		return errors.New("helper: -run, -evidence, -uid, -gid and -budget are needed")
	}
	return Helper(ctx, HelperConfig{State: state, Run: *run, Evidence: *evidence, UID: *uid, GID: *gid, Budget: *budget,
		RootCopy: *rootCopy, In: in, Out: out, Log: log})
}

// DeadmanMain is the "deadman" mode, which the helper starts.
func DeadmanMain(ctx context.Context, args []string, state StateConfig) error {
	fs := flag.NewFlagSet("deadman", flag.ContinueOnError)
	run := fs.String("run", "", "the run's id")
	pid := fs.Int("helper-pid", 0, "the helper it watches")
	deadline := fs.Duration("deadline", 0, "the plan's budget")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !state.AllowNonRoot {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := CheckRootCopy(filepath.Dir(exe)); err != nil {
			return err
		}
	}
	return Deadman(ctx, state, *run, DeadmanConfig{HelperPID: *pid, Deadline: *deadline})
}

// RestoreMain is the "restore" mode: it restores an unfinished run from
// its journal and prints the result as one Response line.
func RestoreMain(ctx context.Context, args []string, state StateConfig, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	rootCopy := fs.String("root-copy", "", "the launch script's directory (it adds this)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := checkLaunched(*rootCopy, state); err != nil {
		return err
	}
	res, err := RestoreRun(ctx, state, "devicetest restore, at "+time.Now().UTC().Format(time.RFC3339))
	resp := Response{OK: err == nil, Result: &res}
	if err != nil {
		resp.Err = err.Error()
	}
	_ = json.NewEncoder(out).Encode(resp)
	return errors.Join(err, removeRootCopy(*rootCopy))
}

// checkLaunched refuses a root mode that the launch script didn't start
// from a root copy (the core's tests aside).
func checkLaunched(rootCopy string, state StateConfig) error {
	if rootCopy == "" && state.AllowNonRoot {
		return nil
	}
	return CheckRootCopy(rootCopy)
}
