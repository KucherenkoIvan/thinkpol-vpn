package lab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Result is a finished command's output.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// run runs a command on the host. A non-zero exit is an error that carries
// the command's stderr; the Result is filled in either way.
func run(ctx context.Context, stdin io.Reader, env []string, name string, args ...string) (Result, error) {
	return runEnv(ctx, stdin, append(os.Environ(), env...), name, args...)
}

// runEnv is run with exactly env as the command's environment.
func runEnv(ctx context.Context, stdin io.Reader, env []string, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = env
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
		return res, fmt.Errorf("%s: exit %d: %s", describe(name, args), res.ExitCode, strings.TrimSpace(res.Stderr))
	case err != nil:
		return res, fmt.Errorf("%s: %w", describe(name, args), err)
	}
	return res, nil
}

func docker(ctx context.Context, args ...string) (Result, error) {
	return run(ctx, nil, nil, "docker", args...)
}

// environWithoutCompose is the environment without COMPOSE_* variables,
// which could point Compose at someone else's files or project.
func environWithoutCompose() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "COMPOSE_") {
			env = append(env, kv)
		}
	}
	return env
}

func describe(name string, args []string) string {
	s := name + " " + strings.Join(args, " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
