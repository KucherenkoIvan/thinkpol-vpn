//go:build darwin || linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// client is the user side of the helper's protocol: one request, one
// answer, over the helper's stdin and stdout.
type client struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
	mu  sync.Mutex
	id  int
}

// startClient starts the helper (cmd) and reads its first answer: the run
// is started, or why not.
func startClient(cmd *exec.Cmd) (*client, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &client{cmd: cmd, in: in, out: bufio.NewScanner(stdout)}
	c.out.Buffer(nil, 4<<20)
	hello, err := c.read()
	if err == nil && !hello.OK {
		err = errors.New(hello.Err)
	}
	if err != nil {
		_ = in.Close()
		_ = cmd.Wait()
		return nil, fmt.Errorf("the helper: %w", err)
	}
	return c, nil
}

func (c *client) read() (safety.Response, error) {
	if !c.out.Scan() {
		if err := c.out.Err(); err != nil {
			return safety.Response{}, err
		}
		return safety.Response{}, errors.New("the helper ended")
	}
	var r safety.Response
	err := json.Unmarshal(c.out.Bytes(), &r)
	return r, err
}

// call sends req and returns the helper's answer; a refusal is an error.
func (c *client) call(req safety.Request) (safety.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id++
	req.ID = c.id
	b, err := json.Marshal(req)
	if err != nil {
		return safety.Response{}, err
	}
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		return safety.Response{}, fmt.Errorf("the helper: %w", err)
	}
	r, err := c.read()
	switch {
	case err != nil:
		return r, fmt.Errorf("the helper: %w", err)
	case r.ID != req.ID:
		return r, fmt.Errorf("the helper answered request %d, not %d", r.ID, req.ID)
	case !r.OK:
		return r, errors.New(r.Err)
	}
	return r, nil
}

// restore asks the helper to restore and end the run.
func (c *client) restore() (safety.Result, error) {
	r, err := c.call(safety.Request{Op: safety.OpRestore})
	_ = c.in.Close()
	werr := c.cmd.Wait()
	if r.Result == nil {
		return safety.Result{}, errors.Join(err, werr, errors.New("no result from the helper"))
	}
	return *r.Result, err
}

// abandon closes the helper's input: it restores by itself.
func (c *client) abandon() { _ = c.in.Close() }
