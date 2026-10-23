//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// fileAction writes a file of its own in the run's directory: the
// self-test's harmless change that goes through the journal and is undone
// through it, and the persistent change the core's tests replay.
type fileAction struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

func (a *fileAction) validate() error {
	if !fileName.MatchString(a.Name) {
		return fmt.Errorf("file change: bad name %q", a.Name)
	}
	return nil
}

func (a *fileAction) path() string     { return "file-" + a.Name }
func (*fileAction) kind() string       { return KindFile }
func (*fileAction) lifetime() lifetime { return persistent }
func (a *fileAction) does() string     { return "write the run's own file " + a.path() }
func (a *fileAction) undoText() string {
	return "remove " + a.path() + " if it holds what was written"
}

// pre refuses a file that is there already: it would be someone else's.
func (a *fileAction) pre(_ context.Context, h *host) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(h.runDir.Fd()), a.path(), &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		return fmt.Errorf("%s is there already", a.path())
	case errors.Is(err, unix.ENOENT):
		return nil
	}
	return err
}

func (a *fileAction) apply(_ context.Context, h *host, _ func(json.RawMessage) error) error {
	fd, err := unix.Openat(int(h.runDir.Fd()), a.path(), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", a.path(), err)
	}
	_, werr := unix.Write(fd, []byte(a.Content))
	return errors.Join(werr, unix.Fsync(fd), unix.Close(fd))
}

func (a *fileAction) undo(_ context.Context, h *host) error {
	got, err := trusteddir.ReadFile(h.runDir, a.path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !bytes.Equal(got, []byte(a.Content)):
		return fmt.Errorf("%s holds something else: left as it is", a.path())
	}
	return trusteddir.Remove(h.runDir, a.path())
}
