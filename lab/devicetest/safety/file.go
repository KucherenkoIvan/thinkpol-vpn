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

// KindFile is FileAction's kind.
const KindFile = "file"

// FileAction writes a file of its own in the run's directory: the
// self-test's harmless change that goes through the journal and is undone
// through it, and the persistent change the core's tests replay.
type FileAction struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

func (a *FileAction) validate() error {
	if !fileName.MatchString(a.Name) {
		return fmt.Errorf("file action: bad name %q", a.Name)
	}
	return nil
}

func (a *FileAction) path() string     { return "file-" + a.Name }
func (*FileAction) Kind() string       { return KindFile }
func (*FileAction) Lifetime() Lifetime { return Persistent }
func (a *FileAction) Does() string     { return "write the run's own file " + a.path() }
func (a *FileAction) UndoText() string {
	return "remove " + a.path() + " if it holds what was written"
}

// Pre refuses a file that is there already: it would be someone else's.
func (a *FileAction) Pre(_ context.Context, h *Host) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(h.RunDir.Fd()), a.path(), &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		return fmt.Errorf("%s is there already", a.path())
	case errors.Is(err, unix.ENOENT):
		return nil
	}
	return err
}

func (a *FileAction) Apply(_ context.Context, h *Host) (json.RawMessage, error) {
	fd, err := unix.Openat(int(h.RunDir.Fd()), a.path(), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", a.path(), err)
	}
	_, werr := unix.Write(fd, []byte(a.Content))
	return nil, errors.Join(werr, unix.Fsync(fd), unix.Close(fd))
}

func (a *FileAction) Undo(_ context.Context, h *Host) error {
	got, err := trusteddir.ReadFile(h.RunDir, a.path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !bytes.Equal(got, []byte(a.Content)):
		return fmt.Errorf("%s holds something else: left as it is", a.path())
	}
	return trusteddir.Remove(h.RunDir, a.path())
}
