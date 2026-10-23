package safety

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// fullSync puts f's data on the disk itself: macOS's fsync only hands it
// to the drive, whose cache a power loss empties; F_FULLFSYNC flushes
// that too. Where the file system doesn't support it, fsync; any other
// error is the sync's.
func fullSync(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTTY) {
		return f.Sync()
	}
	return err
}
