package safety

import (
	"os"

	"golang.org/x/sys/unix"
)

// fullSync puts f's data on the disk itself: macOS's fsync only hands it
// to the drive, whose cache a power loss empties; F_FULLFSYNC flushes
// that too. Where the file system refuses it, fsync.
func fullSync(f *os.File) error {
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err == nil {
		return nil
	}
	return f.Sync()
}
