//go:build !linux && !darwin

package testcache

import (
	"io/fs"
	"time"
)

// changeTime is the inode's change time (ctime), when the system has one:
// here only the modification time is checked.
func changeTime(fs.FileInfo) (time.Time, bool) { return time.Time{}, false }
