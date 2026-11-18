package testcache

import (
	"io/fs"
	"syscall"
	"time"
)

// changeTime is the inode's change time (ctime), when the system has one.
func changeTime(fi fs.FileInfo) (time.Time, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), true // int32 on 32-bit
}
