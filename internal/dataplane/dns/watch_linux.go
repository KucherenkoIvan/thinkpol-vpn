//go:build linux && !android

package dns

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchFile signals changes to the file at path: written and closed,
// created, or renamed into its directory (inotify on the directory). The
// channel may be nil where that can't be watched; callers poll too.
func watchFile(path string) (<-chan struct{}, func()) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, func() {}
	}
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_CREATE); err != nil {
		_ = unix.Close(fd)
		return nil, func() {}
	}
	f := os.NewFile(uintptr(fd), "inotify") // non-blocking: Close ends a Read
	ch := make(chan struct{}, 1)
	name := filepath.Base(path)
	go func() {
		buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
				off += unix.SizeofInotifyEvent + int(ev.Len)
				if string(trimNUL(nameBytes)) == name {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return ch, func() { _ = f.Close() }
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
