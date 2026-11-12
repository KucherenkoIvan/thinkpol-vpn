//go:build linux && !android

package dns

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchFile signals changes to the file at path: written and closed,
// created, or renamed into its directory (inotify on the directory). A
// signal is true when every change it stands for was a rename into the
// path: a file renamed in was complete before it got the name, while one
// created at the path (IN_CREATE fires at the open) may still be being
// written. The channel may be nil where that can't be watched; callers
// poll too.
func watchFile(path string) (<-chan bool, func()) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, func() {}
	}
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_CREATE); err != nil {
		_ = unix.Close(fd)
		return nil, func() {}
	}
	f := os.NewFile(uintptr(fd), "inotify") // non-blocking: Close ends a Read
	ch := make(chan bool, 1)
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
					signal(ch, ev.Mask&unix.IN_MOVED_TO != 0)
				}
			}
		}
	}()
	return ch, func() { _ = f.Close() }
}

// signal sends renamed on ch, or merges it into the signal not yet
// received: a merged signal is a rename only if every change was. Only
// this goroutine sends on ch, so once its buffer is emptied the send
// can't block.
func signal(ch chan bool, renamed bool) {
	select {
	case ch <- renamed:
		return
	default:
	}
	select {
	case pending := <-ch:
		renamed = renamed && pending
	default:
	}
	ch <- renamed
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
