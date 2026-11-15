//go:build linux && !android

package dns

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchFile watches the file at path for changes: written and closed,
// created, or renamed into its directory (inotify on the directory). The
// watch is set up at once and signals from start on. own is how many
// changes the caller made to the file itself since the set-up (each
// write, renamed in or in place, is one): the changes made before start
// are dropped when they are no more than own, and are one signal
// otherwise, never a rename, as whose rename it was can't be told. A
// signal is true when every change it stands for was a rename into the
// path: a file renamed in was complete before it got the name, while one
// created at the path (IN_CREATE fires at the open) may still be being
// written. start's channel may be nil where that can't be watched;
// callers poll too. start is called at most once, and closeWatch ends
// the watch, started or not.
func watchFile(path string) (start func(own int) <-chan bool, closeWatch func()) {
	unwatched := func(int) <-chan bool { return nil }
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return unwatched, func() {}
	}
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_CREATE); err != nil {
		_ = unix.Close(fd)
		return unwatched, func() {}
	}
	var f *os.File
	ch := make(chan bool, 1)
	name := filepath.Base(path)
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	start = func(own int) <-chan bool {
		before, lost := 0, false
		for { // the queued events, read before the poller owns the fd
			n, err := unix.Read(fd, buf)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n <= 0 {
				break
			}
			eachChange(buf[:n], name, func(mask uint32) {
				before++
				lost = lost || mask&unix.IN_Q_OVERFLOW != 0
			})
		}
		if lost || before > own {
			signal(ch, false)
		}
		f = os.NewFile(uintptr(fd), "inotify") // non-blocking: Close ends a Read
		go func() {
			for {
				n, err := f.Read(buf)
				if err != nil {
					return
				}
				eachChange(buf[:n], name, func(mask uint32) {
					signal(ch, mask&unix.IN_MOVED_TO != 0 && mask&unix.IN_Q_OVERFLOW == 0)
				})
			}
		}()
		return ch
	}
	closeWatch = func() {
		if f != nil {
			_ = f.Close()
			return
		}
		_ = unix.Close(fd)
	}
	return start, closeWatch
}

// eachChange calls change with the mask of each event in buf that may
// have changed the file called name: one about name, or a queue overflow
// (events were lost, a creation among them maybe).
func eachChange(buf []byte, name string, change func(mask uint32)) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
		off += unix.SizeofInotifyEvent + int(ev.Len)
		if ev.Mask&unix.IN_Q_OVERFLOW != 0 || string(trimNUL(nameBytes)) == name {
			change(ev.Mask)
		}
	}
}

// signal sends renamed on ch, or merges it into the signal not yet
// received: a merged signal is a rename only if every change was. One
// goroutine at a time sends on ch (start, then its reader), so once its
// buffer is emptied the send can't block.
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
