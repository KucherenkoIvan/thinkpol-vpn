package dns

// TEMPORARY trace for TP-220, removed before review.

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type traceLog struct {
	mu    sync.Mutex
	start time.Time
	lines []string
}

func (l *traceLog) add(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf("+%v ", time.Since(l.start).Round(time.Microsecond))+fmt.Sprintf(format, a...))
}

func ino(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestTraceTP220SlowWriterFixed(t *testing.T) {
	path, r, _ := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: 300 * time.Millisecond})
	l := &traceLog{start: time.Now()}
	r.mu.Lock()
	r.rewrite = func(p string, f resolvConfFile, content []byte) error {
		if string(content) == string(f.content) {
			return nil
		}
		l.add("take-back: read inode %d %q", ino(f.info), f.content)
		err := rewriteResolvConf(p, f, content)
		now, _ := os.Lstat(p)
		l.add("take-back: done, the path now inode %d (err %v)", ino(now), err)
		return err
	}
	r.mu.Unlock()
	truncateFile(t, path)
	time.Sleep(400 * time.Millisecond)
	for _, line := range []string{"search lan\n", "nameserver 192.0.2.7\n", "nameserver 2001:db8::7\n"} {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened, _ := f.Stat()
		l.add("writer: opened inode %d", ino(opened))
		_, _ = f.WriteString(line)
		_ = f.Close()
		now, _ := os.Lstat(path)
		l.add("writer: appended %q into inode %d; the path now inode %d", line, ino(opened), ino(now))
		time.Sleep(400 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !managedWith(t, path, renewedInPlace) {
		if time.Now().After(deadline) {
			l.mu.Lock()
			for _, s := range l.lines {
				t.Log("TRACE " + s)
			}
			l.mu.Unlock()
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
