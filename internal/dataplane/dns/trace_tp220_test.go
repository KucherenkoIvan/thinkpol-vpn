package dns

// TEMPORARY trace for TP-220, removed before review.

import (
	"fmt"
	"os"
	"slices"
	"sync"
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
	l.lines = append(l.lines, fmt.Sprintf("+%v ", time.Since(l.start).Round(time.Millisecond))+fmt.Sprintf(format, a...))
}

func inode(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	return statIno(fi)
}

// appendTraced is appendFile, saying which file the write landed in.
func appendTraced(t *testing.T, l *traceLog, path, s string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	opened, _ := f.Stat()
	_, err = f.WriteString(s)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	now, _ := os.Lstat(path)
	l.add("append %q into inode %d; the path now inode %d", s, inode(opened), inode(now))
}

func TestTraceTP220SlowWriter(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: 300 * time.Millisecond})
	l := &traceLog{start: time.Now()}
	r.mu.Lock()
	r.rewrite = func(p string, f resolvConfFile, content []byte) error {
		l.add("take-back: read inode %d %q", inode(f.info), f.content)
		err := rewriteResolvConf(p, f, content)
		now, _ := os.Lstat(p)
		l.add("take-back: wrote, the path now inode %d (err %v)", inode(now), err)
		return err
	}
	r.mu.Unlock()
	truncateFile(t, path)
	fi, _ := os.Lstat(path)
	l.add("truncated inode %d", inode(fi))
	time.Sleep(400 * time.Millisecond)
	for _, line := range []string{"search lan\n", "nameserver 192.0.2.7\n", "nameserver 2001:db8::7\n"} {
		appendTraced(t, l, path, line)
		time.Sleep(400 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !managedWith(t, path, renewedInPlace) {
		if time.Now().After(deadline) {
			r.mu.Lock()
			for _, s := range l.lines {
				t.Log("TRACE " + s)
			}
			r.mu.Unlock()
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := lastTold(t, told); !slices.Equal(got, renewedInPlaceServers) {
		t.Errorf("told %v last", got)
	}
}

func TestTraceTP220NeverSettles(t *testing.T) {
	timing := resolvConfTiming{check: 20 * time.Millisecond, settle: 300 * time.Millisecond, settleMax: time.Second}
	path, _, _ := startInPlace(t, timing)
	start := time.Now()
	var opens []time.Duration
	var prev os.FileInfo
	var prevOpened time.Time
	for i := 0; time.Since(start) < 3*time.Second; i++ {
		opened := time.Now()
		opens = append(opens, opened.Sub(start).Round(time.Millisecond))
		fi := overwriteInPlaceStat(t, path, fmt.Sprintf("nameserver 192.0.2.%d\n", 10+i%200))
		if prev != nil && !os.SameFile(prev, fi) {
			if after := prevOpened.Sub(start); after > timing.settleMax+timing.settle {
				t.Errorf("taken back after %v, want within %v; the writer's opens: %v", after, timing.settleMax+timing.settle, opens)
			}
			return
		}
		prev, prevOpened = fi, opened
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("never taken back while the writer ran")
}
