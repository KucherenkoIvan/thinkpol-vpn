//go:build linux

package nsthreadtest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Kinds are the namespaces a helper may move a thread into.
var Kinds = []string{"net", "mnt"}

// CheckThreadsHome fails t for every thread of this process whose network
// or mount namespace differs from the lab node's own, which are its init's
// (pid 1's): lab tests run in the node's namespaces.
func CheckThreadsHome(t testing.TB) {
	t.Helper()
	want := map[string]string{}
	for _, kind := range Kinds {
		l, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		want[kind] = l
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(os.Getpid())
	for _, task := range tasks {
		for _, kind := range Kinds {
			l, err := os.Readlink(filepath.Join("/proc/self/task", task.Name(), "ns", kind))
			if errors.Is(err, fs.ErrNotExist) {
				break // the thread has exited since the listing
			}
			if err != nil {
				t.Fatal(err)
			}
			if l != want[kind] {
				t.Errorf("thread %s (main thread: %v) is in %s namespace %s, the node's is %s",
					task.Name(), task.Name() == pid, kind, l, want[kind])
			}
		}
	}
}
