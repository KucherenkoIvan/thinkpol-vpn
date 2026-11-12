//go:build linux && !android

package dns

import "testing"

// Signals not yet received merge: the merged one is a rename only if
// every change was, so a creation after a rename is never taken for a
// complete file.
func TestWatchSignalsMergeAsARenameOnlyIfEveryChangeWas(t *testing.T) {
	for _, tc := range []struct {
		sent []bool
		want bool
	}{
		{[]bool{true}, true},
		{[]bool{false}, false},
		{[]bool{true, true}, true},
		{[]bool{true, false}, false},
		{[]bool{false, true}, false},
	} {
		ch := make(chan bool, 1)
		for _, renamed := range tc.sent {
			signal(ch, renamed)
		}
		if got := <-ch; got != tc.want {
			t.Errorf("sent %v: received %t, want %t", tc.sent, got, tc.want)
		}
		select {
		case extra := <-ch:
			t.Errorf("sent %v: a second signal %t", tc.sent, extra)
		default:
		}
	}
}
