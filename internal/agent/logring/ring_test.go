package logring_test

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
)

func TestKeepsLinesInOrder(t *testing.T) {
	r := logring.New(1 << 16)
	_, _ = r.Write([]byte("one\ntw"))
	_, _ = r.Write([]byte("o\nthree"))
	if got, want := r.Lines(), []string{"one", "two", "three"}; !slices.Equal(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

func TestDropsOldestPastItsSize(t *testing.T) {
	r := logring.New(logring.MaxLine) // the smallest ring
	line := strings.Repeat("x", 99) + "\n"
	for i := range 100 {
		_, _ = fmt.Fprintf(r, "%02d%s", i, line)
	}
	lines := r.Lines()
	size := 0
	for _, l := range lines {
		size += len(l) + 1
	}
	if size > logring.MaxLine {
		t.Fatalf("ring holds %d bytes, more than its %d", size, logring.MaxLine)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "99") {
		t.Fatalf("newest line lost: %q", lines[len(lines)-1])
	}
	if got := uint64(100 - len(lines)); r.Dropped() != got {
		t.Fatalf("dropped %d, want %d", r.Dropped(), got)
	}
}

func TestLongLinesAreCut(t *testing.T) {
	r := logring.New(1 << 20)
	_, _ = r.Write([]byte(strings.Repeat("a", 2*logring.MaxLine+10)))
	_, _ = r.Write([]byte(strings.Repeat("b", logring.MaxLine+1) + "\n"))
	for _, l := range r.Lines() {
		if len(l) > logring.MaxLine {
			t.Fatalf("line of %d bytes kept", len(l))
		}
	}
	if got := strings.Join(r.Lines(), ""); got != strings.Repeat("a", 2*logring.MaxLine+10)+strings.Repeat("b", logring.MaxLine+1) {
		t.Fatal("content lost when cutting lines")
	}
}

func TestConcurrentSlogWriters(t *testing.T) {
	r := logring.New(1 << 20)
	log := slog.New(slog.NewTextHandler(r, nil))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				log.Info("hello", "writer", i, "n", j)
			}
		})
	}
	wg.Wait()
	lines := r.Lines()
	if len(lines) != 800 {
		t.Fatalf("%d lines, want 800", len(lines))
	}
	for _, l := range lines {
		if !strings.Contains(l, "msg=hello") {
			t.Fatalf("torn line %q", l)
		}
	}
}

func TestNewlineFloodStaysBounded(t *testing.T) {
	r := logring.New(logring.MaxLine)
	// Many empty lines: the ring must not grow its backing storage without
	// bound, and the byte size must stay within the limit.
	for range 1 << 20 {
		_, _ = r.Write([]byte("\n"))
	}
	lines := r.Lines()
	size := 0
	for _, l := range lines {
		size += len(l) + 1
	}
	if size > logring.MaxLine {
		t.Fatalf("ring holds %d bytes, more than its %d", size, logring.MaxLine)
	}
	if r.Dropped() == 0 {
		t.Fatal("nothing counted as dropped under a flood")
	}
}

func TestSinceFollowsTheLogLineByLine(t *testing.T) {
	r := logring.New(logring.MaxLine)
	_, _ = r.Write([]byte("one\ntwo\nthr"))
	lines, next, missed := r.Since(0)
	if !slices.Equal(lines, []string{"one", "two"}) || next != 2 || missed != 0 {
		t.Fatalf("got %q, next %d, missed %d", lines, next, missed)
	}
	if lines, next2, _ := r.Since(next); len(lines) != 0 || next2 != next {
		t.Fatalf("nothing new, got %q, next %d", lines, next2)
	}
	_, _ = r.Write([]byte("ee\n"))
	if lines, next, _ = r.Since(next); !slices.Equal(lines, []string{"three"}) || next != 3 {
		t.Fatalf("got %q, next %d", lines, next)
	}
	// A reader that fell behind is told how much it missed.
	line := strings.Repeat("x", 99) + "\n"
	for range 100 {
		_, _ = r.Write([]byte(line))
	}
	lines, next, missed = r.Since(next)
	if missed == 0 || uint64(len(lines))+missed != 100 || next != 103 {
		t.Fatalf("%d lines, missed %d, next %d", len(lines), missed, next)
	}
	// A seq from the future is the end.
	if lines, next, _ = r.Since(1000); len(lines) != 0 || next != 103 {
		t.Fatalf("got %q, next %d", lines, next)
	}
}
