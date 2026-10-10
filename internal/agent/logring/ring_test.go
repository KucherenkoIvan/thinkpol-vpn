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
