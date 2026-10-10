package path_test

import (
	"errors"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

// Packets too long for WireGuard or for a link's network path are dropped
// and counted, not lost silently.
func TestOversizePacketsAreCounted(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		f.add("A", "B")
		f.dial("A", "B")
		a, b := f.bind("A", peer("B", "B")), f.bind("B", peer("A", "A"))
		toB := a.endpoint(t, "B")

		f.limitPath("A", "B", 300)
		long := append(wgMsg("long"), make([]byte, 400)...)
		if err := a.Send([][]byte{long}, toB); err != nil {
			t.Fatal(err)
		}
		eventually(t, "the long packet counted", func() bool { return f.node("A").Counters().TooLarge == 1 })
		b.expectNothing(t, 50*wait/1000)

		if err := a.Send([][]byte{make([]byte, path.MaxMessageSize+1)}, toB); !errors.Is(err, path.ErrMessageSize) {
			t.Fatalf("send of a message longer than WireGuard's: %v", err)
		}
		if c := f.node("A").Counters(); c.TooLarge != 2 || c.WriteFailed != 0 {
			t.Fatalf("counters %+v", c)
		}
		a.send(t, toB, "short")
		b.expect(t, "short")
	})
}
