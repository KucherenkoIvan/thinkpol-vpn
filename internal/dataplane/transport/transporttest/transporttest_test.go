package transporttest

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// camouflaged is a dial the listener refused into camo: the camouflage
// takes the connection, and the dial fails.
func camouflaged(camo *Recorder) error {
	c, _ := net.Pipe()
	camo.Stream(c, nil)
	return io.EOF
}

func TestDialPastCamouflageRedialsCamouflagedDials(t *testing.T) {
	camo := &Recorder{}
	dials := 0
	start := time.Now()
	_, err := dialPastCamouflage(func() (transport.Link, error) {
		dials++
		if dials < 4 {
			return nil, camouflaged(camo)
		}
		return nil, nil
	}, camo, time.Now().Add(wait))
	if err != nil || dials != 4 {
		t.Fatalf("got %v after %d dials, want success on the 4th", err, dials)
	}
	// Three short waits (5, 10, 20 ms), not the quiet period each.
	if took := time.Since(start); took >= quiet {
		t.Fatalf("took %v to get past three camouflaged dials", took)
	}
}

func TestDialPastCamouflageFailsAtOnceOnOtherErrors(t *testing.T) {
	camo := &Recorder{}
	errSettings := errors.New("bad settings")
	dials := 0
	_, err := dialPastCamouflage(func() (transport.Link, error) {
		dials++
		return nil, errSettings
	}, camo, time.Now().Add(time.Second))
	if !errors.Is(err, errSettings) || dials != 1 {
		t.Fatalf("got %v after %d dials, want the dial's error after 1", err, dials)
	}
}

func TestDialPastCamouflageGivesUpAtTheDeadline(t *testing.T) {
	camo := &Recorder{}
	dials := 0
	start := time.Now()
	_, err := dialPastCamouflage(func() (transport.Link, error) {
		dials++
		return nil, camouflaged(camo)
	}, camo, time.Now().Add(100*time.Millisecond))
	if !errors.Is(err, io.EOF) || dials < 2 {
		t.Fatalf("got %v after %d dials, want the dial's error after several", err, dials)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("gave up after %v, past the deadline", took)
	}
}
