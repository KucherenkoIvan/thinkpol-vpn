package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestInboxDeliversQueuedPackets(t *testing.T) {
	in := NewInbox[[]byte](2)
	if !in.TrySend([]byte("one")) || !in.TrySend([]byte("two")) {
		t.Fatal("an inbox with room refused a packet")
	}
	if in.TrySend([]byte("three")) {
		t.Fatal("a full inbox took a packet")
	}
	p := make([]byte, MaxPacketSize)
	n, err := ReadPacketFrom(in, p)
	if err != nil || string(p[:n]) != "one" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
	n, err = ReadPacketFrom(in, p)
	if err != nil || string(p[:n]) != "two" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
}

func TestInboxReadPacketDropsAPacketTooLong(t *testing.T) {
	in := NewInbox[[]byte](1)
	in.TrySend(make([]byte, 100))
	if _, err := ReadPacketFrom(in, make([]byte, 10)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("reading 100 bytes into 10: %v", err)
	}
	// The dropped packet is gone; the inbox reads what is next.
	in.TrySend([]byte("next"))
	p := make([]byte, MaxPacketSize)
	n, err := ReadPacketFrom(in, p)
	if err != nil || string(p[:n]) != "next" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
}

func TestInboxRecvWaitsForAnItem(t *testing.T) {
	in := NewInbox[Identity](1)
	go func() {
		in.TrySend(Identity{Node: NodeID{1}})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, err := in.Recv(ctx)
	if err != nil || v.Node != (NodeID{1}) {
		t.Fatalf("Recv: %v, %v", v, err)
	}
}

func TestInboxRecvFailsWhenCtxDoes(t *testing.T) {
	in := NewInbox[Identity](1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := in.Recv(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv waited on a done context: %v", err)
	}
}

func TestInboxCloseEndsRecv(t *testing.T) {
	in := NewInbox[Identity](1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := in.Recv(ctx)
		errc <- err
	}()
	in.Close(nil)
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Recv after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close didn't unblock a waiting Recv")
	}
}

func TestInboxCloseCauseReachesTheReaders(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	in := NewInbox[[]byte](1)
	in.Close(cause)
	p := make([]byte, MaxPacketSize)
	if _, err := ReadPacketFrom(in, p); !errors.Is(err, cause) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadPacketFrom on a closed inbox: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := in.Recv(ctx); !errors.Is(err, cause) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Recv on a closed inbox: %v", err)
	}
}

// TestAnItemRacingClose races an item against the close, 200 times per
// read: a sender sends until the close shows, a closer yields once and
// closes with a cause, and the reader takes what arrives until it sees an
// error — which must be the cause. From then on the close is sticky: every
// later read returns the cause, never an item.
func TestInboxItemRacingClose(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	for _, read := range []struct {
		name string
		read func(*Inbox[[]byte]) error
	}{
		{"ReadPacketFrom", func(in *Inbox[[]byte]) error { _, err := ReadPacketFrom(in, make([]byte, MaxPacketSize)); return err }},
		{"Recv", func(in *Inbox[[]byte]) error { _, err := in.Recv(context.Background()); return err }},
	} {
		t.Run(read.name, func(t *testing.T) {
			for range 200 {
				in := NewInbox[[]byte](1)
				var wg sync.WaitGroup
				wg.Add(3)
				go func() {
					defer wg.Done()
					for !in.Closed() {
						in.TrySend([]byte("packet"))
					}
				}()
				go func() {
					defer wg.Done()
					runtime.Gosched()
					in.Close(cause)
				}()
				errc := make(chan error, 1)
				go func() {
					defer wg.Done()
					for {
						err := read.read(in)
						if err != nil {
							errc <- err
							return
						}
					}
				}()
				if err := <-errc; !errors.Is(err, cause) {
					t.Fatalf("reading past the close: %v", err)
				}
				wg.Wait()
				for range 16 {
					if err := read.read(in); !errors.Is(err, cause) {
						t.Fatalf("the close isn't sticky: %v", err)
					}
				}
			}
		})
	}
}

func TestInboxCloseEndsTheReads(t *testing.T) {
	in := NewInbox[[]byte](1)
	in.TrySend([]byte("queued")) // a closed inbox drops what is queued
	if !in.Close(nil) {
		t.Fatal("the first Close reported nothing closed")
	}
	if in.Close(nil) {
		t.Fatal("the second Close closed it again")
	}
	p := make([]byte, MaxPacketSize)
	if _, err := ReadPacketFrom(in, p); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read a closed inbox: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := in.Recv(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Recv on a closed inbox: %v", err)
	}
}
