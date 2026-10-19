package transport

import (
	"context"
	"errors"
	"io"
	"net"
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
	n, err := ReadPacket(in, p)
	if err != nil || string(p[:n]) != "one" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
	n, err = ReadPacket(in, p)
	if err != nil || string(p[:n]) != "two" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
}

func TestInboxReadPacketDropsAPacketTooLong(t *testing.T) {
	in := NewInbox[[]byte](1)
	in.TrySend(make([]byte, 100))
	if _, err := ReadPacket(in, make([]byte, 10)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("reading 100 bytes into 10: %v", err)
	}
	// The dropped packet is gone; the inbox reads what is next.
	in.TrySend([]byte("next"))
	p := make([]byte, MaxPacketSize)
	n, err := ReadPacket(in, p)
	if err != nil || string(p[:n]) != "next" {
		t.Fatalf("read %q, %v", p[:n], err)
	}
}

func TestInboxRecvWaitsForAnItem(t *testing.T) {
	in := NewInbox[Identity](1)
	go func() {
		time.Sleep(time.Millisecond)
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
	if _, err := in.Recv(ctx); err == nil {
		t.Fatal("Recv waited on a done context")
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
	if _, err := ReadPacket(in, p); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read a closed inbox: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := in.Recv(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Recv on a closed inbox: %v", err)
	}
}
