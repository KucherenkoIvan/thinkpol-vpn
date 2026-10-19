package transport

import (
	"context"
	"io"
	"sync"
)

// Inbox is a queue a transport feeds and a reader drains: a link's
// packets for its reader, an accepted link for the listener's Accept. A
// sender that doesn't block drops what a full queue can't take, as a
// datagram network drops datagrams; one that blocks, or picks among
// queues and closings, uses Queue and Done. Closing the inbox ends the
// reads with a ClosedError; whatever is still queued then is dropped.
type Inbox[T any] struct {
	queue     chan T
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewInbox returns an inbox holding depth items.
func NewInbox[T any](depth int) *Inbox[T] {
	return &Inbox[T]{queue: make(chan T, depth), done: make(chan struct{})}
}

// Queue is the inbox's queue, for a sender that blocks (a stream's
// backpressure) or selects among queues and closings.
func (i *Inbox[T]) Queue() chan T { return i.queue }

// Done is closed when the inbox closes; senders select against it.
func (i *Inbox[T]) Done() <-chan struct{} { return i.done }

// TrySend queues v without blocking, and reports whether it fit.
func (i *Inbox[T]) TrySend(v T) bool {
	select {
	case i.queue <- v:
		return true
	default:
		return false
	}
}

// Recv waits for the inbox's next item, failing with a ClosedError once
// the inbox has closed, or with ctx's error when ctx did first. An item
// that arrives as the inbox closes is not delivered.
func (i *Inbox[T]) Recv(ctx context.Context) (T, error) {
	var zero T
	if i.closed() {
		return zero, ClosedError(nil)
	}
	select {
	case <-i.done:
	case <-ctx.Done():
		return zero, ctx.Err()
	case v := <-i.queue:
		if !i.closed() {
			return v, nil
		}
	}
	return zero, ClosedError(nil)
}

// Err is the error reads return once the inbox has closed.
func (i *Inbox[T]) Err() error { return i.closeErr }

// Close closes the inbox: reads return ClosedError(cause). Close reports
// whether this call closed it; the later ones change nothing.
func (i *Inbox[T]) Close(cause error) bool {
	first := false
	i.closeOnce.Do(func() {
		first = true
		i.closeErr = ClosedError(cause)
		close(i.done)
	})
	return first
}

func (i *Inbox[T]) closed() bool {
	select {
	case <-i.done:
		return true
	default:
		return false
	}
}

// ReadPacket receives the inbox's next packet into p: the ReadPacket of a
// link whose receive end the inbox is. A packet longer than p doesn't
// fit: it is dropped and io.ErrShortBuffer returned, as transport.Link's
// ReadPacket says.
func ReadPacket(i *Inbox[[]byte], p []byte) (int, error) {
	select {
	case <-i.done:
		return 0, i.closeErr
	default:
	}
	select {
	case <-i.done:
		return 0, i.closeErr
	case packet := <-i.queue:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}
