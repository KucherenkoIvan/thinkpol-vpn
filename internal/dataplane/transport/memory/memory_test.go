package memory_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

func TestConformance(t *testing.T) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			network := memory.NewNetwork(sem)
			var endpoints atomic.Int64
			transporttest.Run(t, transporttest.Harness{
				Listen: func(t *testing.T, address string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
					if address == "" {
						address = fmt.Sprintf("listener-%d", endpoints.Add(1))
					}
					l, err := network.Listen(context.Background(), transport.ListenConfig{Address: address, Peers: peers, Camouflage: camouflage})
					if err != nil {
						t.Fatal(err)
					}
					return l, transporttest.Endpoint{Address: address}
				},
				Dialer:    network.Dialer(),
				Transport: network,
				Refused: []transport.Shaping{
					{Padding: transporttest.Buckets(1280)},
					{Padding: transport.Padding{Mode: transport.PadRandom, Max: 16}},
					{BatchWindow: time.Millisecond},
					{Jitter: time.Millisecond},
					{CoverInterval: time.Second},
				},
			})
		})
	}
}

// With AcceptShaping, shaped maps run in-process: links carry on as
// unshaped ones do.
func TestConformanceAcceptShaping(t *testing.T) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			network := memory.NewNetwork(sem, memory.AcceptShaping())
			var endpoints atomic.Int64
			transporttest.Run(t, transporttest.Harness{
				Listen: func(t *testing.T, address string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
					if address == "" {
						address = fmt.Sprintf("listener-%d", endpoints.Add(1))
					}
					l, err := network.Listen(context.Background(), transport.ListenConfig{Address: address, Peers: peers, Camouflage: camouflage})
					if err != nil {
						t.Fatal(err)
					}
					return l, transporttest.Endpoint{Address: address}
				},
				Dialer:    network.Dialer(),
				Transport: network,
				Shaping: transport.Shaping{
					Padding:       transporttest.Buckets(256, 1280),
					BatchWindow:   time.Millisecond,
					Jitter:        time.Millisecond,
					CoverInterval: time.Second,
				},
			})
		})
	}
}

func TestRegistry(t *testing.T) {
	dg, st := memory.NewNetwork(memory.Datagram), memory.NewNetwork(memory.Stream)
	if _, err := transport.NewRegistry(dg, st); err == nil {
		t.Fatal("registered one name twice")
	}
	r, err := transport.NewRegistry(dg)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := r.Get(memory.Name); !ok || got != dg {
		t.Fatalf("Get(%q) = %v, %v", memory.Name, got, ok)
	}
	if _, ok := r.Get("tls"); ok {
		t.Fatal("found a transport that isn't registered")
	}
	if names := r.Names(); len(names) != 1 || names[0] != memory.Name {
		t.Fatalf("Names() = %v", names)
	}
}

// TestConcurrentClosesFreeTheEndpoint: a Close that lost the race waits
// for the winner, so once both return the endpoint is free and Listen
// takes the address again.
func TestConcurrentClosesFreeTheEndpoint(t *testing.T) {
	network := memory.NewNetwork(memory.Datagram)
	l, err := network.Listen(context.Background(), transport.ListenConfig{Address: "endpoint", Peers: transport.NewPeerTable()})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			<-start
			_ = l.Close()
		}()
	}
	close(start)
	wg.Wait()
	if _, err := network.Listen(context.Background(), transport.ListenConfig{Address: "endpoint", Peers: transport.NewPeerTable()}); err != nil {
		t.Fatalf("Listen on the closed listener's address: %v", err)
	}
}
