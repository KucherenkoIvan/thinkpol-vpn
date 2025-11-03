package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"thinkpol-vpn/pkg/protocol"

	"google.golang.org/grpc"
)

var (
	port = flag.String("port", "8080", "The gateway server port")
)

// gatewayServer implements the gateway functionality
type gatewayServer struct {
	protocol.UnimplementedTransportServiceServer
	clients sync.Map // map[string]*clientSession
}

// clientSession represents a connected client
type clientSession struct {
	id       string
	stream   grpc.BidiStreamingServer[protocol.TransportPacket, protocol.TransportPacket]
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	isActive bool
}

// TransportPackets handles client-initiated connections
// This is called by transport services (client-initiated as per requirements)
func (s *gatewayServer) TransportPackets(stream grpc.BidiStreamingServer[protocol.TransportPacket, protocol.TransportPacket]) error {
	ctx := stream.Context()
	
	// Generate client ID (in production, use proper authentication)
	clientID := generateClientID()
	log.Printf("[GATEWAY] New client connected: %s", clientID)

	session := &clientSession{
		id:       clientID,
		stream:   stream,
		ctx:      ctx,
		isActive: true,
	}
	ctx, cancel := context.WithCancel(ctx)
	session.ctx = ctx
	session.cancel = cancel

	s.clients.Store(clientID, session)
	defer s.clients.Delete(clientID)

	// Handle incoming packets from client
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := stream.Recv()
				if err != nil {
					if err == io.EOF || ctx.Err() != nil {
						log.Printf("[GATEWAY] Client %s disconnected", clientID)
						session.mu.Lock()
						session.isActive = false
						session.mu.Unlock()
						return
					}
					log.Printf("[GATEWAY] Error receiving from client %s: %v", clientID, err)
					return
				}

				// Process incoming packet from client
				if err := s.handleIncomingPacket(clientID, packet); err != nil {
					log.Printf("[GATEWAY] Error handling packet from client %s: %v", clientID, err)
				}
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	log.Printf("[GATEWAY] Client %s session ended", clientID)
	return ctx.Err()
}

// handleIncomingPacket processes packets received from clients
func (s *gatewayServer) handleIncomingPacket(clientID string, packet *protocol.TransportPacket) error {
	log.Printf("[GATEWAY] Received packet from client %s: %d bytes", clientID, packet.Length)

	// TODO: In a full implementation:
	// 1. Decode packet (using encoding service if needed)
	// 2. Route to backend/internet
	// 3. Receive response
	// 4. Encode response
	// 5. Send back to client

	// For MVP: Echo back to client (simulating successful routing)
	// In production, this would forward to actual backend
	if sessionInterface, ok := s.clients.Load(clientID); ok {
		session := sessionInterface.(*clientSession)
		session.mu.Lock()
		defer session.mu.Unlock()

		if session.isActive {
			response := &protocol.TransportPacket{
				Data:   packet.Data[:packet.Length],
				Length: packet.Length,
			}

			if err := session.stream.Send(response); err != nil {
				return err
			}

			log.Printf("[GATEWAY] Sent response to client %s: %d bytes", clientID, response.Length)
		}
	}

	return nil
}

// generateClientID generates a simple client ID
// In production, use proper authentication tokens
func generateClientID() string {
	// Simple implementation - in production, extract from auth token
	return "client-" + generateRandomString(8)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("[GATEWAY] Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	gateway := &gatewayServer{}
	protocol.RegisterTransportServiceServer(s, gateway)

	log.Printf("[GATEWAY] Gateway server listening on :%s", *port)
	log.Printf("[GATEWAY] Ready to accept client-initiated connections")

	if err := s.Serve(lis); err != nil {
		log.Fatalf("[GATEWAY] Failed to serve: %v", err)
	}
}
