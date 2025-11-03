package main

import (
	"flag"
	"io"
	"log"
	"net"

	"thinkpol-vpn/pkg/protocol"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	port          = flag.String("port", "50052", "The server port")
	gatewayAddr   = flag.String("gateway", "localhost:8080", "Gateway server address")
)

// server implements the TransportService
type server struct {
	protocol.UnimplementedTransportServiceServer
	gatewayAddr string
}

// TransportPackets handles bidirectional streaming for packet transport to/from gateway
// This acts as a proxy: receives from client, forwards to gateway, receives from gateway, forwards to client
func (s *server) TransportPackets(stream grpc.BidiStreamingServer[protocol.TransportPacket, protocol.TransportPacket]) error {
	log.Println("[TRANSPORT] New client connected")

	ctx := stream.Context()

	// Connect to gateway server (client-initiated as per requirements)
	gatewayConn, err := grpc.DialContext(ctx, s.gatewayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("[TRANSPORT] Failed to connect to gateway: %v", err)
		return err
	}
	defer gatewayConn.Close()

	gatewayClient := protocol.NewTransportServiceClient(gatewayConn)
	gatewayStream, err := gatewayClient.TransportPackets(ctx)
	if err != nil {
		log.Printf("[TRANSPORT] Failed to create gateway stream: %v", err)
		return err
	}
	defer gatewayStream.CloseSend()

	log.Printf("[TRANSPORT] Connected to gateway at %s", s.gatewayAddr)

	// Forward packets from client to gateway
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := stream.Recv()
				if err != nil {
					if err == io.EOF || ctx.Err() != nil {
						log.Println("[TRANSPORT] Client disconnected")
						return
					}
					log.Printf("[TRANSPORT] Error receiving from client: %v", err)
					return
				}

				// Forward to gateway
				if err := gatewayStream.Send(packet); err != nil {
					log.Printf("[TRANSPORT] Error sending to gateway: %v", err)
					return
				}

				log.Printf("[TRANSPORT] Forwarded packet to gateway: %d bytes", packet.Length)
			}
		}
	}()

	// Forward packets from gateway to client
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := gatewayStream.Recv()
				if err != nil {
					if err == io.EOF || ctx.Err() != nil {
						log.Println("[TRANSPORT] Gateway disconnected")
						return
					}
					log.Printf("[TRANSPORT] Error receiving from gateway: %v", err)
					return
				}

				// Forward to client
				if err := stream.Send(packet); err != nil {
					log.Printf("[TRANSPORT] Error sending to client: %v", err)
					return
				}

				log.Printf("[TRANSPORT] Forwarded packet from gateway: %d bytes", packet.Length)
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return ctx.Err()
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	protocol.RegisterTransportServiceServer(s, &server{
		gatewayAddr: *gatewayAddr,
	})

	log.Printf("[TRANSPORT] Server listening on :%s (gateway: %s)", *port, *gatewayAddr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
