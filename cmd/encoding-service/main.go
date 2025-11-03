package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net"

	"thinkpol-vpn/pkg/protocol"

	"google.golang.org/grpc"
)

var (
	port = flag.String("port", "50051", "The server port")
)

// server implements the EncodingService
type server struct {
	protocol.UnimplementedEncodingServiceServer
}

// ProcessPackets handles bidirectional streaming for encoding/decoding
func (s *server) ProcessPackets(stream grpc.BidiStreamingServer[protocol.EncodingPacket, protocol.EncodingPacket]) error {
	log.Println("[ENCODING] New client connected")

	ctx := stream.Context()

	// Handle incoming packets (encoding)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := stream.Recv()
				if err != nil {
					if err.Error() == "EOF" || ctx.Err() != nil {
						log.Println("[ENCODING] Client disconnected")
						return
					}
					log.Printf("[ENCODING] Error receiving packet: %v", err)
					return
				}

				// Check if packet is already base64 encoded (downstream decode)
				// or needs encoding (upstream encode)
				data := packet.Data[:packet.Length]

				var processedData []byte
				var processedLength int32

				// Try to decode first - if it's valid base64, decode it (downstream)
				// Otherwise, encode it (upstream)
				decoded, err := base64.StdEncoding.DecodeString(string(data))
				if err == nil && len(decoded) > 0 {
					// Successfully decoded - this was encoded data (downstream)
					processedData = decoded
					processedLength = int32(len(decoded))
					log.Printf("[ENCODING] Decoded packet: %d bytes -> %d bytes", packet.Length, processedLength)
				} else {
					// Not base64, encode it (upstream)
					encodedData := base64.StdEncoding.EncodeToString(data)
					processedData = []byte(encodedData)
					processedLength = int32(len(encodedData))
					log.Printf("[ENCODING] Encoded packet: %d bytes -> %d bytes", packet.Length, processedLength)
				}

				// Return processed packet
				response := &protocol.EncodingPacket{
					Data:   processedData,
					Length: processedLength,
				}

				if err := stream.Send(response); err != nil {
					log.Printf("[ENCODING] Error sending packet: %v", err)
					return
				}
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
	protocol.RegisterEncodingServiceServer(s, &server{})

	log.Printf("[ENCODING] Server listening on :%s", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
