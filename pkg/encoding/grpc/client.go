package grpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"thinkpol-vpn/pkg/protocol"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client handles communication with encoding service via gRPC
type Client struct {
	conn         *grpc.ClientConn
	client       protocol.EncodingServiceClient
	stream       grpc.BidiStreamingClient[protocol.EncodingPacket, protocol.EncodingPacket]
	ctx          context.Context
	cancel       context.CancelFunc
	upstreamCh   chan []byte
	downstreamCh chan []byte
	wg           sync.WaitGroup
	mu           sync.Mutex
	isConnected  bool
}

// NewClient creates a new encoding service client
func NewClient(serviceAddress string) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Connect to encoding service
	conn, err := grpc.Dial(serviceAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to encoding service: %w", err)
	}

	client := protocol.NewEncodingServiceClient(conn)

	return &Client{
		conn:        conn,
		client:      client,
		ctx:         ctx,
		cancel:      cancel,
		upstreamCh:  make(chan []byte, 100),
		downstreamCh: make(chan []byte, 100),
		isConnected: false,
	}, nil
}

// Start begins the bidirectional streaming with the encoding service
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return fmt.Errorf("client is already started")
	}

	stream, err := c.client.ProcessPackets(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	c.stream = stream
	c.isConnected = true

	// Start goroutines for sending and receiving
	c.wg.Add(2)
	go c.sendLoop()
	go c.receiveLoop()

	log.Println("[ENCODING] Started encoding service client")
	return nil
}

// sendLoop sends packets from upstream channel to encoding service
func (c *Client) sendLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.upstreamCh:
			if !c.isConnected {
				log.Println("[ENCODING] Not connected, dropping packet")
				continue
			}

			pkt := &protocol.EncodingPacket{
				Data:   packet,
				Length: int32(len(packet)),
			}
			if err := c.stream.Send(pkt); err != nil {
				if err == io.EOF {
					log.Println("[ENCODING] Stream closed by server")
					return
				}
				log.Printf("[ENCODING] Error sending packet: %v", err)
				return
			}
		}
	}
}

// receiveLoop receives encoded packets from encoding service
func (c *Client) receiveLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			packet, err := c.stream.Recv()
			if err != nil {
				if err == io.EOF {
					log.Println("[ENCODING] Stream closed")
					return
				}
				log.Printf("[ENCODING] Error receiving packet: %v", err)
				return
			}

			select {
			case c.downstreamCh <- packet.Data[:packet.Length]:
				// Packet sent to downstream channel
			case <-c.ctx.Done():
				return
			default:
				log.Println("[ENCODING] Downstream channel full, dropping packet")
			}
		}
	}
}

// Encode sends a packet for encoding and returns the encoded packet
// This is a blocking call - for non-blocking, use SendPacket/ReceivePacket
func (c *Client) Encode(data []byte) ([]byte, error) {
	// For async operation, we use SendPacket and receive from downstream channel
	// This is a simplified synchronous version
	if err := c.SendPacket(data); err != nil {
		return nil, err
	}

	// Wait for response
	encoded := <-c.downstreamCh
	return encoded, nil
}

// SendPacket sends a packet to encoding service (non-blocking)
func (c *Client) SendPacket(data []byte) error {
	if !c.isConnected {
		return fmt.Errorf("not connected to encoding service")
	}

	select {
	case c.upstreamCh <- data:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("client context cancelled")
	default:
		return fmt.Errorf("upstream channel full")
	}
}

// ReceivePacket receives an encoded/decoded packet (non-blocking)
func (c *Client) ReceivePacket() ([]byte, error) {
	select {
	case packet := <-c.downstreamCh:
		return packet, nil
	case <-c.ctx.Done():
		return nil, fmt.Errorf("client context cancelled")
	default:
		return nil, fmt.Errorf("no packet available")
	}
}

// GetDownstreamChannel returns the downstream channel for receiving packets
func (c *Client) GetDownstreamChannel() <-chan []byte {
	return c.downstreamCh
}

// Stop stops the client and closes connections
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isConnected {
		return nil
	}

	c.cancel()
	c.isConnected = false

	if c.stream != nil {
		if err := c.stream.CloseSend(); err != nil {
			log.Printf("[ENCODING] Error closing stream: %v", err)
		}
		c.stream = nil
	}

	c.wg.Wait()

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("error closing connection: %w", err)
		}
	}

	log.Println("[ENCODING] Stopped encoding service client")
	return nil
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isConnected
}
