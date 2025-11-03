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

// Client handles communication with transport service via gRPC
type Client struct {
	conn         *grpc.ClientConn
	client       protocol.TransportServiceClient
	stream       grpc.BidiStreamingClient[protocol.TransportPacket, protocol.TransportPacket]
	ctx          context.Context
	cancel       context.CancelFunc
	upstreamCh   chan []byte
	downstreamCh chan []byte
	wg           sync.WaitGroup
	mu           sync.Mutex
	isConnected  bool
}

// NewClient creates a new transport service client
func NewClient(serviceAddress string) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Connect to transport service
	conn, err := grpc.Dial(serviceAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to transport service: %w", err)
	}

	client := protocol.NewTransportServiceClient(conn)

	return &Client{
		conn:         conn,
		client:       client,
		ctx:          ctx,
		cancel:       cancel,
		upstreamCh:   make(chan []byte, 100),
		downstreamCh: make(chan []byte, 100),
		isConnected: false,
	}, nil
}

// Start begins the bidirectional streaming with the transport service
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return fmt.Errorf("client is already started")
	}

	stream, err := c.client.TransportPackets(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	c.stream = stream
	c.isConnected = true

	// Start goroutines for sending and receiving
	c.wg.Add(2)
	go c.sendLoop()
	go c.receiveLoop()

	log.Println("[TRANSPORT] Started transport service client")
	return nil
}

// sendLoop sends packets from upstream channel to transport service
func (c *Client) sendLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.upstreamCh:
			if !c.isConnected {
				log.Println("[TRANSPORT] Not connected, dropping packet")
				continue
			}

			pkt := &protocol.TransportPacket{
				Data:   packet,
				Length: int32(len(packet)),
			}
			if err := c.stream.Send(pkt); err != nil {
				if err == io.EOF {
					log.Println("[TRANSPORT] Stream closed by server")
					return
				}
				log.Printf("[TRANSPORT] Error sending packet: %v", err)
				return
			}
		}
	}
}

// receiveLoop receives packets from transport service
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
					log.Println("[TRANSPORT] Stream closed")
					return
				}
				log.Printf("[TRANSPORT] Error receiving packet: %v", err)
				return
			}

			select {
			case c.downstreamCh <- packet.Data[:packet.Length]:
				// Packet sent to downstream channel
			case <-c.ctx.Done():
				return
			default:
				log.Println("[TRANSPORT] Downstream channel full, dropping packet")
			}
		}
	}
}

// SendPacket sends a packet to transport service (non-blocking)
func (c *Client) SendPacket(data []byte) error {
	if !c.isConnected {
		return fmt.Errorf("not connected to transport service")
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

// ReceivePacket receives a packet from transport service (non-blocking)
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
			log.Printf("[TRANSPORT] Error closing stream: %v", err)
		}
		c.stream = nil
	}

	c.wg.Wait()

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("error closing connection: %w", err)
		}
	}

	log.Println("[TRANSPORT] Stopped transport service client")
	return nil
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isConnected
}
