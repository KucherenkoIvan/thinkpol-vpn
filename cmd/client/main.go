package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"thinkpol-vpn/internal/config"
	"thinkpol-vpn/internal/tun"
	encodingClient "thinkpol-vpn/pkg/encoding/grpc"
	transportClient "thinkpol-vpn/pkg/transport/grpc"
)

var (
	interfaceConfigPath = flag.String("interface-config", "configs/interface.json", "Path to interface configuration")
	encodingConfigPath  = flag.String("encoding-config", "configs/encoding.json", "Path to encoding configuration")
	transportConfigPath = flag.String("transport-config", "configs/transport.json", "Path to transport configuration")
)

func main() {
	flag.Parse()

	log.Println("🚀 Starting ThinkPol VPN Client")
	log.Println("")

	// Load configurations
	log.Println("📋 Loading configurations...")
	interfaceCfg, err := config.LoadInterfaceConfig(*interfaceConfigPath)
	if err != nil {
		log.Fatalf("Failed to load interface config: %v", err)
	}

	encodingCfg, err := config.LoadEncodingConfig(*encodingConfigPath)
	if err != nil {
		log.Fatalf("Failed to load encoding config: %v", err)
	}

	transportCfg, err := config.LoadTransportConfig(*transportConfigPath)
	if err != nil {
		log.Fatalf("Failed to load transport config: %v", err)
	}
	log.Println("✅ Configurations loaded")
	log.Println("")

	// Create TUN manager
	log.Println("🔧 Creating TUN interface manager...")
	tunManager, err := tun.NewManager(interfaceCfg)
	if err != nil {
		log.Fatalf("Failed to create TUN manager: %v", err)
	}

	// Create encoding client
	log.Printf("🔗 Connecting to encoding service at %s...", encodingCfg.ServiceAddress)
	encClient, err := encodingClient.NewClient(encodingCfg.ServiceAddress)
	if err != nil {
		log.Fatalf("Failed to create encoding client: %v", err)
	}

	if err := encClient.Start(); err != nil {
		log.Fatalf("Failed to start encoding client: %v", err)
	}
	log.Println("✅ Encoding client connected")

	// Create transport client
	log.Printf("🔗 Connecting to transport service at %s...", transportCfg.ServiceAddress)
	transClient, err := transportClient.NewClient(transportCfg.ServiceAddress)
	if err != nil {
		log.Fatalf("Failed to create transport client: %v", err)
	}

	if err := transClient.Start(); err != nil {
		log.Fatalf("Failed to start transport client: %v", err)
	}
	log.Println("✅ Transport client connected")
	log.Println("")

	// Create TUN interface
	log.Println("🌐 Creating TUN interface...")
	if err := tunManager.Create(); err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	log.Println("✅ TUN interface created")
	log.Println("")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up packet flow handlers
	// We'll use channels to route packets properly
	upstreamQueue := make(chan []byte, 100) // TUN → Encoding → Transport

	// Upstream: TUN → Encoding → Transport
	tunManager.SetUpstreamHandler(func(data []byte, length int) error {
		// Queue packet for upstream processing
		select {
		case upstreamQueue <- data[:length]:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			log.Printf("[CLIENT] Upstream queue full, dropping packet")
			return nil
		}
	})

	// Worker: Process upstream packets (TUN → Encoding → Transport)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rawPacket := <-upstreamQueue:
				// Encode packet
				encodedPacket, err := encClient.Encode(rawPacket)
				if err != nil {
					log.Printf("[CLIENT] Error encoding packet: %v", err)
					continue
				}
				// Send to transport
				if err := transClient.SendPacket(encodedPacket); err != nil {
					log.Printf("[CLIENT] Error sending to transport: %v", err)
				}
			}
		}
	}()

	// Worker: Process downstream packets (Transport → Encoding → TUN)
	go func() {
		transDownstream := transClient.GetDownstreamChannel()
		for {
			select {
			case <-ctx.Done():
				return
			case encodedPacket, ok := <-transDownstream:
				if !ok {
					log.Println("[CLIENT] Transport downstream channel closed")
					return
				}
				// Decode packet (encoding service auto-detects and decodes)
				decodedPacket, err := encClient.Encode(encodedPacket)
				if err != nil {
					log.Printf("[CLIENT] Error decoding packet: %v", err)
					continue
				}
				// Write to TUN
				if err := tunManager.WritePacket(decodedPacket); err != nil {
					log.Printf("[CLIENT] Error writing to TUN: %v", err)
				}
			}
		}
	}()

	// Start TUN packet processing
	log.Println("▶️  Starting packet processing...")
	if err := tunManager.Start(); err != nil {
		log.Fatalf("Failed to start TUN manager: %v", err)
	}
	log.Println("✅ VPN client started successfully!")
	log.Println("")
	log.Println("Press Ctrl+C to stop gracefully")
	log.Println("")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down gracefully...", sig)
	log.Println("")

	// Cancel context to stop all goroutines
	cancel()

	// Give goroutines a moment to finish
	time.Sleep(100 * time.Millisecond)

	// Stop TUN manager first
	log.Println("🛑 Stopping TUN manager...")
	if err := tunManager.Stop(); err != nil {
		log.Printf("Error stopping TUN manager: %v", err)
	}
	if err := tunManager.Close(); err != nil {
		log.Printf("Error closing TUN manager: %v", err)
	}
	log.Println("✅ TUN manager stopped")

	// Stop transport client
	log.Println("🛑 Stopping transport client...")
	if err := transClient.Stop(); err != nil {
		log.Printf("Error stopping transport client: %v", err)
	}
	log.Println("✅ Transport client stopped")

	// Stop encoding client
	log.Println("🛑 Stopping encoding client...")
	if err := encClient.Stop(); err != nil {
		log.Printf("Error stopping encoding client: %v", err)
	}
	log.Println("✅ Encoding client stopped")

	log.Println("")
	log.Println("👋 Shutdown complete")
}
