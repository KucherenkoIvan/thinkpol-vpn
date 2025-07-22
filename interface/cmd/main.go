package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"thinkpol-vpn/interface/internal/api"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 8080, "Port to listen on")
	unsafe := flag.Bool("unsafe", false, "Enable unsafe features (traffic interception)")
	logFile := flag.String("log", "logs/vpn-interface.log", "Log file path")
	flag.Parse()

	// Initialize logger

	log.Println("ThinkPol VPN Interface starting...")

	// Create and start the API server
	server := api.NewServer(*port, *unsafe)

	log.Printf("Starting ThinkPol VPN Interface on port %d", *port)
	log.Println("Available endpoints:")
	log.Println("  POST   /api/interface/create     - Create the TUN interface")
	log.Println("  GET    /api/interface/status     - Get interface status")
	log.Println("  POST   /api/interface/start      - Start packet processing")
	log.Println("  POST   /api/interface/stop       - Stop packet processing")
	log.Println("  DELETE /api/interface/delete     - Delete the interface")
	if *unsafe {
		log.Println("  POST   /api/interface/intercept  - Intercept ALL internet traffic (UNSAFE)")
	}
	log.Println("  GET    /health                   - Health check")
	log.Println("")
	log.Printf("Interface configuration: %s/%s (MTU: %d)", api.InterfaceIP, api.InterfaceMask, api.InterfaceMTU)
	log.Println("Press Ctrl+C to stop gracefully")
	log.Printf("Logs are being written to: %s", *logFile)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down gracefully...", sig)

	// Perform cleanup
	if err := server.Cleanup(); err != nil {
		log.Fatalf("Cleanup error: %v", err)
	}

	log.Println("Shutdown complete")
}
